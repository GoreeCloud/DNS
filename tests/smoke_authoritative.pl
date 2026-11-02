#!/usr/bin/env perl
# Offline authoritative DNS contract test; no external resolver or host networking.
use strict;
use warnings;
use JSON::PP qw(decode_json);
use IO::Socket::INET;

my $header = shift @ARGV // die "Usage: perl smoke_authoritative.pl /work/session-header\n";
die "Unexpected arguments\n" if @ARGV;
-f $header or die "FAIL: missing temporary bearer-token header\n";

sub api {
    my ($label, $path, @data) = @_;
    my $output = "/work/$label.json";
    my @args = ('curl', '--fail', '--silent', '--show-error', '--max-time', '5',
                '--output', $output, '--header', '@' . $header);
    for my $field (@data) { push @args, '--data-urlencode', $field; }
    push @args, 'http://127.0.0.1:5380' . $path;
    system(@args) == 0 or die "FAIL: $label API transport\n";
    open my $file, '<', $output or die "FAIL: $label response unreadable\n";
    local $/;
    my $body = eval { decode_json(<$file>) };
    close $file;
    ref($body) eq 'HASH' && ($body->{status} // '') eq 'ok'
        or die "FAIL: $label API did not return ok\n";
}

api('zone-create', '/api/zones/create', 'zone=smoke.invalid', 'type=Primary');
api('zone-record', '/api/zones/records/add',
    'zone=smoke.invalid', 'domain=host.smoke.invalid', 'type=A',
    'ipAddress=192.0.2.42', 'ttl=120');

sub read_n {
    my ($socket, $wanted) = @_;
    my $result = '';
    while (length($result) < $wanted) {
        my $n = sysread($socket, my $part, $wanted - length($result));
        defined($n) && $n > 0 or die "FAIL: premature DNS TCP response\n";
        $result .= $part;
    }
    return $result;
}

sub skip_qname {
    my ($wire, $offset) = @_;
    for (1..128) {
        $offset < length($wire) or die "FAIL: truncated DNS name\n";
        my $size = ord(substr($wire, $offset, 1));
        if (($size & 0xc0) == 0xc0) {
            $offset + 2 <= length($wire) or die "FAIL: truncated DNS pointer\n";
            return $offset + 2;
        }
        ($size & 0xc0) == 0 or die "FAIL: invalid DNS label type\n";
        $offset++;
        return $offset if $size == 0;
        $offset + $size <= length($wire) or die "FAIL: truncated DNS label\n";
        $offset += $size;
    }
    die "FAIL: DNS name contains too many labels\n";
}

for my $transport (qw(udp tcp)) {
    my $id = $transport eq 'udp' ? 0xa11e : 0xb11e;
    my $domain = join('', map { pack('C', length($_)) . $_ } qw(host smoke invalid)) . "\0";
    my $query = pack('n6', $id, 0x0100, 1, 0, 0, 0) . $domain . pack('n2', 1, 1);
    my $socket = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => 53, Proto => $transport, Timeout => 4)
        or die "FAIL: $transport DNS socket unavailable\n";
    my $answer;
    local $SIG{ALRM} = sub { die "FAIL: $transport query timed out\n" };
    alarm 5;
    if ($transport eq 'udp') {
        send($socket, $query, 0) == length($query) or die "FAIL: UDP send\n";
        defined recv($socket, $answer, 4096, 0) or die "FAIL: UDP receive\n";
    } else {
        my $packet = pack('n', length($query)) . $query;
        syswrite($socket, $packet) == length($packet) or die "FAIL: TCP send\n";
        my $size = unpack('n', read_n($socket, 2));
        $size >= 12 or die "FAIL: TCP answer too short\n";
        $answer = read_n($socket, $size);
    }
    alarm 0;
    length($answer) >= 12 or die "FAIL: short $transport DNS answer\n";
    my ($response_id, $flags, $questions, $count) = unpack('n4', $answer);
    $response_id == $id && ($flags & 0x8000) && ($flags & 0x0400) &&
        ($flags & 15) == 0 && $questions == 1 && $count >= 1
        or die "FAIL: $transport response not authoritative NOERROR with answer\n";
    my $offset = 12;
    for (1..$questions) {
        $offset = skip_qname($answer, $offset);
        $offset + 4 <= length($answer) or die "FAIL: short question metadata\n";
        $offset += 4;
    }
    my $found = 0;
    for (1..$count) {
        $offset = skip_qname($answer, $offset);
        $offset + 10 <= length($answer) or die "FAIL: short answer metadata\n";
        my ($type, $class, $ttl, $rdlength) = unpack('nnNn', substr($answer, $offset, 10));
        $offset += 10;
        $offset + $rdlength <= length($answer) or die "FAIL: short RDATA\n";
        if ($type == 1 && $class == 1 && $ttl > 0 && $ttl <= 120 &&
            $rdlength == 4 && substr($answer, $offset, 4) eq pack('C4', 192, 0, 2, 42)) {
            $found = 1;
        }
        $offset += $rdlength;
    }
    $found or die "FAIL: $transport answer omitted configured A record\n";
    print "PASS: $transport authoritative A record from disposable test zone\n";
}
