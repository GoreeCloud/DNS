#!/usr/bin/env perl
# EDNS unsupported-version boundary; run only in the network-none DNS smoke container.
use strict;
use warnings;
use IO::Socket::INET;

sub receive_exact {
    my ($sock, $size) = @_;
    my $data = '';
    while (length($data) < $size) {
        my $n = sysread($sock, my $part, $size - length($data));
        defined($n) && $n > 0 or die "FAIL: incomplete framed DNS response\n";
        $data .= $part;
    }
    return $data;
}

sub after_name {
    my ($wire, $at) = @_;
    for (1..128) {
        $at < length($wire) or die "FAIL: invalid DNS name offset\n";
        my $n = ord(substr($wire, $at, 1));
        if (($n & 0xc0) == 0xc0) {
            $at + 2 <= length($wire) or die "FAIL: short DNS name pointer\n";
            return $at + 2;
        }
        ($n & 0xc0) == 0 or die "FAIL: invalid DNS label\n";
        $at++;
        return $at if $n == 0;
        $at + $n <= length($wire) or die "FAIL: short DNS label\n";
        $at += $n;
    }
    die "FAIL: too many DNS labels\n";
}

for my $transport (qw(udp tcp)) {
    my $id = $transport eq 'udp' ? 0xe101 : 0xe102;
    my $qname = join('', map { pack('C', length($_)) . $_ } qw(host smoke invalid)) . "\0";
    # OPT (41), UDP 1232, EDNS version=1 in OPT TTL, zero options.
    my $opt = pack('CnnNn', 0, 41, 1232, 0x00010000, 0);
    my $query = pack('n6', $id, 0x0100, 1, 0, 0, 1)
        . $qname . pack('n2', 1, 1) . $opt;
    my $socket = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => 53, Proto => $transport, Timeout => 4)
        or die "FAIL: $transport EDNS socket unavailable\n";
    my $answer;
    local $SIG{ALRM} = sub { die "FAIL: $transport BADVERS query timeout\n" };
    alarm 5;
    if ($transport eq 'udp') {
        send($socket, $query, 0) == length($query) or die "FAIL: UDP EDNS send\n";
        defined recv($socket, $answer, 4096, 0) or die "FAIL: UDP EDNS recv\n";
    } else {
        my $packet = pack('n', length($query)) . $query;
        syswrite($socket, $packet) == length($packet) or die "FAIL: TCP EDNS send\n";
        my $len = unpack('n', receive_exact($socket, 2));
        $len >= 12 or die "FAIL: invalid TCP EDNS response length\n";
        $answer = receive_exact($socket, $len);
    }
    alarm 0;

    length($answer) >= 12 or die "FAIL: short EDNS response\n";
    my ($answer_id, $flags, $qd, $an, $ns, $ar) = unpack('n6', $answer);
    $answer_id == $id && ($flags & 0x8000) && !($flags & 0x0200) && $qd == 1
        or die "FAIL: malformed $transport BADVERS response header\n";
    my $pos = 12;
    for (1..$qd) {
        $pos = after_name($answer, $pos);
        $pos + 4 <= length($answer) or die "FAIL: malformed response question\n";
        $pos += 4;
    }
    my $opt_count = 0;
    my $extended_rcode;
    for (1..($an + $ns + $ar)) {
        $pos = after_name($answer, $pos);
        $pos + 10 <= length($answer) or die "FAIL: malformed resource record\n";
        my ($type, $class, $ttl, $rdlen) = unpack('nnNn', substr($answer, $pos, 10));
        $pos += 10;
        $pos + $rdlen <= length($answer) or die "FAIL: truncated resource data\n";
        if ($type == 41) {
            $opt_count++;
            $extended_rcode = ($ttl >> 24) & 0xff;
            my $edns_version = ($ttl >> 16) & 0xff;
            $edns_version == 0 or die "FAIL: response advertised unsupported EDNS version\n";
        }
        $pos += $rdlen;
    }
    $opt_count == 1 && defined($extended_rcode)
        or die "FAIL: missing or duplicate OPT record\n";
    my $rcode = ($extended_rcode << 4) | ($flags & 0x000f);
    $rcode == 16 or die "FAIL: expected BADVERS extended RCODE 16, received $rcode\n";
    print "PASS: $transport unsupported EDNS version returned BADVERS RCODE 16\n";
}
