#!/usr/bin/env perl
# Offline-only authoritative negative-answer verification for disposable smoke.invalid.
use strict;
use warnings;
use IO::Socket::INET;

sub exact_read {
    my ($socket, $wanted) = @_;
    my $out = '';
    while (length($out) < $wanted) {
        my $count = sysread($socket, my $chunk, $wanted - length($out));
        defined($count) && $count > 0 or die "FAIL: short TCP negative DNS read\n";
        $out .= $chunk;
    }
    return $out;
}

sub after_name {
    my ($message, $position) = @_;
    for (1..128) {
        $position < length($message) or die "FAIL: short compressed domain name\n";
        my $label_size = ord(substr($message, $position, 1));
        if (($label_size & 0xc0) == 0xc0) {
            $position + 2 <= length($message) or die "FAIL: truncated name pointer\n";
            return $position + 2;
        }
        ($label_size & 0xc0) == 0 or die "FAIL: malformed DNS label\n";
        $position++;
        return $position if $label_size == 0;
        $position + $label_size <= length($message) or die "FAIL: short DNS label\n";
        $position += $label_size;
    }
    die "FAIL: excessive DNS labels\n";
}

sub verify_negative {
    my ($transport, $name, $type, $expected_rcode, $id) = @_;
    my $domain = join('', map { pack('C', length($_)) . $_ } split /\./, $name) . "\0";
    my $packet = pack('n6', $id, 0x0100, 1, 0, 0, 0)
        . $domain . pack('n2', $type, 1);
    my $socket = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
        PeerPort => 53, Proto => $transport, Timeout => 4)
        or die "FAIL: $transport negative DNS socket unavailable\n";
    my $answer;
    local $SIG{ALRM} = sub { die "FAIL: $transport negative DNS timeout\n" };
    alarm 5;
    if ($transport eq 'udp') {
        send($socket, $packet, 0) == length($packet) or die "FAIL: UDP negative query send\n";
        defined recv($socket, $answer, 4096, 0) or die "FAIL: UDP negative query read\n";
    } else {
        my $wire = pack('n', length($packet)) . $packet;
        syswrite($socket, $wire) == length($wire) or die "FAIL: TCP negative query send\n";
        my $n = unpack('n', exact_read($socket, 2));
        $n >= 12 or die "FAIL: TCP negative DNS response too short\n";
        $answer = exact_read($socket, $n);
    }
    alarm 0;
    length($answer) >= 12 or die "FAIL: negative DNS response too short\n";
    my ($reply_id, $flags, $qd, $an, $ns, $ar) = unpack('n6', $answer);
    $reply_id == $id && ($flags & 0x8000) && ($flags & 0x0400)
        && (($flags & 0x000f) == $expected_rcode) && $qd == 1 && $an == 0
        or die "FAIL: $transport unexpected negative DNS header (expected code $expected_rcode)\n";
    my $offset = 12;
    for (1..$qd) {
        $offset = after_name($answer, $offset);
        $offset + 4 <= length($answer) or die "FAIL: short question metadata\n";
        $offset += 4;
    }
    my $saw_soa = 0;
    for (1..$ns) {
        $offset = after_name($answer, $offset);
        $offset + 10 <= length($answer) or die "FAIL: short authority record header\n";
        my ($rrtype, $class, $ttl, $length) =
            unpack('nnNn', substr($answer, $offset, 10));
        $offset += 10;
        $offset + $length <= length($answer) or die "FAIL: short authority RDATA\n";
        $saw_soa = 1 if $rrtype == 6 && $class == 1 && $length > 0;
        $offset += $length;
    }
    $saw_soa or die "FAIL: $transport negative authoritative response missing SOA\n";
    print "PASS: $transport authoritative negative code $expected_rcode with SOA\n";
}

for my $proto ('udp', 'tcp') {
    verify_negative($proto, 'absent.smoke.invalid', 1, 3,
        $proto eq 'udp' ? 0xd301 : 0xd302);
    verify_negative($proto, 'host.smoke.invalid', 28, 0,
        $proto eq 'udp' ? 0xd303 : 0xd304);
}
