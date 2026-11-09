#!/usr/bin/env perl
# Narrow signed NODATA proof capture, after the disposable smoke.invalid signing.
# Only saves public response packets. No private keys, host networking or config.
use strict;
use warnings;
use IO::Socket::INET;

sub read_exact {
    my ($s, $count) = @_;
    my $data = '';
    while (length($data) < $count) {
        my $got = sysread($s, my $bytes, $count - length($data));
        defined($got) && $got > 0 or die "FAIL: DNSSEC NODATA TCP incomplete\n";
        $data .= $bytes;
    }
    return $data;
}

for my $transport ('udp','tcp') {
    # An existing A-only owner must not answer an AAAA type. Its NSEC bitmap
    # can prove exactly this limited NODATA fact; NOT NXDOMAIN or wildcard.
    my $name = "\x04host\x05smoke\x07invalid\x00";
    my $id = $transport eq 'udp' ? 0xc201 : 0xc202;
    my $opt = pack('CnnNn', 0, 41, 1232, 0x8000, 0);
    my $question = pack('n6', $id, 0x0100, 1, 0, 0, 1)
        . $name . pack('n2', 28, 1) . $opt; # AAAA, IN, EDNS DO
    my $sock = IO::Socket::INET->new(
        PeerAddr => '127.0.0.1', PeerPort => 53,
        Proto => $transport, Timeout => 5,
    ) or die "FAIL: DNSSEC NODATA sandbox socket unavailable\n";
    local $SIG{ALRM} = sub { die "FAIL: DNSSEC NODATA timed out\n" };
    alarm 8;
    my $wire;
    if ($transport eq 'udp') {
        send($sock, $question, 0) == length($question)
            or die "FAIL: DNSSEC NODATA UDP send\n";
        defined recv($sock, $wire, 4096, 0)
            or die "FAIL: DNSSEC NODATA UDP receive\n";
    } else {
        my $frame = pack('n', length($question)) . $question;
        syswrite($sock, $frame) == length($frame)
            or die "FAIL: DNSSEC NODATA TCP send\n";
        my $length = unpack('n', read_exact($sock, 2));
        $length >= 12 && $length <= 65535
            or die "FAIL: DNSSEC NODATA TCP framing\n";
        $wire = read_exact($sock, $length);
    }
    alarm 0;
    length($wire) >= 12 or die "FAIL: short DNSSEC NODATA response\n";
    my ($response_id, $flags, $qd, $an, $ns, $ar) = unpack('n6', $wire);
    if ($response_id != $id || !($flags & 0x8000) ||
        !($flags & 0x0400) || ($flags & 0x0200) ||
        (($flags & 15) != 0) || $qd != 1 || $an != 0 || $ns < 2) {
        die "FAIL: signed NODATA response shape not present\n";
    }
    my $file = "/work/dnssec-nodata-$transport.bin";
    open my $out, '>:raw', $file or die "FAIL: cannot save NODATA packet\n";
    print {$out} $wire or die "FAIL: cannot write NODATA packet\n";
    close $out or die "FAIL: cannot close NODATA packet\n";
    chmod 0600, $file or die "FAIL: cannot protect NODATA packet\n";
    print "PASS: $transport NODATA AAAA packet preserved for independent NSEC check\n";
}
