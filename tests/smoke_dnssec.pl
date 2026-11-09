#!/usr/bin/env perl
# Offline DNSSEC publication smoke. No external trust anchor or network involved.
use strict;
use warnings;
use IO::Socket::INET;
use JSON::PP qw(decode_json);

my $header = shift @ARGV // die "Usage: perl smoke_dnssec.pl /work/session-header\n";
-f $header && !@ARGV or die "FAIL: expected local auth header only\n";
my $root = 'http://127.0.0.1:5380';

# The private ECDSA keys and resulting zone are created only in disposable /work/config.
my @sign = ('curl', '--fail', '--silent', '--show-error', '--max-time', '20',
    '--output', '/work/dnssec-sign.json', '--header', '@' . $header, '--get',
    '--data-urlencode', 'zone=smoke.invalid', '--data-urlencode', 'algorithm=ECDSA',
    '--data-urlencode', 'curve=P256', '--data-urlencode', 'nxProof=NSEC',
    '--data-urlencode', 'zskRolloverDays=0',
    "$root/api/zones/dnssec/sign");
system(@sign) == 0 or die "FAIL: DNSSEC sign API transport\n";
open my $file, '<', '/work/dnssec-sign.json' or die "FAIL: sign API result unreadable\n";
local $/;
my $result = eval { decode_json(<$file>) };
close $file;
ref($result) eq 'HASH' && ($result->{status} // '') eq 'ok'
    or die "FAIL: sign API refused disposable zone\n";
print "PASS: disposable primary zone signed with ECDSA P-256\n";

sub exact_read {
    my ($sock, $required) = @_;
    my $bytes = '';
    while (length($bytes) < $required) {
        my $n = sysread($sock, my $chunk, $required - length($bytes));
        defined($n) && $n > 0 or die "FAIL: short TCP DNSSEC read\n";
        $bytes .= $chunk;
    }
    return $bytes;
}

sub skip_name {
    my ($wire, $pos) = @_;
    for (1..128) {
        $pos < length($wire) or die "FAIL: DNSSEC name out of range\n";
        my $size = ord(substr($wire, $pos, 1));
        if (($size & 0xc0) == 0xc0) {
            $pos + 2 <= length($wire) or die "FAIL: short DNS name pointer\n";
            return $pos + 2;
        }
        ($size & 0xc0) == 0 or die "FAIL: illegal DNSSEC label\n";
        $pos++;
        return $pos if $size == 0;
        $pos + $size <= length($wire) or die "FAIL: short DNSSEC label\n";
        $pos += $size;
    }
    die "FAIL: too many labels in DNS name\n";
}

sub signed_query {
    my ($transport, $labels, $qtype, $id) = @_;
    my $name = join('', map { pack('C', length($_)) . $_ } @$labels) . "\0";
    my $edns = pack('CnnNn', 0, 41, 1232, 0x8000, 0); # OPT, EDNS DO=1
    my $question = pack('n6', $id, 0x0100, 1, 0, 0, 1)
        . $name . pack('n2', $qtype, 1) . $edns;
    my $sock = IO::Socket::INET->new(PeerAddr=>'127.0.0.1', PeerPort=>53,
        Proto=>$transport, Timeout=>5)
        or die "FAIL: DNSSEC $transport socket unavailable\n";
    local $SIG{ALRM} = sub { die "FAIL: DNSSEC $transport query timed out\n" };
    alarm 8;
    my $wire;
    if ($transport eq 'udp') {
        send($sock, $question, 0) == length($question) or die "FAIL: UDP DO send\n";
        defined recv($sock, $wire, 4096, 0) or die "FAIL: UDP DO recv\n";
    } else {
        my $frame = pack('n', length($question)) . $question;
        syswrite($sock, $frame) == length($frame) or die "FAIL: TCP DO send\n";
        my $size = unpack('n', exact_read($sock, 2));
        $size >= 12 && $size <= 65535 or die "FAIL: TCP DO length\n";
        $wire = exact_read($sock, $size);
    }
    alarm 0;
    length($wire) >= 12 or die "FAIL: DNSSEC response too short\n";
    my ($response_id, $flags, $qd, $an, $ns, $ar) = unpack('n6', $wire);
    $response_id == $id && ($flags & 0x8000) && ($flags & 0x0400) &&
        !($flags & 0x0200) && (($flags & 15) == 0) && $qd == 1 && $an >= 2
        or die "FAIL: missing authoritative untruncated DNSSEC answer on $transport\n";
    my $at = 12;
    for (1..$qd) {
        $at = skip_name($wire, $at);
        $at + 4 <= length($wire) or die "FAIL: short DNSSEC question\n";
        $at += 4;
    }
    my ($records, $signatures) = (0,0);
    for (1..$an) {
        $at = skip_name($wire, $at);
        $at + 10 <= length($wire) or die "FAIL: short DNSSEC resource record\n";
        my ($rrtype, $class, $ttl, $len) = unpack('nnNn', substr($wire,$at,10));
        $at += 10;
        $at + $len <= length($wire) or die "FAIL: malformed DNSSEC RDATA\n";
        my $rdata = substr($wire, $at, $len);
        if ($rrtype == $qtype && $class == 1 && $len > 0) {
            $records++;
        }
        if ($rrtype == 46 && $class == 1 && $len >= 18
            && unpack('n', substr($rdata, 0, 2)) == $qtype) {
            $signatures++;
        }
        $at += $len;
    }
    $records >= 1 && $signatures >= 1
        or die "FAIL: missing DNSSEC type $qtype record or matching RRSIG on $transport\n";
    print "PASS: $transport DNSSEC type $qtype and covering RRSIG published\n";
}

for my $transport ('udp', 'tcp') {
    signed_query($transport, [qw(smoke invalid)], 48,
        $transport eq 'udp' ? 0xc101 : 0xc102);
    signed_query($transport, [qw(host smoke invalid)], 1,
        $transport eq 'udp' ? 0xc103 : 0xc104);
}
