#!/usr/bin/env perl
# RFC 7858 DNS-over-TLS query against a disposable localhost-only test endpoint.
use strict;
use warnings;
use IPC::Open2;
use IO::Handle;

open my $file, '<:raw', '/work/doh-query.bin' or die "FAIL: missing test DNS question\n";
local $/;
my $query = <$file>;
close $file;
length($query) >= 12 or die "FAIL: short DNS test question\n";

sub read_exact {
    my ($handle, $size) = @_;
    my $data = '';
    while (length($data) < $size) {
        my $got = sysread($handle, my $part, $size - length($data));
        defined($got) && $got > 0 or die "FAIL: DoT TLS stream closed before response\n";
        $data .= $part;
    }
    return $data;
}

sub skip_name {
    my ($data, $pos) = @_;
    for (1..128) {
        $pos < length($data) or die "FAIL: short DoT DNS name\n";
        my $n = ord(substr($data, $pos, 1));
        if (($n & 0xc0) == 0xc0) {
            $pos + 2 <= length($data) or die "FAIL: malformed DoT compression pointer\n";
            return $pos + 2;
        }
        ($n & 0xc0) == 0 or die "FAIL: malformed DoT DNS label\n";
        $pos++;
        return $pos if $n == 0;
        $pos + $n <= length($data) or die "FAIL: DoT DNS label overrun\n";
        $pos += $n;
    }
    die "FAIL: DoT DNS name too long\n";
}

my ($reader, $writer, $pid, $answer);
my $success = eval {
    local $SIG{ALRM} = sub { die "FAIL: DoT TLS query timed out\n" };
    local $SIG{PIPE} = 'IGNORE';
    alarm 9;
    $pid = open2($reader, $writer,
        'openssl', 's_client', '-quiet',
        '-verify_return_error', '-verify_hostname', 'localhost',
        '-CAfile', '/work/doh-cert.pem',
        '-servername', 'localhost',
        '-connect', '127.0.0.1:1853');
    binmode($reader);
    binmode($writer);

    my $framed = pack('n', length($query)) . $query;
    my $offset = 0;
    while ($offset < length($framed)) {
        my $sent = syswrite($writer, $framed,
                            length($framed) - $offset, $offset);
        defined($sent) && $sent > 0 or die "FAIL: DoT framed query write failed\n";
        $offset += $sent;
    }
    my $length = unpack('n', read_exact($reader, 2));
    $length >= 12 && $length <= 4096 or die "FAIL: malformed DoT frame length\n";
    $answer = read_exact($reader, $length);
    alarm 0;
    1;
};
my $error = $@;
if (defined($pid)) {
    kill 'TERM', $pid;
    close $writer if $writer;
    close $reader if $reader;
    waitpid($pid, 0);
}
$success or die $error || "FAIL: DoT TLS client failed\n";

my ($id, $flags, $questions, $answers) = unpack('n4', $answer);
$id == 0 && ($flags & 0x8000) && ($flags & 0x0400) &&
    (($flags & 0x000f) == 0) && $questions == 1 && $answers >= 1
    or die "FAIL: DoT authoritative response flags are wrong\n";

my $at = 12;
for (1..$questions) {
    $at = skip_name($answer, $at);
    $at + 4 <= length($answer) or die "FAIL: DoT question truncated\n";
    $at += 4;
}
my $found = 0;
for (1..$answers) {
    $at = skip_name($answer, $at);
    $at + 10 <= length($answer) or die "FAIL: DoT resource header truncated\n";
    my ($type, $class, $ttl, $rdlength) = unpack('nnNn', substr($answer, $at, 10));
    $at += 10;
    $at + $rdlength <= length($answer) or die "FAIL: DoT resource data truncated\n";
    if ($type == 1 && $class == 1 && $ttl > 0 && $ttl <= 120 &&
        $rdlength == 4 && substr($answer, $at, 4) eq pack('C4', 192, 0, 2, 42)) {
        $found = 1;
    }
    $at += $rdlength;
}
$found or die "FAIL: DoT authoritative A record missing\n";
print "PASS: DoT verified TLS identity, DNS TCP framing and authoritative A response\n";

# The same CA-trusted endpoint must not authenticate under a different hostname.
my $bad_rc = system('timeout', '6s', 'openssl', 's_client', '-brief',
    '-verify_return_error', '-verify_hostname', 'wrong-host.invalid',
    '-CAfile', '/work/doh-cert.pem', '-servername', 'wrong-host.invalid',
    '-connect', '127.0.0.1:1853');
$bad_rc > 0 && $bad_rc != (124 << 8) &&
    $bad_rc != (125 << 8) && $bad_rc != (126 << 8) && $bad_rc != (127 << 8)
    or die "FAIL: DoT hostname mismatch did not fail TLS verification\n";
print "PASS: DoT certificate hostname mismatch rejected\n";
