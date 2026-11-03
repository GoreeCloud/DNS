#!/usr/bin/env perl
# Offline DNS protocol contract test. Invoke only inside the isolated DNS smoke container.
use strict;
use warnings;
use IO::Socket::INET;

my $protocol = shift @ARGV // '';
die "Usage: perl smoke_dns_protocol.pl udp|tcp\n" unless $protocol eq 'udp' || $protocol eq 'tcp';
die "Unexpected arguments\n" if @ARGV;

my $socket = IO::Socket::INET->new(
    PeerAddr => '127.0.0.1',
    PeerPort => 53,
    Proto    => $protocol,
    Timeout  => 4
) or die "FAIL: $protocol DNS socket unavailable: $!\n";

my $query_id = $protocol eq 'tcp' ? 0xC0DE : 0xBEEF;
my $question = pack('n6', $query_id, 0x0100, 1, 0, 0, 0)
             . pack('C', 9) . 'localhost' . "\0"
             . pack('n2', 1, 1);

sub read_exactly {
    my ($socket, $bytes) = @_;
    my $buffer = '';
    while (length($buffer) < $bytes) {
        my $received = sysread($socket, my $chunk, $bytes - length($buffer));
        defined $received && $received > 0
            or die "FAIL: $protocol DNS response ended early\n";
        $buffer .= $chunk;
    }
    return $buffer;
}

my $response;
$SIG{ALRM} = sub { die "FAIL: $protocol DNS query timed out\n" };
alarm 5;
if ($protocol eq 'udp') {
    send($socket, $question, 0) == length($question)
        or die "FAIL: $protocol DNS query send failed\n";
    my $sender = recv($socket, $response, 512, 0);
    defined $sender or die "FAIL: no UDP DNS response\n";
} else {
    my $payload = pack('n', length($question)) . $question;
    my $written = syswrite($socket, $payload);
    defined $written && $written == length($payload)
        or die "FAIL: TCP DNS query send failed\n";
    my $length = unpack('n', read_exactly($socket, 2));
    $length >= 12 && $length <= 65535
        or die "FAIL: invalid TCP DNS response length\n";
    $response = read_exactly($socket, $length);
}
alarm 0;

length($response) >= 12 or die "FAIL: malformed $protocol DNS response\n";
my ($id, $flags, $questions, $answers) = unpack('n4', $response);
$id == $query_id or die "FAIL: $protocol DNS transaction ID mismatch\n";
($flags & 0x8000) or die "FAIL: $protocol DNS response bit missing\n";
($flags & 0x7800) == 0 or die "FAIL: $protocol DNS response opcode changed\n";
($flags & 0x0200) == 0 or die "FAIL: unexpected truncated $protocol DNS refusal\n";
$questions == 1 or die "FAIL: $protocol DNS question count mismatch\\n";
# This query uses the first, uncompressed question name in the packet.
# A refusal for a different name/type/class must not satisfy this smoke test.
my $expected_question = substr($question, 12);
length($response) >= 12 + length($expected_question)
    or die "FAIL: $protocol DNS response question is truncated\\n";
substr($response, 12, length($expected_question)) eq $expected_question
    or die "FAIL: $protocol DNS response question changed\\n";
$answers == 0 or die "FAIL: $protocol DNS refusal unexpectedly contains answers\n";
($flags & 15) == 5 or die "FAIL: expected $protocol DNS REFUSED (recursion is denied)\n";
print "PASS: $protocol DNS returned REFUSED under explicit recursion-denied configuration\n";
