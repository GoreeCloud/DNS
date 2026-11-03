#!/usr/bin/env perl
# Disposable DoH/TLS wire acceptance. Run only in the network-none smoke container.
use strict;
use warnings;
use JSON::PP qw(decode_json);
use MIME::Base64 qw(encode_base64);

my $auth_header = shift @ARGV // die "Usage: perl smoke_doh_tls.pl /work/session-header\n";
die "FAIL: unexpected arguments\n" if @ARGV;
-f $auth_header or die "FAIL: session header missing\n";

open my $urandom, '<:raw', '/dev/urandom' or die "FAIL: secure randomness unavailable\n";
read($urandom, my $random, 18) == 18 or die "FAIL: short randomness read\n";
close $urandom;
open my $password_file, '>', '/work/doh-pfx-password'
    or die "FAIL: could not create temporary PFX password file\n";
print {$password_file} unpack('H*', $random);
close $password_file;
chmod 0600, '/work/doh-pfx-password';

system('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
       '-sha256', '-days', '1', '-subj', '/CN=localhost',
       '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
       '-keyout', '/work/doh-private.key', '-out', '/work/doh-cert.pem') == 0
    or die "FAIL: cannot generate disposable localhost certificate\n";
system('openssl', 'pkcs12', '-export', '-in', '/work/doh-cert.pem',
       '-inkey', '/work/doh-private.key', '-out', '/work/doh.pfx',
       '-passout', 'file:/work/doh-pfx-password') == 0
    or die "FAIL: cannot generate disposable PKCS#12 certificate\n";

my @settings_cmd = ('curl', '--silent', '--show-error', '--fail',
    '--noproxy', '*', '--max-time', '15', '--header', '@' . $auth_header,
    '--data-urlencode', 'enableDnsOverHttps=true',
    '--data-urlencode', 'enableDnsOverTls=true',
    '--data-urlencode', 'dnsOverTlsPort=1853',
    '--data-urlencode', 'dnsOverHttpsPort=18443',
    '--data-urlencode', 'dnsTlsCertificatePath=/work/doh.pfx',
    '--data-urlencode', 'dnsTlsCertificatePassword@/work/doh-pfx-password',
    '--output', '/work/doh-settings.json',
    'http://127.0.0.1:5380/api/settings/set');
system(@settings_cmd) == 0 or die "FAIL: cannot configure local DoH listener\n";
open my $settings, '<', '/work/doh-settings.json' or die "FAIL: settings response missing\n";
local $/;
my $settings_body = <$settings>;
close $settings;
my $json = eval { decode_json($settings_body) };
ref($json) eq 'HASH' && ($json->{status} // '') eq 'ok'
    or die "FAIL: settings API rejected disposable DoH listener\n";

my $qname = join('', map { pack('C', length($_)) . $_ } qw(host smoke invalid)) . "\0";
my $query = pack('n6', 0, 0x0100, 1, 0, 0, 0) . $qname . pack('n2', 1, 1);
open my $query_file, '>:raw', '/work/doh-query.bin' or die "FAIL: query file\n";
print {$query_file} $query;
close $query_file;

sub after_name {
    my ($wire, $offset) = @_;
    for (1..128) {
        $offset < length($wire) or die "FAIL: DoH response name truncated\n";
        my $size = ord(substr($wire, $offset, 1));
        if (($size & 0xc0) == 0xc0) {
            $offset + 2 <= length($wire) or die "FAIL: short DoH compression pointer\n";
            return $offset + 2;
        }
        ($size & 0xc0) == 0 or die "FAIL: invalid DoH name label\n";
        $offset++;
        return $offset if $size == 0;
        $offset + $size <= length($wire) or die "FAIL: truncated DoH label\n";
        $offset += $size;
    }
    die "FAIL: too many DoH name labels\n";
}

sub check_response {
    my ($label) = @_;
    open my $headers, '<', "/work/$label.headers" or die "FAIL: DoH headers missing\n";
    local $/;
    my $http_headers = <$headers>;
    close $headers;
    $http_headers =~ m!^HTTP/(?:1\.\d|2) 200\b!m
        or die "FAIL: $label expected HTTP 200\n";
    $http_headers =~ m!^content-type:\s*application/dns-message\b!im
        or die "FAIL: $label unexpected DoH response content type\n";

    open my $body, '<:raw', "/work/$label.response" or die "FAIL: DoH binary response missing\n";
    my $wire = <$body>;
    close $body;
    length($wire) >= 12 or die "FAIL: $label short DNS payload\n";
    my ($id, $flags, $qd, $an) = unpack('n4', $wire);
    $id == 0 && ($flags & 0x8000) && ($flags & 0x0400) &&
        (($flags & 0x000f) == 0) && $qd == 1 && $an >= 1
        or die "FAIL: $label unexpected authoritative DNS result\n";
    my $offset = 12;
    for (1..$qd) {
        $offset = after_name($wire, $offset);
        $offset + 4 <= length($wire) or die "FAIL: $label short question\n";
        $offset += 4;
    }
    my $found = 0;
    for (1..$an) {
        $offset = after_name($wire, $offset);
        $offset + 10 <= length($wire) or die "FAIL: $label short record header\n";
        my ($type, $class, $ttl, $len) = unpack('nnNn', substr($wire, $offset, 10));
        $offset += 10;
        $offset + $len <= length($wire) or die "FAIL: $label truncated record data\n";
        if ($type == 1 && $class == 1 && $ttl > 0 && $ttl <= 120 &&
            $len == 4 && substr($wire, $offset, 4) eq pack('C4', 192, 0, 2, 42)) {
            $found = 1;
        }
        $offset += $len;
    }
    $found or die "FAIL: $label missing disposable authoritative A record\n";
}

sub run_doh {
    my ($label, $method) = @_;
    my @cmd = ('curl', '--silent', '--fail', '--noproxy', '*',
        '--max-time', '5', '--cacert', '/work/doh-cert.pem',
        '--resolve', 'localhost:18443:127.0.0.1',
        '--header', 'Accept: application/dns-message',
        '--dump-header', "/work/$label.headers",
        '--output', "/work/$label.response");
    if ($method eq 'POST') {
        push @cmd, '--header', 'Content-Type: application/dns-message',
            '--data-binary', '@/work/doh-query.bin';
    } else {
        my $encoded = encode_base64($query, '');
        $encoded =~ tr|+/|-_|;
        $encoded =~ s/=+$//;
        push @cmd, '--get', '--data-urlencode', 'dns=' . $encoded;
    }
    push @cmd, 'https://localhost:18443/dns-query';
    return system(@cmd) == 0;
}

my $started = 0;
for (1..18) {
    if (run_doh('doh-post', 'POST')) {
        $started = 1;
        last;
    }
    select undef, undef, undef, 0.4;
}
$started or die "FAIL: verified local DoH POST listener did not respond\n";
check_response('doh-post');
print "PASS: DoH POST verified TLS hostname and authoritative A response\n";

run_doh('doh-get', 'GET') or die "FAIL: verified local DoH GET request failed\n";
check_response('doh-get');
print "PASS: DoH GET verified TLS hostname and authoritative A response\n";

sub expect_http_error {
    my ($name, $expected_code, @options) = @_;
    my @args = ('curl', '--silent', '--show-error', '--noproxy', '*',
        '--max-time', '5', '--cacert', '/work/doh-cert.pem',
        '--resolve', 'localhost:18443:127.0.0.1',
        '--header', 'Accept: application/dns-message',
        '--dump-header', "/work/$name.headers",
        '--output', "/work/$name.response",
        @options, 'https://localhost:18443/dns-query');
    system(@args) == 0 or die "FAIL: $name HTTPS transport failed\n";
    open my $headers, '<', "/work/$name.headers"
        or die "FAIL: $name status headers missing\n";
    local $/;
    my $raw_headers = <$headers>;
    close $headers;
    $raw_headers =~ m!^HTTP/(?:1\.\d|2) $expected_code\b!m
        or die "FAIL: $name expected HTTP $expected_code\n";
}
expect_http_error('doh-missing-dns', 400);
expect_http_error('doh-invalid-dns-base64', 400,
    '--get', '--data-urlencode', 'dns=not*base64');
expect_http_error('doh-invalid-post-media', 415,
    '--header', 'Content-Type: text/plain',
    '--data-binary', '@/work/doh-query.bin');
print "PASS: DoH missing/malformed GET and wrong POST media type rejected\n";
run_doh('doh-valid-after-errors', 'POST')
    or die "FAIL: DoH valid request failed after invalid requests\n";
check_response('doh-valid-after-errors');
print "PASS: DoH valid request still succeeds after invalid requests\n";

my @bad_host = ('curl', '--silent', '--fail', '--noproxy', '*', '--max-time', '4',
    '--cacert', '/work/doh-cert.pem',
    '--resolve', 'wrong-host.invalid:18443:127.0.0.1',
    '--output', '/dev/null', 'https://wrong-host.invalid:18443/dns-query');
my $exit = system(@bad_host);
$exit == (60 << 8) or die "FAIL: invalid TLS hostname was not rejected with certificate error\n";
print "PASS: DoH certificate hostname mismatch rejected\n";
