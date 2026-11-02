#!/usr/bin/env perl
# Temporary first-run administrator session smoke: run only in offline container.
use strict;
use warnings;
use JSON::PP qw(decode_json);

my $root = 'http://127.0.0.1:5380';

sub api {
    my ($name, @arguments) = @_;
    my $output = "/work/$name.json";
    my $result = system('curl', '--fail', '--silent', '--show-error',
        '--max-time', '5', '--output', $output, @arguments);
    $result == 0 or die "FAIL: HTTP request for $name failed\n";

    open my $handle, '<', $output or die "FAIL: cannot read $name response\n";
    local $/;
    my $data = <$handle>;
    close $handle;
    my $body = eval { decode_json($data) };
    ref($body) eq 'HASH' or die "FAIL: malformed JSON for $name\n";
    return $body;
}

my $bad = api('bad-login',
    '--data-urlencode', 'user=admin',
    '--data-urlencode', 'pass=admin',
    "$root/api/user/login");
($bad->{status} // '') ne 'ok' && !exists $bad->{token}
    or die "FAIL: known default password was accepted despite secret-file setup\n";
print "PASS: known default admin password rejected\n";

# curl reads the secret from a file; it never appears in command-line arguments.
my $login = api('valid-login',
    '--data-urlencode', 'user=admin',
    '--data-urlencode', 'pass@/work/admin-password',
    "$root/api/user/login");
($login->{status} // '') eq 'ok' && ($login->{username} // '') eq 'admin'
    or die "FAIL: configured admin password did not authenticate\n";
my $token = $login->{token} // '';
$token =~ /\A[0-9a-fA-F]{64}\z/
    or die "FAIL: invalid login token format\n";

my $header_path = '/work/session-header';
open my $header, '>', $header_path or die "FAIL: cannot create temporary auth header\n";
print {$header} "Authorization: Bearer $token\n";
close $header;
chmod 0600, $header_path or die "FAIL: cannot protect auth header\n";
undef $token;
print "PASS: configured admin password authenticated\n";

my $settings = api('authenticated-settings',
    '--header', '@' . $header_path,
    "$root/api/settings/get");
($settings->{status} // '') eq 'ok' && ref($settings->{response}) eq 'HASH'
    or die "FAIL: authenticated admin cannot read settings\n";
print "PASS: authenticated settings API access\n";

system('perl', '/work/smoke_authoritative.pl', $header_path) == 0
    or die "FAIL: isolated authoritative DNS verification failed\n";

my $logout = api('logout', '--header', '@' . $header_path, "$root/api/user/logout");
($logout->{status} // '') eq 'ok'
    or die "FAIL: logout was unsuccessful\n";

my $revoked = api('revoked-settings',
    '--header', '@' . $header_path,
    "$root/api/settings/get");
($revoked->{status} // '') eq 'invalid-token' && !exists $revoked->{response}
    or die "FAIL: logged-out token still accesses settings\n";
print "PASS: logged-out token cannot access settings\n";
