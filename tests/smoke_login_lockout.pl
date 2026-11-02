#!/usr/bin/env perl
# Run ONLY after all other admin checks, inside the network-disabled disposable container.
use strict;
use warnings;
use JSON::PP qw(decode_json);

my $root = 'http://127.0.0.1:5380';

sub request_login {
    my ($label, $secret_field) = @_;
    my $path = "/work/$label.json";
    my @args = ('curl', '--silent', '--show-error', '--max-time', '7',
        '--output', $path, '--data-urlencode', 'user=admin',
        '--data-urlencode', $secret_field, "$root/api/user/login");
    system(@args) == 0 or die "FAIL: $label transport\n";
    open my $stream, '<', $path or die "FAIL: $label response unreadable\n";
    local $/;
    my $body = eval { decode_json(<$stream>) };
    close $stream;
    ref($body) eq 'HASH' or die "FAIL: $label malformed JSON\n";
    return $body;
}

# Five bounded negative requests against the disposable loopback-only service;
# never target an external account and never output the password or session token.
for my $attempt (1..5) {
    my $body = request_login("negative-login-$attempt",
        'pass=disposable-invalid-test-password');
    ($body->{status} // '') ne 'ok' && !exists $body->{token}
        or die "FAIL: negative login $attempt unexpectedly authenticated\n";
}
print "PASS: five incorrect disposable admin logins rejected\n";

# The correct secret must remain rejected while this source-IP lockout is active.
# curl reads the temporary secret from a protected file, not argv.
my $locked = request_login('locked-valid-login', 'pass@/work/admin-password');
($locked->{status} // '') ne 'ok' &&
    !exists $locked->{token} &&
    ($locked->{errorMessage} // '') =~ /Max limit of 5 attempts exceeded/
    or die "FAIL: source-IP lockout did not block a correct password\n";
print "PASS: five-attempt source-IP lockout denies valid login\n";
