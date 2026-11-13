#!/usr/bin/env perl
# GoreeCloud DNS candidate manual-block and client-bypass acceptance, V2.
# Only safe inside the authorized rootless --network=none disposable image.
# Uses reserved synthetic test names, loopback source IPs, throwaway auth.
use strict;
use warnings;
use JSON::PP qw(decode_json);

# Fail closed before any local management API interaction.
# Host users or containers with an external network must never run this test.
$> == 1654 && -d '/work' && -f '/work/admin-password'
    && (-f '/.dockerenv' || -f '/run/.containerenv')
    or die "FAIL: test requires disposable rootless container\n";
opendir(my $netdir, '/sys/class/net')
    or die "FAIL: cannot verify network isolation\n";
my @interfaces=grep {$_ ne '.' && $_ ne '..'} readdir($netdir);
closedir($netdir);
@interfaces == 1 && $interfaces[0] eq 'lo'
    or die "FAIL: test requires network namespace containing loopback only\n";

my $header = shift @ARGV // die "FAIL: missing ephemeral auth file\n";
@ARGV == 0 && $header eq '/work/session-header' && -f $header
    or die "FAIL: incorrect synthetic policy fixture\n";
my $base='http://127.0.0.1:5380';
my $counter=0;
sub api {
    my ($path,@fields)=@_;
    $counter++;
    my $file="/work/synthetic-v2-response-$counter.json";
    my @cmd=('curl','--fail','--silent','--show-error',
             '--max-time','5','--noproxy','*','--output',$file,
             '--header','@'.$header,'--get');
    push @cmd, map { ('--data-urlencode',$_) } @fields;
    push @cmd,$base.$path;
    system(@cmd)==0 or die "FAIL: synthetic policy API transport\n";
    open my $fh,'<',$file or die "FAIL: synthetic API result missing\n";
    local $/;
    my $d=eval {decode_json(<$fh>)};
    close $fh;
    ref($d) eq 'HASH' && ($d->{status}//'') eq 'ok'
        or die "FAIL: synthetic policy API rejected\n";
    return $d;
}
sub answer {
    my ($name,$client,$tcp)=@_;
    $name =~ /\Apolicy-block-[123]\.example\z/
        or die "FAIL: unexpected synthetic test name\n";
    $client =~ /\A127\.0\.0\.[23]\z/
        or die "FAIL: unexpected non-loopback client\n";
    my @args=('dig','+tries=1','+time=2','+noall','+comments','+answer');
    push @args,'+tcp' if $tcp;
    push @args,'-b',$client,'@127.0.0.1','-p','53',$name,'A';
    open my $fh,'-|',@args or die "FAIL: DNS test invocation\n";
    local $/; my $data=<$fh>;
    close $fh or die "FAIL: DNS test query failed\n";
    defined($data) && length($data)<16384
        or die "FAIL: DNS test response oversized or missing\n";
    my ($rcode)=$data =~ /status:\s*([A-Z]+),/;
    $rcode //= 'UNKNOWN';
    my $is_blocked=($data =~ /^policy-block-[123]\.example\.\s+\d+\s+IN\s+A\s+0\.0\.0\.0\s*$/m)?1:0;
    return [$rcode,$is_blocked];
}
api('/api/settings/set',
    'enableBlocking=true','blockingType=AnyAddress',
    'recursion=AllowOnlyForPrivateNetworks');
my $current=api('/api/settings/get')->{response};
ref($current) eq 'HASH' && $current->{enableBlocking} &&
  ($current->{blockingType}//'') eq 'AnyAddress'
    or die "FAIL: synthetic block settings were not applied\n";
print "PASS: synthetic address-based block settings confirmed\n";

my $baseline=answer('policy-block-1.example','127.0.0.3',0);
$baseline->[1] == 0 or die "FAIL: synthetic name blocked before policy creation\n";
print "PASS: synthetic name initially lacks blocked address\n";

for my $i (1..3) {
    api('/api/blocked/add',"domain=policy-block-$i.example");
}
for my $i (1..3) {
    for my $tcp (0,1) {
        my $got=answer("policy-block-$i.example",'127.0.0.3',$tcp);
        print "DIAGNOSTIC: manual-block i=$i tcp=$tcp rcode=$got->[0] blockaddr=$got->[1]\n";
        $got->[0] eq 'NOERROR' && $got->[1] == 1
            or die "FAIL: explicit blocked-domain address policy not enforced\n";
    }
}
print "PASS: 3 synthetic blocked hosts returned 0.0.0.0 via UDP and TCP\n";

api('/api/allowed/add','domain=policy-block-1.example');
for my $tcp (0,1) {
    my $got=answer('policy-block-1.example','127.0.0.3',$tcp);
    print "DIAGNOSTIC: allowed-override tcp=$tcp rcode=$got->[0] blockaddr=$got->[1]\n";
    $got->[1] == 0
        or die "FAIL: synthetic allow exception did not suppress block address\n";
}
print "PASS: synthetic allow exception suppresses manual blocked address\n";

api('/api/settings/set','blockingBypassList=127.0.0.2');
$current=api('/api/settings/get')->{response};
ref($current) eq 'HASH' && ref($current->{blockingBypassList}) eq 'ARRAY'
    or die "FAIL: synthetic bypass list not reflected\n";
for my $tcp (0,1) {
    my $blocked=answer('policy-block-2.example','127.0.0.3',$tcp);
    my $bypass=answer('policy-block-2.example','127.0.0.2',$tcp);
    print "DIAGNOSTIC: client-difference tcp=$tcp blocked=$blocked->[1] bypass=$bypass->[1]\n";
    $blocked->[1] == 1 && $bypass->[1] == 0
        or die "FAIL: synthetic two-client blocking/bypass difference absent\n";
}
print "PASS: two synthetic clients show distinct block/bypass outcomes over UDP and TCP\n";
print "PASS: only surrogate structure tested, no real AdGuard policies, logs or client identifiers\n";
