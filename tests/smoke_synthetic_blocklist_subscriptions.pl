#!/usr/bin/env perl
# GoreeCloud DNS candidate: 10 synthetic enabled / 2 disabled local-list smoke.
# Must execute only inside a disposable --network=none rootless container.
use strict;
use warnings;
use IO::Socket::INET;
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

my $header=shift @ARGV // die "FAIL: missing temporary auth header\n";
@ARGV==0 && $header eq '/work/session-header' && -f $header
    or die "FAIL: invalid synthetic-list arguments\n";
my $root="http://127.0.0.1:5380";
my $listen_port=18081;
my $listen=IO::Socket::INET->new(
    LocalAddr=>'127.0.0.1',LocalPort=>$listen_port,Proto=>'tcp',
    Listen=>12,ReuseAddr=>1,Timeout=>5
) or die "FAIL: synthetic localhost list server cannot bind\n";
my $pid=fork();
defined $pid or die "FAIL: synthetic local server cannot fork\n";
if ($pid==0) {
    $SIG{ALRM}=sub{exit 0};
    alarm 70;
    while (my $client=$listen->accept()) {
        eval {
            $client->autoflush(1);
            my $request=<$client> // '';
            my ($n)=$request =~ m!\AGET\s+/list-(\d{2})\.txt\s+HTTP/1\.[01]\r?\n\z!;
            my $count=0;
            while (defined(my $line=<$client>)) {
                last if $line =~ /^\r?\n$/;
                ++$count <= 40 or die "header limit\n";
            }
            if (defined($n) && $n >=1 && $n <=12) {
                my $domain=sprintf('policy-list-%02d.example',$n);
                my $body="0.0.0.0 $domain\n";
                print $client "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ".length($body)."\r\nConnection: close\r\n\r\n".$body;
            } else {
                print $client "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            }
        };
        close $client;
    }
    exit 0;
}
close $listen;
END {
    local $?;  # Server cleanup must not overwrite successful test exit status.
    if (defined($pid) && $pid>0) {
        kill 'TERM',$pid;
        waitpid($pid,0);
    }
}
my $num=0;
sub api {
    my ($path,@parts)=@_;
    $num++;
    my $file="/work/list-policy-api-$num.json";
    my @cmd=('curl','--fail','--silent','--show-error','--max-time','5',
             '--noproxy','*','--output',$file,'--header','@'.$header,'--get');
    push @cmd,map {('--data-urlencode',$_)} @parts;
    push @cmd,$root.$path;
    system(@cmd)==0 or die "FAIL: candidate blocklist settings API transport\n";
    open my $fh,'<',$file or die "FAIL: candidate blocklist API output\n";
    local $/;
    my $body=eval {decode_json(<$fh>)};
    close $fh;
    ref($body) eq 'HASH' && ($body->{status}//'') eq 'ok'
        or die "FAIL: blocklist API unexpected status\n";
    return $body;
}
sub blocked {
    my ($number,$tcp)=@_;
    $number>=1 && $number<=12 or die "FAIL: nonfixture list name\n";
    my $domain=sprintf('policy-list-%02d.example',$number);
    my @cmd=('dig','+tries=1','+time=2','+noall','+comments','+answer');
    push @cmd,'+tcp' if $tcp;
    push @cmd,'-b','127.0.0.3','@127.0.0.1','-p','53',$domain,'A';
    open my $fh,'-|',@cmd or die "FAIL: list DNS query cannot run\n";
    local $/;my $text=<$fh>;
    close $fh or die "FAIL: list DNS query exited nonzero\n";
    defined $text && length($text)<12000
        or die "FAIL: list DNS packet too large\n";
    return ($text =~ /^policy-list-\d{2}\.example\.\s+\d+\s+IN\s+A\s+0\.0\.0\.0\s*$/m)?1:0;
}
my @active=map{sprintf('http://127.0.0.1:%d/list-%02d.txt',$listen_port,$_)}(1..10);
my @inactive=map{sprintf('http://127.0.0.1:%d/list-%02d.txt',$listen_port,$_)}(11..12);
@active==10 && @inactive==2 or die "FAIL: fixture count wrong\n";
api('/api/settings/set',
    'enableBlocking=true','blockingType=AnyAddress',
    'recursion=AllowOnlyForPrivateNetworks',
    'blockListUrls='.join(',',@active));
my $settings=api('/api/settings/get')->{response};
ref($settings) eq 'HASH' && ref($settings->{blockListUrls}) eq 'ARRAY'
    or die "FAIL: blockListUrls config not reported\n";
my $actual=$settings->{blockListUrls};
@$actual==10 or die "FAIL: not all 10 synthetic list subscriptions configured\n";
my %configured=map {$_=>1} @$actual;
for my $u (@active) {$configured{$u} or die "FAIL: configured list URL mismatch\n";}
for my $u (@inactive) {!$configured{$u} or die "FAIL: inactive list configured\n";}
print "PASS: 10 enabled and 2 excluded synthetic blocklist subscriptions configured\n";
api('/api/settings/forceUpdateBlockLists');
print "PASS: synthetic local blocklist update trigger accepted\n";
my $full=0;
for my $trial (1..20) {
    $full=1;
    for my $i (1..10) {
        if (!blocked($i,0)) {$full=0;last}
    }
    last if $full;
    select(undef,undef,undef,0.5);
}
$full or die "FAIL: not all 10 synthetic downloaded lists applied\n";
for my $i (1..10) {
    blocked($i,1) or die "FAIL: synthetic blocklist not enforced via TCP\n";
}
print "PASS: 10 synthetic blocklist domains blocked over both UDP and TCP\n";
for my $i (11..12) {
    !blocked($i,0) && !blocked($i,1)
        or die "FAIL: disabled list unexpectedly applied\n";
}
print "PASS: 2 excluded synthetic subscriptions do not block their fixture domains\n";
print "PASS: synthetic list transport and policy matrix complete, actual AdGuard list content and DNS client parity remain unverified\n";
