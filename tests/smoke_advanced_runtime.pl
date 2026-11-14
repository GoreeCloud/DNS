#!/usr/bin/env perl
# Disposable rootless/no-network synthetic Advanced Blocking wire acceptance.
use strict;use warnings;use JSON::PP qw(decode_json);
$> == 1654 && -f '/work/admin-password' && -f '/work/AdvancedBlocking.zip'
 && (-f '/.dockerenv' || -f '/run/.containerenv') or die "FAIL: isolated runtime required\n";
opendir(my $n,'/sys/class/net') or die "FAIL: no net namespace\n";
my @ifs=grep {$_ ne '.' && $_ ne '..'} readdir($n);closedir($n);
@ifs==1 && $ifs[0] eq 'lo' or die "FAIL: external network interface\n";
my $base='http://127.0.0.1:5380';my $count=0;
sub api{
 my($path,$mode,@fields)=@_;++$count;
 $path =~ m{\A/api/[A-Za-z0-9?=&/-]+\z} or die "FAIL: path\n";
 my $file="/work/advanced-api-$count.json";
 my @cmd=('curl','--fail','--silent','--show-error','--max-time','10','--noproxy','*','--output',$file);
 if($mode eq 'login'){push @cmd,'--data-urlencode','user=admin','--data-urlencode','pass@/work/admin-password';}
 elsif($mode eq 'post'){push @cmd,'--header','@/work/session-header',@fields;}
 elsif($mode eq 'get'){push @cmd,'--header','@/work/session-header','--get';for(@fields){push @cmd,'--data-urlencode',$_;}}
 else{die "FAIL: mode\n";}
 push @cmd,$base.$path;system(@cmd)==0 or die "FAIL: localhost API transport\n";
 open my $fh,'<',$file or die "FAIL: response missing\n";local $/;my $s=<$fh>;close $fh;
 defined($s)&&length($s)<200000 or die "FAIL: response bound\n";
 my $v=eval{decode_json($s)};ref($v) eq 'HASH' or die "FAIL: invalid API JSON\n";
 if(($v->{status}//'') ne 'ok'){my $state=$v->{status}//'unknown';$state =~ /\A[a-zA-Z0-9_-]{1,48}\z/ or $state='unknown';die "FAIL: local API status $state\n";}
 return $v;
}
sub dns {
 my($ip,$tcp,$type)=@_;
 $ip =~ /\A127\.0\.0\.[23]\z/ && $type =~ /\A(?:A|TXT)\z/ or die "FAIL: fixture mismatch\n";
 my @cmd=('dig','+tries=1','+time=2','+noall','+comments','+answer','+edns=0');
 push @cmd,'+tcp' if $tcp;
 push @cmd,'-b',$ip,'@127.0.0.1','-p','53','policy-block-1.example',$type;
 open my $fh,'-|',@cmd or die "FAIL: dig start\n";
 local $/;my $text=<$fh>;close $fh or die "FAIL: dig timeout\n";
 defined($text)&&length($text)<16000 or die "FAIL: DNS output invalid\n";
 my($rcode)=$text=~/status:\s*([A-Z]+),/;$rcode //='UNKNOWN';
 my $blocked=($text=~/^policy-block-1\.example\.\s+\d+\s+IN\s+A\s+0\.0\.0\.0\s*$/m)?1:0;
 my $leak=($text=~/source=advanced-blocking-app|blockListUrl=|group=filtered/)?1:0;
 return[$rcode,$blocked,$leak];
}
my $before=dns('127.0.0.3',0,'A');
!$before->[1] or die "FAIL: initially blocked\n";
print "PASS: preinstall synthetic DNS name not blocked\n";
my $login=api('/api/user/login','login');
($login->{username}//'') eq 'admin' && ($login->{token}//'')=~/\A[0-9a-fA-F]{64}\z/ or die "FAIL: ephemeral auth\n";
open my $h,'>','/work/session-header' or die "FAIL: auth header file\n";
print {$h} "Authorization: Bearer $login->{token}\n";close $h;
chmod 0600,'/work/session-header' or die "FAIL: auth header mode\n";undef $login;
print "PASS: ephemeral admin session\n";
api('/api/settings/set','get','enableBlocking=false','recursion=AllowOnlyForPrivateNetworks');
my $settings=api('/api/settings/get','get');
ref($settings->{response}) eq 'HASH' && !$settings->{response}{enableBlocking} or die "FAIL: builtin still enabled\n";
print "PASS: built-in blocking disabled only in lab\n";
my $r=api('/api/apps/install?name=AdvancedBlocking','post','-F','file=@/work/AdvancedBlocking.zip;type=application/zip');
my $entries=$r->{response}{installedApp}{dnsApps};
ref($entries) eq 'ARRAY' or die "FAIL: no loaded DNS app handlers\n";
my $found=0;
for my $x(@$entries){
 if(ref($x) eq 'HASH' && ($x->{classPath}//'') eq 'AdvancedBlocking.App' && $x->{isRequestBlockingHandler}){$found=1;}
}
print "DIAGNOSTIC: installer_module_count=".scalar(@$entries)."\n";
for my $entry (@$entries) { next unless ref($entry) eq 'HASH'; print "DIAGNOSTIC: app_class_match=".(($entry->{classPath}//'') eq 'AdvancedBlocking.App'?1:0)." request_blocking_handler=".($entry->{isRequestBlockingHandler}?1:0)."\n"; }
$found or die "FAIL: app handler not loaded\n";
print "PASS: compiled app installed as blocking handler\n";
my $appconfig=api('/api/apps/config/get','get','name=AdvancedBlocking');
my $config=$appconfig->{response}{config};
defined($config)&&!ref($config) or die "FAIL: app config not text\n";
my $v=eval{decode_json($config)};
ref($v) eq 'HASH' && ref($v->{groups}) eq 'ARRAY' && @{$v->{groups}}==2 or die "FAIL: app groups unavailable\n";
for my $g(@{$v->{groups}}){ref($g) eq 'HASH' && exists($g->{allowTxtBlockingReport}) && !$g->{allowTxtBlockingReport} or die "FAIL: blocking report enabled\n";}
print "PASS: two synthetic groups with metadata report disabled\n";
for my $tcp(0,1){
 my $f=dns('127.0.0.3',$tcp,'A');my $b=dns('127.0.0.2',$tcp,'A');
 print "DIAGNOSTIC: ".($tcp?'tcp':'udp')." filtered=$f->[0]/$f->[1] bypass=$b->[0]/$b->[1]\n";
 $f->[0] eq 'NOERROR' && $f->[1] && !$b->[1] or die "FAIL: app per-client wire enforcement\n";
}
print "PASS: per-client app DNS answers differ over UDP and TCP\n";
my $txt=dns('127.0.0.3',0,'TXT');!$txt->[2] or die "FAIL: blocking report leaked\n";
print "PASS: TXT/EDNS report absent from synthetic blocked DNS response\n";
api('/api/user/logout','get');
print "PASS: session logged out; other protections NOT VERIFIED\n";
