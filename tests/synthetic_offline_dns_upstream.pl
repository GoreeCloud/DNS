#!/usr/bin/env perl
# Synthetic DNS-only forwarder for a disposable rootless --network=none lab.
# Serves precisely one RFC 2606 .example A record with a RFC 5737 TEST-NET IP.
use strict;
use warnings;
use IO::Socket::INET;
use Socket qw(SOCK_DGRAM);
$> == 1654 && (-f '/.dockerenv' || -f '/run/.containerenv')
    or die "FAIL: disposable nonroot DNS lab only\n";
opendir(my $dir,'/sys/class/net') or die "FAIL: no network namespace\n";
my @interfaces=grep {$_ ne '.' && $_ ne '..'} readdir($dir);
closedir($dir);
@interfaces==1 && $interfaces[0] eq 'lo'
    or die "FAIL: network egress interface present\n";
my $udp=IO::Socket::INET->new(LocalAddr=>'127.0.0.4',LocalPort=>5301,Proto=>'udp',ReuseAddr=>1)
    or die "FAIL: loopback UDP 5301 bind unavailable\n";
$SIG{TERM}=sub{exit 0};
$SIG{INT}=sub{exit 0};
$|=1;
print "READY: fixed synthetic DNS upstream loopback UDP only\n";
while (1){
    my $peer=recv($udp,my $message,2048,0);
    next unless defined($peer) && defined($message) && length($message)>=17 && length($message)<=2048;
    my ($id,$flags,$qd)=unpack('n3',substr($message,0,6));
    next unless $qd==1 && !($flags & 0x8000);
    my $offset=12;my @labels;my $ok=1;
    for(1..20) {
        $ok=0,last if $offset>=length($message);
        my $n=ord(substr($message,$offset++,1));
        last if $n==0;
        if($n>63 || $offset+$n>length($message)){$ok=0;last;}
        my $label=substr($message,$offset,$n);
        if($label!~/\A[a-zA-Z0-9-]{1,63}\z/){$ok=0;last;}
        push @labels,lc($label);
        $offset+=$n;
    }
    next unless $ok && $offset+4<=length($message);
    my ($type,$class)=unpack('n2',substr($message,$offset,4));
    my $question=substr($message,12,$offset+4-12);
    my $valid=(join('.',@labels) eq 'policy-block-1.example' && $type==1 && $class==1);
    print "SYNTHETIC_A_QUERY\n" if $valid;
    my $header=pack('n6',$id,$valid?0x8580:0x8583,1,$valid?1:0,0,0);
    my $answer=$valid?pack('n n n N n C4',0xc00c,1,1,60,4,192,0,2,53):'';
    send($udp,$header.$question.$answer,0,$peer);
}
