#!/usr/bin/perl -w

use strict;
use warnings;
use IO::Socket::SSL;

print qq{
===============================================

SSL/TLS BEAST Vulnerability Check
 by YGN Ethical Hacker Group, http://yehg.net/

===============================================
};

if ($#ARGV != 0) {
 print qq{
Usage: beast.pl host [port]

port = 443 by default \{optional\}
};
 exit;
}

my $host = $ARGV[0];
my $port = 443;
if ($#ARGV == 1) {$port = $ARGV[1];}

print qq{
Target: $host:$port       
};

my $client = new IO::Socket::SSL(
          PeerAddr        => $host,
          PeerPort        => $port,
          Proto           => 'tcp',
          SSL_honor_cipher_order => 1,
          SSL_version => 'TLSv1'          
);
           
if (defined $client) {
        my $v_beast = 'PRONE to BEAST attack.';
        my $s_beast = 'YES';
        my $cipher = $client->get_cipher();
       
        if ($cipher =~ /RC4/){
            $v_beast = 'NOT vulnerable to BEAST attack.';
            $s_beast = 'NO';
        }
        
        print qq{
## The target is $v_beast ##

Protocol: TLS v1
Server Preferred Cipher: $cipher
Vulnerable: $s_beast

-----------------------------------------------
N.B. This check assumes no workaround
(i.e. EMPTY FRAGMENT) applied in target server.
};
        print $client "GET / HTTP/1.0\r\n\r\n";

        close $client;
} else {
         warn "\nERROR:\nConnecting to the taget\n\nDETAILS:\n",
         IO::Socket::SSL::errstr();
}
warn $! if not defined($client);

