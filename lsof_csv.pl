#!/usr/bin/perl
#
# list_fields.pl   -- sample Perl script to list lsof full field output
#		      (i.e., -F output without -0)
#
# Written by: Keven Murphy
# Version: 0.1
# Rewritten from: Victor A. Abell <abe@purdue.edu> (https://github.com/lsof-org/lsof/blob/master/scripts/list_fields.pl)
# Some code is from Victor A. Abell.


use Switch;

# Initialize variables.

$fhdr = 0;							# fd hdr. flag
$fdst = 0;							# fd state
$access = $devch = $devn = $fd = $inode = $lock = $name = "";	# | file descr.
$offset = $proto = $size = $state = $stream = $type = "";	# | variables
$pidst = 0;							# process state
$cmd = $login = $pgrp = $pid = $ppid = $uid = "";		# process var.
$cmdtmp = $logintmp = $pgrptmp = $pidtmp = $ppidtmp = $uidtmp = "";

# Process the ``lsof -F'' output a line at a time, gathering
# the variables for a process together before printing them;
# then gathering the variables for each file descriptor
# together before printing them.

# Print headers
print "COMMAND|PID|PPID|PGRP|USER|FD|TYPE|DEVICE|SIZE/OFF|INODE|NAME\n";
#      $cmd   $pid$pgrp$ppid $uid 

sub printproc {
    $tmp = $uid; if ($login ne "") {$tmp = $login }
    printf "%s|%d|%d|%d|%s|", $cmd, $pid, $ppid, $pgrp, $tmp;
}

sub printfd {
    printf "%s%s %s|%s", $fd, $access, $lock, $type;
    $tmp = $devn; 
    if ($devch ne "") { $tmp = $devch }
    printf "|%s", $tmp;
    $tmp = $size; 
    if ($offset ne "") { $tmp = $offset }
    printf "|%s", $tmp;
    $tmp = $inode; 
    if ($proto ne "") { $tmp = $proto }
    printf "|%s", $tmp;
    $tmp = $stream; 
    if ($name ne "") { $tmp = $name }
    printf "|%s", $tmp;
    if ($state ne "") { 
        printf " %s)\n", $state; 
     } else { 
        printf "\n"; 
    }
}

my $initalfd = 0;

while (defined($line = <STDIN>)) {
    chop($line);
    #print "$line\n";
    switch($line) {
      #p = Entry begins with PID
      case /^p(.*)/ { 
                        if ($pid ne "") {
                           &printproc;
                           &printfd;
                           $access = $devch = $devn = $fd = $inode = $lock = $name = ""; 
                           $offset = $proto = $size = $state = $stream = $type = "";
                           $initalfd = 0;
                        }
                        $cmd = $login = $pgrp = $pid = $uid = ""; 
                        $fhdr = $pidst = 0; 
                        print "=======================\n";
                        $pid = substr($line, 1);  
                    }
      #f = file descriptor
      case /^f(.*)/ {   
                        if ($initalfd > 0) {
                           &printproc;
                           &printfd;
                         } else {
                           $initalfd++;
                        }
                        $access = $devch = $devn = $fd = $inode = $lock = $name = ""; 
                        $offset = $proto = $size = $state = $stream = $type = "";
                        $fd = substr($line, 1);
                    }
                    
      case /^g(.*)/ { $pgrp = substr($line, 1); }
      case /^c(.*)/ { $cmd = substr($line, 1); }
      case /^u(.*)/ { $uid = substr($line, 1); }
      case /^L(.*)/ { $login = substr($line, 1); }
      case /^R(.*)/ { $ppid = substr($line, 1); }
      case /^a(.*)/ { $access = substr($line, 1); }
      case /^C(.*)/ {  }
      case /^d(.*)/ { $devch = substr($line, 1); }
      case /^D(.*)/ { $devn = substr($line, 1);  }
      case /^F(.*)/ {  }
      case /^G(.*)/ {  }
      case /^i(.*)/ { $inode = substr($line, 1); }
      case /^k(.*)/ {  }
      case /^l(.*)/ { $lock = substr($line, 1); }
      case /^N(.*)/ {  }
      case /^o(.*)/ { $offset = substr($line, 1); }
      case /^P(.*)/ { $proto = substr($line, 1); }
      case /^s(.*)/ { $size = substr($line, 1); }
      case /^S(.*)/ { $stream = substr($line, 1); }
      case /^t(.*)/ { $type = substr($line, 1); }
      case /^T(.*)/ { if ($state eq "") { $state = "(" . substr($line, 1); } else { $state = $state . " " . substr($line, 1); }}
      case /^n(.*)/ { $name = substr($line, 1); }
      else {print "ERROR: unrecognized: \"$_\"\n";}
    }
}
&printproc;
&printfd;
