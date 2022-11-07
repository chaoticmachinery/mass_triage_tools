#!/usr/bin/perl
#
# list_fields.pl   -- sample Perl script to list lsof full field output
#		      (i.e., -F output without -0)
#
# Written by: Keven Murphy
# Version: 0.2
#
# Rewritten from: Victor A. Abell <abe@purdue.edu> (https://github.com/lsof-org/lsof/blob/master/scripts/list_fields.pl)
# Some code is from Victor A. Abell.

# Process the ``lsof -F'' output a line at a time, gathering
# the variables for a process together before printing them;
# then gathering the variables for each file descriptor
# together before printing them.

#NOTE:
# --txtfile = Reads from a text file
# --jsonfile = Reads from the GPS.Nix.Sys.LSOF* Velociraptor JSON file
# --verbose = Adds a seperator line between PID line output


use Switch;
use Getopt::Long;
use JSON;
#use Data::Dumper;



sub printproc {
    $tmp = $uid; if ($login ne "") {$tmp = $login }
    printf "%s|%d|%d|%d|%s|", $cmd, $pid, $ppid, $pgrp, $tmp;
}

sub printfd {

    my ($boxname) = @_;

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
        printf " %s)", $state; 
    }
    if ($boxname ne "") {
       printf "|%s\n", $boxname;
     } else { 
        printf "\n"; 
    }
}

# Initialize variables.

$fhdr = 0;							# fd hdr. flag
$fdst = 0;							# fd state
$access = $devch = $devn = $fd = $inode = $lock = $name = "";	# | file descr.
$offset = $proto = $size = $state = $stream = $type = "";	# | variables
$pidst = 0;							# process state
$cmd = $login = $pgrp = $pid = $ppid = $uid = "";		# process var.
$cmdtmp = $logintmp = $pgrptmp = $pidtmp = $ppidtmp = $uidtmp = "";
my $initalfd = 0;
my $json = JSON->new->pretty;
my $boxname = "";



# Print headers
print "COMMAND|PID|PPID|PGRP|USER|FD|TYPE|DEVICE|SIZE/OFF|INODE|NAME|MACHINE\n";
#      $cmd   $pid$pgrp$ppid $uid 



#*********************************************************************************************
# MAIN  **************************************************************************************
#*********************************************************************************************

#=============================================================================================

GetOptions ("txtfile=s"   => \$txtfile,      # output directory
            "jsonfile=s"  => \$jsonfile,
            "verbose" => \$verbose
           ) ||  pod2usage(-verbose => 0);
		      
    pod2usage(-verbose => 1)  if ($opt_help);
    pod2usage(-verbose => 2)  if ($opt_man);
    pod2usage( { -message => q{Mandatory arguement '--mntdrive' is missing}
		 -exitval => 1,
		 -verbose => 1 }
	) unless ($jsonfile or $txtfile);

if ($txtfile) {
    open(DATA, "< $txtfile") or die "Could not open file: $txtfile, $!";
}
if ($jsonfile) {
    open(DATA, "< $jsonfile") or die "Could not open file: $jsonfile, $!";
}

while (defined($inline = <DATA>)) {
    
    my $line = "";
    $boxname = "";
    if ($txtfile) { 
       chop($inline); 
       $line = $inline; 
    }
    
    if ($jsonfile) { 
       my $jsondata = $json->decode($inline);
       $line = $jsondata->{Stdout};
       $boxname = $jsondata->{Fqdn};
       #print Dumper($jsondata);
       #my $test = $jsondata->{Fqdn};
       #print "Test: $boxname\n";
       #exit;       
    }

    switch($line) {
      #p = Entry begins with PID
      case /^p(.*)/ { 
                        if ($pid ne "") {
                           printproc;
                           printfd($boxname);
                           $access = $devch = $devn = $fd = $inode = $lock = $name = ""; 
                           $offset = $proto = $size = $state = $stream = $type = "";
                           $initalfd = 0;
                        }
                        $cmd = $login = $pgrp = $pid = $uid = ""; 
                        $fhdr = $pidst = 0; 
                        print "=======================\n" if $verbose;
                        $pid = substr($line, 1);  
                    }
      #f = file descriptor
      case /^f(.*)/ {   
                        if ($initalfd > 0) {
                           printproc;
                           printfd($boxname);
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

if ($txtfile) {
    close(DATA);
}
