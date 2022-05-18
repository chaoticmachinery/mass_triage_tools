#!/usr/bin/perl
# Written by: Keven Murphy
# Description: Will extract a single file from the tar file.
#
# Version: 0.1
#
# Example: find ./systems -name "etc.tar.gz" -exec ./tarextractfile.pl --tarfile {} --xfile "etc/file" \;;  find . -name "file" -exec md5sum {} \; | sort
#



use Archive::Tar;
use File::Basename;
use Getopt::Long;
use Cwd qw(cwd);
my $currentdir = cwd;


$result = GetOptions ("xfile=s"   => \$xfile,      # string
                    "tarfile=s"   => \$tarfile,      # string
                    "verbose"  => \$verbose);  # flag

my $tar = Archive::Tar->new;
$tar->read($tarfile);

print "Working on: $tarfile\n";
$ndir = $tarfile;
$ndir =~ s/\.\.//g;
$ndir =~ s/\//=/g;


if ($tar->contains_file( $xfile ) )   {
   unless(-e $ndir or mkdir $ndir) {
       die "Unable to create $ndir\n";
   }
   chdir($ndir);
   if ($tar->extract($xfile)) {
       print "\tWritten file to: $ndir\n";
     } else {
       print "\t Error: Could not extract file.\n";
   } 
   chdir($currentdir);
}


