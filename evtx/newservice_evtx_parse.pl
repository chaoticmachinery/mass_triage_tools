#!/usr/bin/env perl

#===================================================================================
# Written by: Andreas Schuster
# Modified by: Keven Murphy
#
# Used for mass triage of systems, the script will parse the EventIDs and present
# the output in a CSV '|' delimited format. This allows for easy frequency analysis.
#
# Parses System EVTX logs for the follow Event IDs:
#   7045
#
# It is suggested that GNU parallel is used when running the script. It will greately
# reduce the amount of time it takes to parse hunderds/thousands of EVTX.
#
# Parallel Example:
# find . -name "*evtx_" | parallel --keep-order  --progress --jobs {# of cores} newservice_etvx_parse.pl -f {}  | tee {output}
# find . -name "*evtx_" | parallel --keep-order  --progress --jobs 10 newservice_etvx_parse.pl -f {}  | tee output
#
# Processing output
# The output must be manuipulated for frequency analysis. The command is:
# cut -d\| -f 5-6 {output}  | sort | uniq -c > {filename}.csv
# cut -d\| -f 5-6 output | sort | uniq -c > file.csv
#
#
# Requirements:
# https://computer.forensikblog.de/en/2011/11/evtx-parser-1-1-1.html
#
# Author Notes:
# 1) Script
#
# Mod Log:
#===================================================================================

#use strict;
# use warnings;
# use diagnostics;
use Getopt::Long;
use Parse::Evtx;
use Parse::Evtx::Chunk;
use Carp::Assert;
use IO::File 1.14;
use XML::Simple;
#use Data::Dumper;
#use  Data::Dumper::Perltidy;
use Pod::Usage;

sub header2 {
	return "'EventID'|'ComputerName'|'TimeCreated'|'UserID'|'ServiceName'|'ImagePath'\n";
};

sub squotes {
    my ($text) = @_;
    $text =~ s/\'/\"/g;
    return $text;
};

# main program
my $inputfile = "";
my $opt_help = "";
my $opt_man = "";

GetOptions ("file=s"   => \$inputfile      # output directory
           ) ||  pod2usage(-verbose => 0);

    pod2usage(-verbose => 1)  if ($opt_help);
    pod2usage(-verbose => 2)  if ($opt_man);
    pod2usage( { -message => q{Mandatory arguement '--file' is missing}
                 -exitval => 1,
                 -verbose => 1 }
        ) unless ($inputfile);


#my $fh = IO::File->new(shift, "r");
my $fh = IO::File->new($inputfile, "r");
if (!defined $fh) {
	print "Unable to open file: $!\n";
	exit 1;	
}

assert(defined $fh);
my $file;
$file = Parse::Evtx->new('FH' => $fh);
if (!defined $file) {
    # if it's not a complete file, is it a chunk then?
    $file = Parse::Evtx::Chunk->new('FH' => $fh );
};
assert(defined $file);
binmode(STDOUT, ":utf8");
select((select(STDOUT), $|=1)[0]);

print header2();
my $event = $file->get_first_event();
while (defined $event) {
    my $data = $event->get_xml();
	my $xmldata = XMLin($data);

	if ($xmldata->{System}{EventID}{content} eq "7045") {
		print "'".$xmldata->{System}{EventID}{content}."'|";   
	    print "'".$xmldata->{System}{Computer}."'|";
	    print "'".$xmldata->{System}{TimeCreated}{SystemTime}."'|";
	    print "'".$xmldata->{System}{Security}{UserID}."'|";
	    print "'".$xmldata->{EventData}{Data}[0]{content}."'|";   #Service Name
	    print "'".$xmldata->{EventData}{Data}[1]{content}."'|";   #ImagePath
	    print "|'".$inputfile."'";
	    print "\n";	    
	}

    #print  Dumper ($xmldata);
    #print "\n";
	$event = $file->get_next_event();
};
$fh->close();

__END__

=head1 newservice_evtx_parse.pl

Image device

=head1 SYNOPSIS

newservice_evtx_parse.pl [options] [file ...]

Options:

--file    EVTX log (MANDATORY)

--help       Brief help message

--man        Full documentation

=head1 OPTIONS

=over 8

=item B<-help>

Print a brief help message and exits.

=item B<-man>

Prints the manual page and exits.

=back

=head1 DESCRIPTION

B<newservice_evtx_parse.pl> parse the EVTX System log for 7045.
=cut
