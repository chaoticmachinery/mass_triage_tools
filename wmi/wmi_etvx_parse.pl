#!/usr/bin/perl

=encoding utf8

=head1 NAME

 wmi_etvx_parse.pl - converts WMI 5861 & 5858 event ids to csv in
 C:\WINDOWS\system32\winevt\logs\Microsoft-Windows-WMI-Activity%4Operational.evtx .

=head1 SYNOPSIS

 evtxdump.pl System.evtx > System.xml

=head1 DESCRIPTION

I used Andreas Schuster's evtxdump.pl as the basis for the script. I
converted the script to csv output. 


=head1 COPYRIGHT

Copyright (c) 2007-2011 by Andreas Schuster

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.

=cut

# Version 1.0

use strict;
# use warnings;
# use diagnostics;

use Parse::Evtx;
use Parse::Evtx::Chunk;
use Carp::Assert;
use IO::File 1.14;
use XML::Simple;
use Data::Dumper;

sub header2 {
	return "EventID|ComputerName|Namespace|ESS|Consumer|PossibleCause/Operation\n";
};



# main program

my $fh = IO::File->new(shift, "r");
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
	print "'".$xmldata->{System}{EventID}."'|";
	print "'".$xmldata->{System}{Computer}."'|";
	if ($xmldata->{System}{EventID} eq "5861") {
	   print "'".$xmldata->{UserData}{Operation_ESStoConsumerBinding}{Namespace}."'|";
	   print "'".$xmldata->{UserData}{Operation_ESStoConsumerBinding}{ESS}."'|";
	   print "'".$xmldata->{UserData}{Operation_ESStoConsumerBinding}{CONSUMER}."'|";
	   print "'".$xmldata->{UserData}{Operation_ESStoConsumerBinding}{PossibleCause}."'";
	}
	if ($xmldata->{System}{EventID} eq "5858") {
       print "|";
	   print "|";
	   print "|";
	   print "'".$xmldata->{UserData}{Operation_ClientFailure}{Operation}."'";
	}
	print "\n";
	$event = $file->get_next_event();
};
$fh->close();
