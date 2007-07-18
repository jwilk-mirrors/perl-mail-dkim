#!/usr/bin/perl -I../lib
#
# Copyright (c) 2005-2007 Messiah College. This program is free software.
# You can redistribute it and/or modify it under the terms of the
# GNU Public License as found at http://www.fsf.org/copyleft/gpl.html.
#
# Written by Jason Long, jlong@messiah.edu.

use strict;
use warnings;

use Mail::DKIM::Verifier;
use Getopt::Long;

my $debug_canonicalization;
GetOptions(
		"debug-canonicalization=s" => \$debug_canonicalization,
		)
	or die "Error: invalid argument(s)\n";

my $debugfh;
if (defined $debug_canonicalization)
{
	open $debugfh, ">", $debug_canonicalization
		or die "Error: cannot write to $debug_canonicalization: $!\n";
}
my $dkim = new Mail::DKIM::Verifier(
		Debug_Canonicalization => $debugfh,
	);
while (<STDIN>)
{
	chomp;
	s/\015$//;
	$dkim->PRINT("$_\015\012");
}
$dkim->CLOSE;

if ($debugfh)
{
	close $debugfh;
	print STDERR "wrong canonicalized message to $debug_canonicalization\n";
}

print "originator address: " . $dkim->message_originator->address . "\n";
foreach my $signature ($dkim->signatures)
{
	print "signature identity: " . $signature->identity . "\n";
	print "verify result: " . $signature->result_detail . "\n";
}

my $author_policy = $dkim->fetch_author_policy;
if ($author_policy)
{
	print "author policy result: " . $author_policy->apply($dkim) . "\n";
}
else
{
	print "author policy result: not found\n";
}

my $dk_policy = $dkim->fetch_sender_policy;
if ($dk_policy)
{
	print "sender policy result: " . $dk_policy->apply($dkim) . "\n";
}
else
{
	print "sender policy result: not found\n";
}
