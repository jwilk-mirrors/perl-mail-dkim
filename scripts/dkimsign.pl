#!/usr/bin/perl -I../lib
#
# Copyright (c) 2005-2006 Messiah College. This program is free software.
# You can redistribute it and/or modify it under the terms of the
# GNU Public License as found at http://www.fsf.org/copyleft/gpl.html.
#
# Written by Jason Long, jlong@messiah.edu.

use strict;
use warnings;

use Mail::DKIM::Signer;
use Getopt::Long;
use Pod::Usage;

my $type = "dkim";
my $selector = "selector1";
my $algorithm = "rsa-sha1";
my $method = "simple";
my $debug_canonicalization;
my $binary;
my $help;
GetOptions(
		"type=s" => \$type,
		"algorithm=s" => \$algorithm,
		"method=s" => \$method,
		"selector=s" => \$selector,
		"debug-canonicalization=s" => \$debug_canonicalization,
		"binary" => \$binary,
		"help|?" => \$help,
		)
	or pod2usage(2);
pod2usage(1) if $help;
pod2usage("Error: unrecognized argument(s)")
	unless (@ARGV == 0);

my $debugfh;
if (defined $debug_canonicalization)
{
	open $debugfh, ">", $debug_canonicalization
		or die "Error: cannot write $debug_canonicalization: $!\n";
}
if ($binary)
{
	binmode STDIN;
}

my $dkim = new Mail::DKIM::Signer(
		Policy => \&signer_policy,
		Algorithm => $algorithm,
		Method => $method,
		Selector => $selector,
		KeyFile => "private.key",
		Debug_Canonicalization => $debugfh,
		);

while (<STDIN>)
{
	unless ($binary)
	{
		chomp $_;
		s/\015?$/\015\012/s;
	}
	$dkim->PRINT($_);
}
$dkim->CLOSE;

if ($debugfh)
{
	close $debugfh;
	print STDERR "wrong canonicalized message to $debug_canonicalization\n";
}

print $dkim->signature->as_string . "\n";

sub signer_policy
{
	my $dkim = shift;

	use Mail::DKIM::DkSignature;

	$dkim->domain($dkim->message_sender->host);

	my $class = $type eq "domainkeys" ? "Mail::DKIM::DkSignature"
		: "Mail::DKIM::Signature";
	my $sig = $class->new(
			Algorithm => $dkim->algorithm,
			Method => $dkim->method,
			Headers => $dkim->headers,
			Domain => $dkim->domain,
			Selector => $dkim->selector,
		);
	$dkim->add_signature($sig);
	return;
}

__END__

=head1 NAME

dkimsign.pl - computes a DKIM signature for an email message

=head1 SYNOPSIS

  dkimsign.pl [options] < original_email.txt
    options:
      --type=TYPE
      --method=METHOD
      --selector=SELECTOR
      --debug-canonicalization=FILE

  dkimsign.pl --help
    to see a full description of the various options

=head1 OPTIONS

=over

=item B<--type>

Determines the desired signature. Use dkim for a DKIM-Signature, or
domainkeys for a DomainKey-Signature.

=item B<--method>

Determines the desired canonicalization method. Possible values are
simple, simple/simple, simple/relaxed, relaxed, relaxed/relaxed,
relaxed/simple.

=item B<--debug-canonicalization>

Outputs the canonicalized message to the specified file, in addition
to computing the DKIM signature. This is helpful for debugging
canonicalization methods.

=back

=cut
