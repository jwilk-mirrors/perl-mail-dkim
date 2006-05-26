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

my $selector = "selector1";
my $algorithm = "rsa-sha1";
my $method = "simple";
my $debug_canonicalization;
my $help;
GetOptions(
		"algorithm=s" => \$algorithm,
		"method=s" => \$method,
		"selector=s" => \$selector,
		"debug-canonicalization=s" => \$debug_canonicalization,
		"help|?" => \$help,
		)
	or pod2usage(2);
pod2usage(1) if $help;
pod2usage("Error: unrecognized argument(s)")
	unless (@ARGV == 0);

my $dkim = new Mail::DKIM::Signer(
		Policy => "MySignerPolicy",
		Algorithm => $algorithm,
		Method => $method,
		Selector => $selector,
		KeyFile => "private.key",
		Debug_Canonicalization => $debug_canonicalization);

while (<STDIN>)
{
	chomp;
	$dkim->PRINT("$_\015\012");
}
$dkim->CLOSE;

print $dkim->signature->as_string . "\n";

package MySignerPolicy;
use Mail::DKIM::SignerPolicy;
use base "Mail::DKIM::SignerPolicy";

sub apply
{
	my ($self, $signer) = @_;

	$signer->domain($signer->message_sender->host);
	return 1;
}

__END__

=head1 NAME

dkimsign.pl - computes a DKIM signature for an email message

=head1 SYNOPSIS

  dkimsign.pl [options] < original_email.txt
    options:
      --method=METHOD
      --selector=SELECTOR
      --debug-canonicalization=FILE

  dkimsign.pl --help
    to see a full description of the various options

=head1 OPTIONS

=over

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
