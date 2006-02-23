#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Mail::DKIM::Signer;

=head1 NAME

Mail::DKIM::SigningFilter - signs email with a DKIM signature

=head1 SYNOPSIS

  use Mail::DKIM::SigningFilter;

  # create a signing filter object
  my $dkim = Mail::DKIM::SigningFilter->new_object(
                  Algorithm => "rsa-sha1",
                  Method => "nowsp",
                  Domain => "example.org",
                  Selector => "selector1",
                  KeyFile => "private.key");
             );

  # read an email from stdin, pass it into the signing filter.
  # the resulting message will be output on STDOUT.
  while (<STDIN>)
  {
      # remove local line terminators
      chomp;
      s/\015$//;

      # use SMTP line terminators
      $dkim->PRINT("$_\015\012");
  }
  $dkim->CLOSE;

=head1 DESCRIPTION

The "Signing Filter" is fed an email address and outputs to the specified
file handle the same message with a DKIM-Signature prepended.

The steps done are:
 1. Parse all headers
 2. Modify headers if desired (e.g. remove existing DKIM-Signature?)
 3. Determine signature parameters
 4. Feed (possibly modified) headers into selected canonicalization/algorithm
 5. Receive rest of message and feed it into canonicalization/algorithm
 6. Generate signature
 7. Write prepended DKIM-Signature header
 8. Write (possibly modified in step 2) headers
 9. Write body

=cut

package Mail::DKIM::SigningFilter;
use base "Mail::DKIM::Signer";
use Carp;

sub add_body
{
	my $self = shift;
	my ($line) = @_;
	$self->SUPER::add_body(@_);
	$self->{body_buffer} .= $line;
}

sub finish_body
{
	my $self = shift;
	$self->SUPER::finish_body;

	# output the generated DKIM-Signature
	print "DKIM-Signature: " . $self->result->as_string . "\015\012";
	print @{$self->{headers}};
	print "\015\012";
	print $self->{body_buffer};
}

1;
