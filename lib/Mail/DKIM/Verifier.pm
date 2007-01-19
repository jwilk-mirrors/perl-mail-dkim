#!/usr/bin/perl

# Copyright 2005-2006 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Mail::DKIM::Signature;
use Mail::DKIM::DkSignature;
use Mail::Address;

=head1 NAME

Mail::DKIM::Verifier - verifies a DKIM-signed message

=head1 SYNOPSIS

  use Mail::DKIM::Verifier;

  # create a verifier object
  my $dkim = Mail::DKIM::Verifier->new();

  # read an email from a file handle
  $dkim->load(*STDIN);

  # or read an email and pass it into the verifier, one line at a time
  while (<STDIN>)
  {
      # remove local line terminators
      chomp;
      s/\015$//;

      # use SMTP line terminators
      $dkim->PRINT("$_\015\012");
  }
  $dkim->CLOSE;

  # what is the result of the verify?
  my $result = $dkim->result;

=cut

#=head1 DESCRIPTION
#
#The verification process does the following, in order:
#
# 1. Reads all the headers.
# 2. Select a valid signature to verify.
# 3. Sets up an appropriate algorithm and canonicalization implementation.
# 4. Feeds the headers into the algorithm/canonicalization implementation.
# 5. Reads the body and feeds it into the body canonicalization.

=head1 CONSTRUCTOR

=head2 new() - construct an object-oriented verifier

  my $dkim = Mail::DKIM::Verifier->new();

  my $dkim = Mail::DKIM::Verifier->new(%options);

The only option supported at this time is:

=over

=item Debug_Canonicalization

if specified, the canonicalized message for the first signature
is written to the referenced string or file handle.

=back

=cut

package Mail::DKIM::Verifier;
use base "Mail::DKIM::Common";
use Carp;
use Error ":try";
our $VERSION = '0.21';

sub init
{
	my $self = shift;
	$self->SUPER::init;
	$self->{signatures} = [];
}

# @{$dkim->{signatures}}
#   list of syntactically valid signatures found in the header,
#   from the top of the header to the bottom
#
# $dkim->{signature_reject_reason}
#   simple string listing a reason, if any, for not using a signature.
#   This may be a helpful diagnostic if there is a signature in the header,
#   but was found not to be valid. It will be ambiguous if there are more
#   than one signatures that could not be used.
#
# $dkim->{signature}
#   contains the selected Mail::DKIM::Signature object found in the header
#
# $dkim->{public_key}
#   object of type Mail::DKIM::PublicKey, fetched using information
#   found in the signature
#
# @{$dkim->{headers}}
#   list of headers found in the header
#
# $dkim->{algorithm} - same as Signer
# $dkim->{canon} - same as Signer
#
# $dkim->{result}
#   result of the verification (see the result() method)
#

sub handle_header
{
	my $self = shift;
	my ($field_name, $contents, $line) = @_;

	$self->SUPER::handle_header($field_name, $contents);

	if (lc($field_name) eq "dkim-signature")
	{
		$self->add_signature($line);
	}

	if (lc($field_name) eq "domainkey-signature")
	{
		$self->add_signature_dk($line);
	}
}

sub add_signature
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($contents) = @_;

	eval
	{
		my $signature = Mail::DKIM::Signature->parse($contents);
		push @{$self->{signatures}}, $signature;
	};
	if ($@)
	{
		chomp (my $E = $@);
		$self->{signature_reject_reason} = $E;
	}
}

# parses a DomainKeys-type signature
sub add_signature_dk
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($contents) = @_;

	eval
	{
		my $signature = Mail::DKIM::DkSignature->parse($contents);
		push @{$self->{signatures}}, $signature;
	};
	if ($@)
	{
		chomp (my $E = $@);
		$self->{signature_reject_reason} = $E;
	}
}

sub check_signature
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($signature) = @_;

	unless ($signature->algorithm
		&& $signature->get_algorithm_class($signature->algorithm))
	{
		# unsupported algorithm
		$self->{signature_reject_reason} = "unsupported algorithm";
		if ($signature->algorithm)
		{
			$self->{signature_reject_reason} .= " " . $signature->algorithm;
		}
		return 0;
	}

	unless ($signature->check_canonicalization)
	{
		# unsupported canonicalization method
		$self->{signature_reject_reason} = "unsupported canonicalization";
		if ($signature->method)
		{
			$self->{signature_reject_reason} .= " " . $signature->method;
		}
		return 0;
	}

	unless ($signature->check_protocol)
	{
		# unsupported protocol
		$self->{signature_reject_reason} = "unsupported protocol";
		if ($signature->protocol)
		{
			$self->{signature_reject_reason} .= " " . $signature->protocol;
		}
		return 0;
	}

	unless ($signature->domain)
	{
		# no domain specified
		$self->{signature_reject_reason} = "missing d= parameter";
		return 0;
	}

	unless ($signature->selector)
	{
		# no selector specified
		$self->{signature_reject_reason} = "missing s= parameter";
		return 0;
	}

	# check domain against message From: and Sender: headers
#	my $responsible_address = $self->message_originator;
#	if (!$responsible_address)
#	{
#		# oops, no From: or Sender: header
#		die "No From: or Sender: header";
#	}
#
#	my $senderdomain = $responsible_address->host;
#	my $sigdomain = $signature->domain;
#	if (!$self->match_subdomain($senderdomain, $sigdomain))
#	{
#		$self->{signature_reject_reason} = "unmatched domain";
#		return 0;
#	}

	return 1;
}

sub check_public_key
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 2);
	my ($signature, $public_key) = @_;

	my $result = 0;
	try
	{
		# check public key's allowed hash algorithms
		$result = $public_key->check_hash_algorithm(
				$signature->hash_algorithm);

		# TODO - check public key's granularity
	}
	otherwise
	{
		my $E = shift;
		chomp $E;
		$self->{signature_reject_reason} = $E;
	};
	return $result;
}

sub match_subdomain
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 2);
	my ($subdomain, $superdomain) = @_;

	my $tmp = substr(".$subdomain", -1 - length($superdomain));
	return (".$superdomain" eq $tmp);
}

#
# called when the verifier has received the last of the message headers
# (body is still to come)
#
sub finish_header
{
	my $self = shift;

	# Signatures we found and were successfully parsed are stored in
	# $self->{signatures}. If none were found, our result is "none".

	if (@{$self->{signatures}} == 0
		&& !defined($self->{signature_reject_reason}))
	{
		$self->{result} = "none";
		return;
	}

	# For each parsed signature, check it for validity. If none are valid,
	# our result is "invalid" and our result detail will be the reason
	# why the last signature was invalid.

	my @valid = ();
	foreach my $signature (@{$self->{signatures}})
	{
		next unless ($self->check_signature($signature));

		# get public key
		try
		{
			$self->{public_key} = $signature->get_public_key;
		}
		otherwise
		{
			my $E = shift;
			chomp $E;
			$self->{signature_reject_reason} = $E;
		};

		if ($self->{public_key})
		{
			$self->check_public_key($signature, $self->{public_key})
				or next;
		}
		else
		{
			# public key not available
			next;
		}

		# this signature is ok
		push @valid, $signature;
	}

	unless (@valid)
	{
		# no valid signatures found
		$self->{result} = "invalid";
		$self->{details} = $self->{signature_reject_reason};
		return;
	}

	# now, for each valid signature, create an "algorithm" object which
	# will process the message

	$self->{algorithms} = [];
	foreach my $signature (@valid)
	{
		# create a canonicalization filter and algorithm
		my $algorithm_class = $signature->get_algorithm_class(
					$signature->algorithm);
		my $algorithm = $algorithm_class->new(
					Signature => $signature,
					Debug_Canonicalization => $self->{Debug_Canonicalization},
				);

		# output header as received so far into canonicalization
		foreach my $line (@{$self->{headers}})
		{
			$algorithm->add_header($line);
		}
		$algorithm->finish_header;

		# save the algorithm
		push @{$self->{algorithms}}, $algorithm;
	}
}

sub finish_body
{
	my $self = shift;

	foreach my $algorithm (@{$self->{algorithms}})
	{
		# finish canonicalizing
		$algorithm->finish_body;

		# verify signature
		my $result;
		my $details;
		local $@ = undef;
		try
		{
			$result = $algorithm->verify() ? "pass" : "fail";
			$details = $algorithm->{verification_details} || $@;
		}
		otherwise
		{
			my $E = shift;
			$result = "fail";
			$details = $E;
			chomp $details;
			if ($details =~ /(OpenSSL error: .*?) at /)
			{
				$details = $1;
			}
			elsif ($details =~ /^(panic:.*?) at /)
			{
				$details = "OpenSSL $1";
			}
		};

		# collate results ... ignore failed signatures if we already got
		# one to pass
		if (!$self->{result} || $result eq "pass")
		{
			$self->{signature} = $algorithm->signature;
			$self->{result} = $result;
			$self->{details} = $details;
		}
	}
}

=head1 METHODS

=head2 PRINT() - feed part of the message to the verifier

  $dkim->PRINT("a line of the message\015\012");

Feeds content of the message being verified into the verifier.
The API is designed this way so that the entire message does NOT need
to be read into memory at once.

=head2 CLOSE() - call this when finished feeding in the message

  $dkim->CLOSE;

This method finishes the canonicalization process, computes a hash,
and verifies the signature.

=head2 fetch_author_policy() - retrieves the "sender signing policy" from DNS

  my $policy = $dkim->fetch_author_policy;
  my $policy_result = $policy->apply($dkim);

See also the fetch() method of Mail::DKIM::Policy.

The "author" policy is the policy for the address found in the From header,
i.e. the "originator" address.

The result will be undef is there are no headers (i.e. From header) to
indicate what policy to check.

=cut

sub fetch_author_policy
{
	my $self = shift;
	use Mail::DKIM::Policy;
	if ($self->message_originator)
	{
		return fetch Mail::DKIM::Policy(
				Protocol => "dns",
				Domain => $self->message_originator->host);
	}
	return undef;
}

=head2 load() - load the entire message from a file handle

  $dkim->load($file_handle);

Reads a complete message from the designated file handle,
feeding it into the verifier. The message must use <CRLF> line
terminators (same as the SMTP protocol).

=head2 message_originator() - access the "From" header

  my $address = $dkim->message_originator;

Returns the "originator address" found in the message. This is typically
the (first) name and email address found in the From: header. The returned
object is of type Mail::Address. To get just the email address part, do:

  my $email = $dkim->message_originator->address;

=head2 message_sender() - access the "From" or "Sender" header

  my $address = $dkim->message_sender;

Returns the "sender" found in the message. This is typically the (first)
name and email address found in the Sender: header. If there is no Sender:
header, it is the first name and email address in the From: header.
The returned object is of type Mail::Address, so to get just the email
address part, do:

  my $email = $dkim->message_sender->address;

The "sender" is the mailbox of the agent responsible for the actual
transmission of the message. For example, if a secretary were to send a
message for another person, the "sender" would be the secretary and
the "originator" would be the actual author.


=head2 result() - access the result of the verification

  my $result = $dkim->result;

Gives the result of the verification. The following values are possible:

=over

=item pass

Returned if a valid DKIM-Signature header was found, and the signature
contains a correct value for the message.

=item fail

Returned if a valid DKIM-Signature header was found, but the signature
does not contain a correct value for the message.

=item invalid

Returned if no valid DKIM-Signature headers were found, but there is at
least one invalid DKIM-Signature header. For a reason why a
DKIM-Signature header found in the message was invalid,
see $dkim->{signature_reject_reason}.

=item none

Returned if no DKIM-Signature headers (valid or invalid) were found.

=back

In case of multiple signatures, the "best" result will be returned.
Best is defined as "pass", followed by "fail", "invalid", and "none".

=cut

=head2 result_detail() - access the result, plus details if available

  my $detail = $dkim->result_detail;

The detail is constructed by taking the result (i.e. one of "pass", "fail",
"invalid" or "none") and appending any details provided by the verification
process in parenthesis.

The following are possible results from the result_detail() method:

  pass
  fail (bad RSA signature)
  fail (headers have been altered)
  fail (body has been altered)
  invalid (unsupported canonicalization)
  invalid (unsupported protocol)
  invalid (missing d= parameter)
  invalid (missing s= parameter)
  invalid (unsupported v=0.1 tag)
  invalid (no public key available)
  invalid (public key has been revoked)
  none

=head2 signature() - access the message's DKIM signature

  my $sig = $dkim->signature;

Accesses the signature found and verified in this message. The returned
object is of type Mail::DKIM::Signature.

In case of multiple signatures, the signature with the "best" result will
be returned.
Best is defined as "pass", followed by "fail", "invalid", and "none".

=head1 AUTHOR

Jason Long, E<lt>jlong@messiah.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Messiah College

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
