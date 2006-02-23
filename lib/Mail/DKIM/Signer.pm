#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Mail::DKIM::Canonicalization::nowsp;
use Mail::DKIM::Algorithm::rsa_sha1;
use Mail::DKIM::Signature;
use Mail::Address;

=head1 NAME

Mail::DKIM::Signer - generates a DKIM signature for a message

=head1 SYNOPSIS

  use Mail::DKIM::Signer;

  # create a signer object
  my $dkim = Mail::DKIM::Signer->new_object(
                  Algorithm => "rsa-sha1",
                  Method => "nowsp",
                  Domain => "example.org",
                  Selector => "selector1",
                  KeyFile => "private.key");
             );

  # read an email from stdin, pass it into the signer
  while (<STDIN>)
  {
      # remove local line terminators
      chomp;
      s/\015$//;

      # use SMTP line terminators
      $dkim->PRINT("$_\015\012");
  }
  $dkim->CLOSE;

  # what is the signature result?
  my $signature = $dkim->signature;

=head1 CONSTRUCTOR

=head2 new_object() - construct an object-oriented signer

  my $dkim = Mail::DKIM::Signer->new_object(
                  Algorithm => "rsa-sha1",
                  Method => "nowsp",
                  Domain => "example.org",
                  Selector => "selector1",
                  KeyFile => "private.key"
             );

  my $dkim = Mail::DKIM::Signer->new_object(
                  Policy => $signer_policy,
                  KeyFile => "private.key"
             );

You must always specify the name of a private key file. In addition,
you must specify a policy object, or specify the algorithm, method,
domain, and selector to use. Use of the policy object lets you defer
the determination of algorithm, method, domain and selector until
the message being signed has been partially read.

See Mail::DKIM::SignerPolicy for more information about policy objects.

=cut

package Mail::DKIM::Signer;
use base "Mail::DKIM::Common";
use Carp;

# PROPERTIES
#
# public:
#
# $dkim->{Algorithm}
#   identifies what algorithm to use when signing the message
#   default is "rsa-sha1"
#
# $dkim->{Domain}
#   identifies what domain the message is signed for
#
# $dkim->{KeyFile}
#   name of the file containing the private key used to sign
#
# $dkim->{Method}
#   identifies what canonicalization method to use when signing
#   the message. default is "nowsp"
#
# $dkim->{Policy}
#   a signing policy (of type Mail::DKIM::SigningPolicy)
#
# $dkim->{Selector}
#   identifies name of the selector identifying the key
#
# private:
#
# $dkim->{algorithm}
#   the algorithm object
#
# $dkim->{private}
#   the loaded private key
#
# $dkim->{result}
#   result of the signing policy: "signed" or "skipped"
#
# $dkim->{signature}
#   the created signature (of type Mail::DKIM::Signature)


sub init
{
	my $self = shift;
	$self->SUPER::init;

	if (defined $self->{KeyFile})
	{
		croak "not a file: " . $self->{KeyFile}
			unless (-f $self->{KeyFile});

		$self->{private} = Mail::DKIM::PrivateKey->load(
				File => $self->{KeyFile});
	}
	croak "No private key specified"
		unless ($self->{private});
	
	unless ($self->{"Algorithm"})
	{
		# use default algorithm
		$self->{"Algorithm"} = "rsa-sha1";
	}
	unless ($self->{"Method"})
	{
		# use default canonicalization method
		$self->{"Method"} = "nowsp";
	}
	unless ($self->{"Domain"})
	{
		# use default domain
		$self->{"Domain"} = "example.org";
	}
	unless ($self->{"Selector"})
	{
		# use default selector
		$self->{"Selector"} = "unknown";
	}
}

sub finish_header
{
	my $self = shift;

	if ($self->{"Policy"})
	{
		my $should_sign = $self->{"Policy"}->apply($self);
		unless ($should_sign)
		{
			$self->{"result"} = "skipped";
			return;
		}
	}

	# check properties
	unless ($self->{"Algorithm"})
	{
		die "invalid algorithm property";
	}
	unless ($self->{"Method"})
	{
		die "invalid method property";
	}
	unless ($self->{"Domain"})
	{
		die "invalid header property";
	}
	unless ($self->{"Selector"})
	{
		die "invalid selector property";
	}

	# create a signature
	my @headers = @{$self->{header_field_names}};
	$self->{signature} = new Mail::DKIM::Signature(
			Algorithm => $self->{"Algorithm"},
			Method => $self->{"Method"},
			Headers => join(":", @headers),
			Domain => $self->{"Domain"},
			Selector => $self->{"Selector"},
		);

	# create a canonicalization filter and algorithm
	my $algorithm_class = $self->get_algorithm_class($self->{"Algorithm"});
	$self->{algorithm} = $algorithm_class->new(
				Signature => $self->{signature},
				Debug_Canonicalization => $self->{Debug_Canonicalization},
			);

	# output header as received so far into canonicalization
	foreach my $header (@{$self->{headers}})
	{
		$self->{algorithm}->add_header($header);
	}
	$self->{algorithm}->finish_header;
}

sub finish_body
{
	my $self = shift;

	if ($self->{algorithm})
	{
		# finished canonicalizing
		$self->{algorithm}->finish_body;

		# compute signature value
		my $signb64 = $self->{algorithm}->sign($self->{private});
		$self->{signature}->signature($signb64);

		$self->{result} = "signed";
	}
}

=head1 METHODS

=head2 PRINT() - feed part of the message to the signer

  $dkim->PRINT("a line of the message\015\012");

Feeds content of the message being signed into the signer.
The API is designed this way so that the entire message does NOT need
to be read into memory at once.

=head2 CLOSE() - call this when finished feeding in the message

  $dkim->CLOSE;

This method finishes the canonicalization process, computes a hash,
and generates a signature.

=head2 algorithm() - get or set the selected algorithm

  $alg = $dkim->algorithm;

  $dkim->algorithm("rsa-sha1");

=cut

sub algorithm
{
	my $self = shift;
	if (@_ == 1)
	{
		$self->{Algorithm} = shift;
	}
	return $self->{Algorithm};
}

=head2 domain() - get or set the selected domain

  $alg = $dkim->domain;

  $dkim->domain("example.org");

=cut

sub domain
{
	my $self = shift;
	if (@_ == 1)
	{
		$self->{Domain} = shift;
	}
	return $self->{Domain};
}

=head2 load() - load the entire message from a file handle

  $dkim->load($file_handle);

Reads a complete message from the designated file handle,
feeding it into the signer.  The message must use <CRLF> line
terminators (same as the SMTP protocol).

=cut

=head2 method() - get or set the selected canonicalization method

  $alg = $dkim->method;

  $dkim->method("relaxed");

=cut

sub method
{
	my $self = shift;
	if (@_ == 1)
	{
		$self->{Method} = shift;
	}
	return $self->{Method};
}

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


=cut

=head2 selector() - get or set the current key selector

  $alg = $dkim->selector;

  $dkim->selector("alpha");

=cut

sub selector
{
	my $self = shift;
	if (@_ == 1)
	{
		$self->{Selector} = shift;
	}
	return $self->{Selector};
}

=head2 signature() - access the generated signature object

  my $signature = $dkim->signature;

Returns the generated signature. The signature is an object of type
Mail::DKIM::Signature.

=cut

=head1 SEE ALSO

Mail::DKIM::SignerPolicy

Mail::DKIM::SigningFilter

=cut

1;
