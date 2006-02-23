#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Mail::DKIM::PrivateKey;
use Mail::DKIM::Canonicalization::nowsp;
use Mail::DKIM::Canonicalization::relaxed;
use Mail::DKIM::Canonicalization::simple;

package Mail::DKIM::Algorithm::rsa_sha1;
use Carp;
use MIME::Base64;
use Digest::SHA1;

sub new
{
	my $class = shift;
	my %args = @_;
	my $self = bless \%args, $class;
	$self->init;
	return $self;
}

sub init
{
	my $self = shift;

	$self->{debug_buf} = "";
	$self->{sha1} = new Digest::SHA1;

	if ($self->{Signature})
	{
		my ($header_method, $body_method)
			= $self->{Signature}->canonicalization;
		#my ($header_method, $body_method) = split(/\//, $method, 2);
		#unless (defined $body_method)
		#{
		#	$body_method = ($header_method eq "relaxed" ? "simple" :
		#				$header_method);
		#}

		my $header_class = $self->get_canonicalization_class($header_method);
		my $body_class = $self->get_canonicalization_class($body_method);
		$self->{canon} = $header_class->new(
				output => $self,
				Signature => $self->{Signature});
		if ($body_class ne $header_class)
		{
			$self->{body_canon} = $body_class->new(
					output => $self,
					Signature => $self->{Signature});
		}
		else
		{
			$self->{body_canon} = $self->{canon};
		}
	}
}

# private method
sub get_canonicalization_class
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($method) = @_;

	my $class = $method eq "nowsp" ? "Mail::DKIM::Canonicalization::nowsp" :
			$method eq "relaxed" ? "Mail::DKIM::Canonicalization::relaxed" :
			$method eq "simple" ? "Mail::DKIM::Canonicalization::simple" :
		die "unknown method $method\n";
	return $class;
}

sub TIEHANDLE
{
	my $class = shift;
	return $class->new(@_);
}

sub PRINT
{
	my $self = shift;
	$self->{sha1}->add(join("", @_));

	if (my $debug = $self->{Debug_Canonicalization})
	{
		if (ref($debug) && ref($debug) eq "SCALAR")
		{
			$$debug .= join("", @_);
		}
		else
		{
			$self->{debug_buf} .= join("", @_);
		}
	}
}

sub CLOSE
{
}


=head1 NAME

Mail::DKIM::Algorithm::rsa_sha1 - implements the rsa-sha1 signing algorithm for DKIM

=head1 SYNOPSIS

  my $algorithm = new Mail::DKIM::Algorithm::rsa_sha1(
                      Signature => $dkim_signature
                  );

  # add headers
  $algorithm->add_header("Subject: this is the subject\015\012");
  $algorithm->finish_header;

  # add body
  $algorithm->add_body("This is the body.\015\012");
  $algorithm->add_body("Another line of the body.\015\012");
  $algorithm->finish_body;

  # now sign or verify...
  # TODO...

=head1 CONSTRUCTOR

=head2 new() - create an object for the DKIM signing algorithm "rsa-sha1"

  my $algorithm = new Mail::DKIM::Algorithm::rsa_sha1(
                      Signature => $dkim_signature
                  );

=head1 METHODS

=head2 add_body() - feeds part of the body into the algorithm/canonicalization

  $algorithm->add_body("This is the body.\015\012");
  $algorithm->add_body("Another line of the body.\015\012");

=cut

sub add_body
{
	my $self = shift;
	$self->{body_canon}->add_body(@_);
}

=head2 add_header() - feeds a header field into the algorithm/canonicalization

  $algorithm->add_header("Subject: this is the subject\015\012");

The header must start with the header field name and continue through any
folded lines (including the embedded <CRLF> sequences). It terminates with
the <CRLF> at the end of the header field.

=cut

sub add_header
{
	my $self = shift;
	$self->{canon}->add_header(@_);
}

=head2 finish_body() - signals the end of the message body

  $algorithm->finish_body

Call this method when all lines from the body have been submitted.
After calling this method, use sign() or verify() to get the results
from the algorithm.

=cut

sub finish_body
{
	my $self = shift;
	$self->{body_canon}->finish_body;
	$self->{canon}->finish_message;

	if (my $debug = $self->{Debug_Canonicalization})
	{
		unless (ref $debug)
		{
			my $filename = $debug;
			open my $fh, ">", $filename
				or die "Error: cannot write to $filename: $!\n";
			print $fh $self->{debug_buf};
			close $fh;
			print STDERR "Wrote canonicalized message to $filename\n";
			print STDERR "Body count is " . $self->{canon}->body_count . "\n";
			print STDERR "Truncated " . $self->{canon}->{body_truncated} . "\n";
		}
	}
}

=head2 finish_header() - signals the end of the header field block

  $algorithm->finish_header;

Call this method when all the headers have been submitted.

=cut

sub finish_header
{
	my $self = shift;
	$self->{canon}->finish_header;
}

=head2 sign() - generates a signature using a private key

  $base64 = $algorithm->sign($private_key);

=cut

sub sign
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($private_key) = @_;

	my $digest = $self->{sha1}->digest;
	my $signature = $private_key->sign_sha1_digest($digest);

	return encode_base64($signature, "");
}

=head2 verify() - verifies a signature using the public key

  $result = $algorithm->verify($base64, $public_key);

The result is a true/false value: true indicates the signature data
($base64) is valid, false indicates it is invalid.

=cut

sub verify
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 2);
	my ($base64, $public_key) = @_;

	my $digest = $self->{sha1}->digest;
	my $sig = decode_base64($base64);
	return $public_key->verify_sha1_digest($digest, $sig);
}

1;
