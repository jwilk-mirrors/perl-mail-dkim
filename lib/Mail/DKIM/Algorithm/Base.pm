#!/usr/bin/perl

# Copyright 2005-2006 Messiah College. All rights reserved.
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

package Mail::DKIM::Algorithm::Base;
use Carp;
use MIME::Base64;

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

	if ($self->{Signature})
	{
		$self->{mode} = $self->{Signature}->signature ? "verify" : "sign";
		$self->{draft_version} ||=
			($self->{mode} eq "sign" ? "01" :
			 $self->{Signature}->body_hash ? "01" : "00");

		# allows subclasses to set the header_digest and body_digest
		# properties
		$self->init_digests;

		my ($header_method, $body_method)
			= $self->{Signature}->canonicalization;

		my ($header_buffer, $body_buffer);
		if ($self->{Debug_Canonicalization})
		{
			$self->{debug_buf} = "";
			$header_buffer = \$self->{debug_buf};
			$self->{debug_body_buf} = "";
			$body_buffer = \$self->{debug_body_buf};
		}

		my $header_class = $self->get_canonicalization_class($header_method);
		my $body_class = $self->get_canonicalization_class($body_method);
		$self->{canon} = $header_class->new(
				buffer => $header_buffer,
				output_digest => $self->{header_digest},
				draft_version => $self->{draft_version},
				Signature => $self->{Signature});
		$self->{body_canon} = $body_class->new(
				buffer => $body_buffer,
				output_digest => $self->{body_digest},
				draft_version => $self->{draft_version},
				Signature => $self->{Signature});
	}
	else
	{
		die "no signature";
	}
}

# override this method, please...
# this method should set the "header_digest" and "body_digest" properties
sub init_digests
{
	die "not implemented";
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

#sub TIEHANDLE
#{
#	my $class = shift;
#	return $class->new(@_);
#}
#
## override this method, please...
#sub PRINT
#{
#	my $self = shift;
#
#	if (my $debug = $self->{Debug_Canonicalization})
#	{
#		if (ref($debug) && ref($debug) eq "SCALAR")
#		{
#			$$debug .= join("", @_);
#		}
#		else
#		{
#			$self->{debug_buf} .= join("", @_);
#		}
#	}
#}
#
#sub CLOSE
#{
#}


=head1 NAME

Mail::DKIM::Algorithm::Base - base class for DKIM "algorithms"

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

You should not create an object of this class directly. Instead, use one
of the DKIM algorithm implementation classes, such as rsa_sha1:

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
	$self->finish_message;
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

# checks the bh= tag of the signature to see if it has the same body
# hash as computed by canonicalizing/digesting the actual message body.
# If it doesn't match, a false value is returned, and the
# verification_details property is set to "body has been altered"
sub check_body_hash
{
	my $self = shift;

	if ($self->{body_hash})
	{
		my $body_hash = $self->{body_hash};
		my $expected = decode_base64($self->{Signature}->body_hash);
		if ($body_hash ne $expected)
		{
			$self->{verification_details} = "body has been altered";
	#		print STDERR "I calculated  "
	#			. encode_base64($body_hash, "") . "\n";
	#		print STDERR "signature has "
	#			. encode_base64($expected, "") . "\n";
			return;
		}
	}
	return 1;
}

sub finish_message
{
	my $self = shift;
#	$self->{canon}->finish_message;

	if ($self->{draft_version} eq "01")
	{
		$self->{body_hash} = $self->{body_digest}->digest;
		if ($self->{mode} eq "sign")
		{
			$self->{Signature}->body_hash(
					encode_base64($self->{body_hash}, ""));
		}
	#	else
	#	{
	#		print STDERR "verify: body hash is "
	#			. encode_base64($self->{body_hash}, "") . "\n";
	#	}
	}

	my $sig_line = $self->{Signature}->as_string_without_data;
	my $canonicalized = $self->{canon}->canonicalize_header($sig_line);

	if ($self->{draft_version} eq "00")
	{
		$canonicalized = "\015\012" . $canonicalized;
	}

	$self->{header_digest}->add($canonicalized);

	if (my $debug = $self->{Debug_Canonicalization})
	{
		$self->{debug_buf} .= $canonicalized;
		unless (ref $debug)
		{
			my $filename = $debug;
			open my $fh, ">", $filename
				or die "Error: cannot write to $filename: $!\n";
			print $fh "-----BEGIN CANONICALIZED HEADERS-----\015\012";
			print $fh $self->{debug_buf};
			print $fh "-----END CANONICALIZED HEADERS-----\015\012";
			print $fh "-----BEGIN CANONICALIZED BODY-----\015\012";
			print $fh $self->{debug_body_buf};
			print $fh "-----END CANONICALIZED BODY-----\015\012";
			close $fh;
			print STDERR "Debug: wrote canonicalized headers and body to $filename\n";
		#	print STDERR "Body count is " . $self->{body_canon}->body_count . "\n";
		#	print STDERR "Truncated " . $self->{body_canon}->{body_truncated} . "\n";
		}
	}
}

=head2 sign() - generates a signature using a private key

  $base64 = $algorithm->sign($private_key);

=cut

# override this method, please...
sub sign
{
	die "Not implemented";
}

=head2 verify() - verifies a signature using the public key

  $result = $algorithm->verify($base64, $public_key);

The result is a true/false value: true indicates the signature data
($base64) is valid, false indicates it is invalid.

=cut

# override this method, please...
sub verify
{
	die "Not implemented";
}

1;
