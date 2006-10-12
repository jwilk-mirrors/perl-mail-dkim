#!/usr/bin/perl

# Copyright 2005-2006 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Mail::DKIM::PrivateKey;
use Mail::DKIM::Canonicalization::dk_nofws;

package Mail::DKIM::Algorithm::dk_rsa_sha1;
use base "Mail::DKIM::Algorithm::Base";
use Carp;
use MIME::Base64;
use Digest::SHA1;

sub get_canonicalization_class
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($method) = @_;

	my $class = $method eq "nofws" ? "Mail::DKIM::Canonicalization::dk_nofws" :
			$method eq "simple" ? "Mail::DKIM::Canonicalization::simple" :
		die "unknown method $method\n";
	return $class;
}

sub init
{
	my $self = shift;

	$self->{debug_buf} = "";

	die "no signature" unless $self->{Signature};

	$self->{mode} = $self->{Signature}->signature ? "verify" : "sign";

	# allows subclasses to set the header_digest and body_digest
	# properties
	$self->init_digests;

	my $method = $self->{Signature}->canonicalization;

	my $buffer;
	if ($self->{Debug_Canonicalization})
	{
		$self->{debug_buf} = "";
		$buffer = \$self->{debug_buf};
	}

	my $canon_class = $self->get_canonicalization_class($method);
	$self->{canon} = $canon_class->new(
			buffer => $buffer,
			output_digest => $self->{header_digest},
			Signature => $self->{Signature});
}

sub init_digests
{
	my $self = shift;

	# initialize a SHA-1 Digest
	$self->{header_digest} = new Digest::SHA1;
	$self->{body_digest} = $self->{header_digest};
}

sub sign
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($private_key) = @_;

	my $digest = $self->{header_digest}->digest;
	my $signature = $private_key->sign_sha1_digest($digest);

	return encode_base64($signature, "");
}

sub verify
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 2);
	my ($base64, $public_key) = @_;

	my $digest = $self->{header_digest}->digest;
	my $sig = decode_base64($base64);
	return $public_key->verify_sha1_digest($digest, $sig);
}

sub finish_message
{
	my $self = shift;

	if (my $debug = $self->{Debug_Canonicalization})
	{
		unless (ref $debug)
		{
			my $filename = $debug;
			open my $fh, ">", $filename
				or die "Error: cannot write to $filename: $!\n";
			print $fh $self->{debug_buf};
			close $fh;
			print STDERR "Debug: wrote canonicalized message to $filename\n";
		}
	}
}

1;
