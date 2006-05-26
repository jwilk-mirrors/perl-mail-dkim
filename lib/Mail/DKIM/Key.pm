#!/usr/bin/perl
#
# Copyright 2006 Jason Long. All rights reserved.
#
# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Mail::DKIM::Key;

use strict;

sub cork {
	my $self = shift;

	(@_) and
		$self->{'CORK'} = shift;

	$self->{'CORK'} or
		$self->convert;

	$self->{'CORK'};
}

sub data {
	my $self = shift;

	(@_) and 
		$self->{'DATA'} = shift;

	$self->{'DATA'};
}

sub errorstr {
	my $self = shift;

	(@_) and 
		$self->{'ESTR'} = shift;

	$self->{'ESTR'};
}

sub size {
	my $self = shift;

	return $self->cork->size * 8;
}

sub type {
	my $self = shift;

	(@_) and 
		$self->{'TYPE'} = shift;

	$self->{'TYPE'};
}

use Crypt::RSA::DataFormat ("h2osp");

sub calculate_EM
{ 
	my ($digest_algorithm, $digest, $emLen) = @_;

	# this function performs DER encoding of the algorithm ID for the
	# hash function and the hash value itself
	# It has this syntax:
	#      DigestInfo ::= SEQUENCE {
	#          digestAlgorithm AlgorithmIdentifier,
	#          digest OCTET STRING
	#      }

	# RFC 3447, page 42, provides the following octet values:
	my %digest_encoding = (
		"SHA-1" => h2osp(
			"0x 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14"),
		"SHA-256" => h2osp(
			"0x 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20"),
		);

	defined $digest_encoding{$digest_algorithm}
		or die "Unsupported digest algorithm '$digest_algorithm'";

	my $T = $digest_encoding{$digest_algorithm} . $digest;
	my $tLen = length($T);

	if ($emLen < $tLen + 11)
	{
		die "Intended encoded message length too short.";
	}

	my $PS = chr(0xff) x ($emLen - $tLen - 3);
	my $EM = chr(0) . chr(1) . $PS . chr(0) . $T; 
	return $EM;
}

1;
