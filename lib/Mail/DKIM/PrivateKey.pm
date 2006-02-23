#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>
#
# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::PrivateKey;
use base "Mail::DKIM::Key";

sub load {
	my $type = shift;
	my %prms = @_;
	my $self = {};


	$self->{'TYPE'} = ($prms{'Type'} or "rsa");

	if ($prms{'Data'}) {
		$self->{'DATA'} = $prms{'Data'};
	} elsif ($prms{'File'}) {	
		my @data;
		open FILE, "<$prms{'File'}" or
			return;
		while (<FILE>) {
			chomp;
			/^---/ and
				next;
			push @data, $_;
		}
		$self->{'DATA'} = join '', @data;
	} else {
		return;
	}

	bless $self, $type;
}

sub convert {
	use Crypt::OpenSSL::RSA;

	my $self = shift;


	$self->data or
		return;

	# have to PKCS1ify the privkey because openssl is too finicky...
	my $pkcs = "-----BEGIN RSA PRIVATE KEY-----\n";

	for (my $i = 0; $i < length $self->data; $i += 64) {
		$pkcs .= substr $self->data, $i, 64;
		$pkcs .= "\n";
	}	

	$pkcs .= "-----END RSA PRIVATE KEY-----\n";

	
	my $cork;

	eval {
		$cork = new_private_key Crypt::OpenSSL::RSA($pkcs);
	};

	$@ and
		$self->errorstr($@),
		return;

	$cork or
		return;

	# segfaults on my machine
#	$cork->check_key or
#		return;

	$self->cork($cork);

	return 1;
}

sub sign
{
	my $self = shift;
	my $mail = shift;


	return $self->cork->sign($mail);
}

use Crypt::RSA::Primitives;
use Crypt::RSA::DataFormat ("os2ip", "octet_len", "i2osp", "h2osp");
use Crypt::RSA::Key::Private;

sub sign_sha1_digest
{
	my $self = shift;
	my ($digest) = @_;

	my ($kn, $ke, $kd) = $self->cork->get_key_parameters;
	my $private = bless { }, "Crypt::RSA::Key::Private";
	$private->n($kn->to_decimal);
	$private->d($kd->to_decimal);
	unless ($private->check)
	{
		die "Key check failed: " . $private->errstr . "\n";
	}

	my $rsa = new Crypt::RSA::Primitives;
	my $k = octet_len($private->n);
	my $m = $rsa->core_sign(
			Message => os2ip(encode_sha1_digest($digest, $k - 1)),
			Key => $private);
	my $m1 = i2osp($m, $k)
		or die "i2osp failed";
	return $m1;
}

sub encode_sha1_digest
{ 
    my ($digest, $emlen) = @_;

    my $alg = h2osp("0x 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14");
    my $T = $alg . $digest;
    die("Intended encoded message length too short.")
		if ($emlen < length($T) + 10);
    my $pslen = $emlen - length($T) - 2;
    my $PS = chr(0xff) x $pslen;
    my $em = chr(1) . $PS . chr(0) . $T; 
    return $em;
}

1;
