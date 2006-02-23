#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::PublicKey;

use base ("Mail::DKIM::KeyValueList", "Mail::DKIM::Key");

sub new {
	my $type = shift;
	my %prms = @_;

	my $self = {};

	$self->{'GRAN'} = $prms{'Granularity'};
	$self->{'NOTE'} = $prms{'Note'};
	$self->{'TEST'} = $prms{'Testing'};
	$self->{'TYPE'} = ($prms{'Type'} or "rsa");
	$self->{'DATA'} = $prms{'Data'};

	bless $self, $type;
}

sub fetch
{
	use Net::DNS;

	my $class = shift;
	my %prms = @_;

	my $strn;


	my ($query_type, $query_options) = split(/\//, $prms{Protocol}, 2);
	if (lc($query_type) ne "dns")
	{
		die "unknown query type '$query_type'\n";
	}

	my $host = $prms{'Selector'} . "._domainkey." . $prms{'Domain'};

	my $rslv = new Net::DNS::Resolver or
		return;
	
	#
	# perform DNS query for public key...
	#   if the query takes too long, we should generate an error
	#
	my $resp;
	eval
	{
		# set a 10 second timeout
		local $SIG{ALRM} = sub { die "DNS query timeout for $host\n" };
		alarm 10;

		$resp = $rslv->query($host, "TXT");
		alarm 0;
	};
	my $E = $@;
	alarm 0;
	if ($E)
	{
		chomp $E;
		die "$E\n";
	}
	unless ($resp)
	{
		# no response => NXDOMAIN
		return;
	}

	foreach my $ans ($resp->answer) {
		next unless $ans->type eq "TXT";
		$strn = join "", $ans->char_str_list;
	}

	$strn or
		return;

	my $self = $class->parse($strn);
	$self->{Selector} = $prms{'Selector'};
	$self->{Domain} = $prms{'Domain'};
	$self->check;
	return $self;
}

# check syntax of the public key
# throw an error if any errors are detected
sub check
{
	my $self = shift;

	# check public key version tag
	if (my $v = $self->get_tag("v"))
	{
		unless ($v eq "DKIM1")
		{
			die "unrecognized public key version\n";
		}
	}

	# check public key granularity
	my $g = $self->granularity;

	# check hash algorithm
	if (my $h = $self->get_tag("h"))
	{
		my @list = split(/:/, $h);
		unless (grep { $_ eq "sha1" } @list)
		{
			die "public key: no supported hash algorithm\n";
		}
	}

	# check key type
	if (my $k = $self->get_tag("k"))
	{
		unless ($k eq "rsa")
		{
			die "public key: unsupported key type\n";
		}
	}

	# check public-key data
	my $p = $self->data;
	if (not defined $p)
	{
		die "public key: missing p= tag\n";
	}
	if ($p eq "")
	{
		die "public key: revoked\n";
	}
	unless ($p =~ /^[A-Za-z0-9\+\/\=]+$/)
	{
		die "public key: invalid data\n";
	}
	
	# check service type
	if (my $s = $self->get_tag("s"))
	{
		my @list = split(/:/, $s);
		unless (grep { $_ eq "*" || $_ eq "email" } @list)
		{
			die "public key: does not support email authentication\n";
		}
	}

	return 1;
}

sub convert
{
	use Crypt::OpenSSL::RSA;

	my $self = shift;


	$self->data or
		return;

	# have to PKCS1ify the pubkey because openssl is too finicky...
	my $cert = "-----BEGIN PUBLIC KEY-----\n";

	for (my $i = 0; $i < length $self->data; $i += 64) {
		$cert .= substr $self->data, $i, 64;
		$cert .= "\n";
	}	

	$cert .= "-----END PUBLIC KEY-----\n";

	my $cork;
	
	eval {
		$cork = new_public_key Crypt::OpenSSL::RSA($cert);
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

sub verify {
	my $self = shift;
	my %prms = @_;


	my $rtrn;

	eval {
		$rtrn = $self->cork->verify($prms{'Text'}, $prms{'Signature'});
	}; 

	$@ and
		$self->errorstr($@),
		return;
	
	return $rtrn;
}

sub granularity
{
	my $self = shift;

	(@_) and 
		$self->set_tag("g", shift);

	return $self->get_tag("g");
}

sub notes
{
	my $self = shift;

	(@_) and 
		$self->set_tag("n", shift);

	return $self->get_tag("n");
}

sub data
{
	my $self = shift;

	(@_) and 
		$self->set_tag("p", shift);

	return $self->get_tag("p");
}

sub flags
{
	my $self = shift;

	(@_) and 
		$self->set_tag("t", shift);

	return $self->get_tag("t");
}

sub revoked
{
	my $self = shift;

	$self->data or
		return 1;

	return;
}

sub testing
{
	my $self = shift;

	my $flags = $self->flags;
	my @flaglist = split(/:/, $flags);
	if (grep { $_ eq "y" } @flaglist)
	{
		return 1;
	}
	return undef;
}


use Crypt::RSA::Primitives;
use Crypt::RSA::DataFormat ("os2ip", "octet_len", "i2osp", "h2osp");
use Crypt::RSA::Key::Private;

sub verify_sha1_digest
{
	my $self = shift;
	my ($digest, $signature) = @_;

    my ($kn, $ke) = $self->cork->get_key_parameters;
    my $key = bless { }, "Crypt::RSA::Key::Public";
	$key->e($ke->to_decimal);
	$key->n($kn->to_decimal);
	unless ($key->check)
	{
		die "Key check failed: " . $key->errstr . "\n";
	}

    my $rsa = new Crypt::RSA::Primitives;
    my $k = octet_len($key->n);
    my $s = os2ip($signature);
    my $m = $rsa->core_verify(
			Key => $key,
			Signature => $s)
		or die "core_verify failed";
    my $verify_result = i2osp($m, $k - 1)
		or die "i2osp failed";
	my $expected = substr($verify_result, -20);

	return ($expected eq $digest);
}

1;
