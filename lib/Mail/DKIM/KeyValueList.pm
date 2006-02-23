#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::KeyValueList;
use Carp;

sub new
{
	my $class = shift;
	my %args = @_;

	my $self = bless \%args, $class;
	return $self;
}

sub parse
{
	my $class = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($string) = @_;

	my $self = {};
	bless $self, $class;	

	$self->{tags} = [];
	foreach my $raw_tag (split /;/, $string, -1)
	{
		my $tag = {
			raw => $raw_tag
			};
		push @{$self->{tags}}, $tag;

		# strip preceding and trailing whitespace
		$raw_tag =~ s/^\s*|\s*$//g;

		next if ($raw_tag eq "");

		my ($tagname, $value) = split(/=/, $raw_tag, 2);
		unless (defined $value)
		{
			die "key value list syntax error\n";
		}

		$tag->{name} = $tagname;
		$tag->{value} = $value;

		$self->{tags_by_name}->{$tagname} = $tag;
	}

	return $self;
}

sub clone
{
	my $self = shift;
	my $str = $self->as_string;
	return ref($self)->parse($str);
}

sub get_tag
{
	my $self = shift;
	my ($tagname) = @_;

	if ($self->{tags_by_name}->{$tagname})
	{
		return $self->{tags_by_name}->{$tagname}->{value};
	}
	return undef;
}

sub set_tag
{
	my $self = shift;
	my ($tagname, $value) = @_;

	if ($tagname =~ /[;=\015\012\t ]/)
	{
		croak "invalid tag name";
	}

	if (defined $value)
	{
		if ($value =~ /;/)
		{
			croak "invalid tag value";
		}
		if ($value =~ /\015\012[^\t ]/)
		{
			croak "invalid tag value";
		}

		if ($self->{tags_by_name}->{$tagname})
		{
			$self->{tags_by_name}->{$tagname}->{value} = $value;
			my ($rawname, $rawvalue) = split(/=/,
					$self->{tags_by_name}->{$tagname}->{raw}, 2);
			$self->{tags_by_name}->{$tagname}->{raw} = "$rawname=$value";
		}
		else
		{
			my $tag = {
				name => $tagname,
				value => $value,
				raw => " $tagname=$value"
				};
			push @{$self->{tags}}, $tag;
			$self->{tags_by_name}->{$tagname} = $tag;
		}
	}
	else
	{
		if ($self->{tags_by_name}->{$tagname})
		{
			delete $self->{tags_by_name}->{$tagname};
		}
		@{$self->{tags}} = grep
			{ $_->{name} ne $tagname } @{$self->{tags}};
	}
}

sub as_string
{
	my $self = shift;
	return join(";", map { $_->{raw} } @{$self->{tags}});
}

1;
