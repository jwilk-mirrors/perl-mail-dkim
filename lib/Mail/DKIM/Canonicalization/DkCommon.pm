#!/usr/bin/perl

# Copyright 2005-2006 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::Canonicalization::DkCommon;
use base "Mail::DKIM::Canonicalization::Base";
use Carp;

sub add_header
{
	my $self = shift;
	my ($line) = @_;

	#croak "header parse error \"$line\"" unless ($line =~ /:/);

	if ($line =~ /^domainkey-signature:/i)
	{
		# DomainKeys never includes headers that precede the
		# DomainKey-Signature header
		$self->{myheaders} = [];
	}
	else
	{
		push @{$self->{myheaders}}, $self->canonicalize_header($line);
	}
}

sub finish_header
{
	my $self = shift;

	# RFC4870, 3.3:
	#   h = A colon-separated list of header field names that identify the
	#       headers presented to the signing algorithm. If present, the
	#       value MUST contain the complete list of headers in the order
	#       presented to the signing algorithm.
	#
	#       In the presence of duplicate headers, a signer may include
	#       duplicate entries in the list of headers in this tag.  If a
	#       header is included in this list, a verifier must include all
	#       occurrences of that header, subsequent to the "DomainKey-
	#       Signature:" header in the verification.
	#
	# RFC4870, 3.4.2.1:
	#   * Each line of the email is presented to the signing algorithm in
	#     the order it occurs in the complete email, from the first line of
	#     the headers to the last line of the body.
	#   * If the "h" tag is used, only those header lines (and their
	#     continuation lines if any) added to the "h" tag list are included.

	# check if signature specifies a list of headers
	my @sig_header_names = $self->{Signature}->headerlist;
	my @sig_headers;
	if (@sig_header_names)
	{
		# - first, group all header fields with the same name together
		#   (using a hash of arrays)
		my %heads;
		foreach my $line (@{$self->{myheaders}})
		{
			my $field_name = "";
			if ($line =~ /^([^\s:]+)\s*:/)
			{
				$field_name = lc $1;
			}
			$heads{$field_name} ||= [];
			push @{$heads{$field_name}}, $line;
		}
		# - second, count how many times each header field name appears
		#   in the h= tag
		my %counts;
		foreach my $field_name (@sig_header_names)
		{
			$heads{lc $field_name} ||= [];
			$counts{lc $field_name}++;
		}
		# - finally, working backwards through the h= tag,
		#   collect the headers we will be signing (last to first).
		#   Normally one header at a time, but if there are more
		#   headers when the last of a certain h= tag value comes up,
		#   put the rest in.
		while (my $field_name = pop @sig_header_names)
		{
			$counts{lc $field_name}--;
			if ($counts{lc $field_name} > 0)
			{
				# this field is named more than once in the h= tag,
				# so only take the last occuring of that header
				my $line = pop @{$heads{lc $field_name}};
				unshift @sig_headers, $line if defined $line;
			}
			else
			{
				unshift @sig_headers, @{$heads{lc $field_name}};
				$heads{lc $field_name} = [];
			}
		}
	}
	else
	{
		@sig_headers = @{$self->{myheaders}};
	}

	# iterate through each header, in the order determined above
	foreach my $line (@sig_headers)
	{
		$self->output($line);
	}

	$self->output($self->canonicalize_body("\015\012"));
}

sub add_body
{
	my $self = shift;
	my ($line) = @_;

	$self->output($self->canonicalize_body($line));
}

sub finish_body
{
}

sub finish_message
{
}

1;
