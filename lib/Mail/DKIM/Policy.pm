#!/usr/bin/perl

# Copyright 2005-2007 Messiah College.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::Policy;
our $DEFAULT_POLICY;

=head1 NAME

Mail::DKIM::Policy - represents a DKIM sender signing policy

=head1 DESCRIPTION

A sender signing policy, according to DKIM, is a record published
in the message author's DNS that describes how they sign messages.

=head1 CONSTRUCTORS

=head2 fetch() - fetch a sender signing policy from DNS

  my $policy = Mail::DKIM::Policy->fetch(
                   Protocol => "dns",
                   Domain => "example.org",
               );

If a DNS error or timeout occurs, an exception is thrown.

Otherwise, a policy object of some sort will be returned.
If no policy is actually published,
then the "default policy" will be returned.
To check when this happens, use

  my $is_default = $policy->is_implied_default_policy;

=cut

sub fetch
{
	my $class = shift;
	my %prms = @_;

	my $strn;

	($prms{'Protocol'} eq "dns")
		or die "invalid protocol '$prms{Protocol}'\n";

	use Net::DNS;

	my $rslv = Net::DNS::Resolver->new();
	
	# IETF seems poised to create policy records this way
	#my $host = "_policy._domainkey." . $prms{Domain};

	# but Yahoo! policy records are still much more common
	# see historic RFC4870, section 3.6
	my $host = "_domainkey." . $prms{Domain};

	#
	# perform DNS query for domain policy...
	#   if the query takes too long, we should catch it and generate
	#   an error
	#
	my $resp;
	eval
	{
		# set a 10 second timeout
		local $SIG{ALRM} = sub { die "DNS query timeout for $host\n" };
		alarm 10;

		# the query itself could cause an exception, which would prevent
		# us from resetting the alarm before leaving the eval {} block
		# so we wrap the query in a nested eval {} block
		eval
		{
			$resp = $rslv->query($host, "TXT");
		};
		my $E = $@;
		alarm 0;
		die $E if $E;
	};
	my $E = $@;
	alarm 0; #FIXME- restore previous alarm?
	die $E if $E;
	unless ($resp)
	{
		# no response => NXDOMAIN, use default policy
		return $class->default;
	}

	foreach my $ans ($resp->answer) {
		next unless $ans->type eq "TXT";
		$strn = join "", $ans->char_str_list;
	}

	unless ($strn)
	{
		# empty record found in DNS, use default policy
		return $class->default;
	}

	return $class->parse(
			String => $strn,
			Domain => $prms{Domain}
			);
}

=head2 new() - construct a default policy object

  my $policy = Mail::DKIM::Policy->new;

=cut

sub new
{
	my $class = shift;
	return $class->parse(String => "o=~");
}

=head2 parse() - gets a policy object by parsing a string

  my $policy = Mail::DKIM::Policy->parse(
                   String => "o=~; t=y"
               );

=cut

sub parse
{
	my $class = shift;
	my %prms = @_;

	my $text = $prms{"String"};
	my %tags;
	foreach my $tag (split /;/, $text)
	{
		# strip whitespace
		$tag =~ s/^\s+|\s+$//g;

		my ($tagname, $value) = split /=/, $tag, 2;
		unless (defined $value)
		{
			die "policy syntax error\n";
		}

		$tagname =~ s/\s+$//;
		$value =~ s/^\s+//;
		$tags{$tagname} = $value;
	}

	$prms{tags} = \%tags;
	return bless \%prms, $class;	
}

=head1 CLASS METHODS

=head2 default() - the policy to use when none is published

  my $default_policy = Mail::DKIM::Policy->default();

=cut

sub default
{
	my $class = shift;
	$DEFAULT_POLICY ||= $class->new;
	return $DEFAULT_POLICY;
}

=head1 METHODS

=head2 apply() - apply the policy to the results of a DKIM verifier

  my $result = $policy->apply($dkim_verifier);

The caller must provide an instance of L<Mail::DKIM::Verifier>, one which
has already been fed the message being verified.

Possible results are:

=over

=item accept

The message is approved by the sender signing policy.

=item reject

The message is rejected by the sender signing policy.

=item neutral

The message is neither approved nor rejected by the sender signing
policy. It can be considered suspicious.

=back

=cut

sub apply
{
	my $self = shift;
	my ($dkim) = @_;

	my $verify_result = $dkim->result;
	my $first_party;
	if ($dkim->message_originator && $dkim->signature)
	{
		my $oa = $dkim->message_originator->address;
		my $id = $dkim->signature->identity;

		if (substr($oa, -length($id)) eq $id)
		{
			$first_party = 1;
		}
	}

	use constant POLICY_NEVER => ".";
	use constant POLICY_EXCLUSIVE => "!";
	use constant POLICY_STRONG => "-";
	return "reject" if ($self->policy eq POLICY_NEVER);
	return "accept" if ($verify_result eq "pass" && $first_party);
	return "reject" if ($self->policy eq POLICY_EXCLUSIVE);
	return "accept" if ($verify_result eq "pass");
	return "reject" if ($self->policy eq POLICY_STRONG);
	return "neutral";
}

=head2 as_string() - the policy as a string

Note that the string returned by this method will not necessarily have
the tags ordered the same as the text record found in DNS.

=cut

sub as_string
{
	my $self = shift;

	return join("; ", map { "$_=" . $self->{tags}->{$_} }
		keys %{$self->{tags}});
}

=head2 flags() - get or set the flags (t=) tag

A vertical-bar separated list of flags.

=cut

sub flags
{
	my $self = shift;

	(@_) and 
		$self->{tags}->{t} = shift;

	$self->{tags}->{t};
}

=head2 is_implied_default_policy() - is this policy implied?

  my $is_implied = $policy->is_implied_default_policy;

If you fetch the policy for a particular domain, but that domain
does not have a policy published, then the "default policy" is
in effect. Use this method to detect when that happens.

=cut

sub is_implied_default_policy
{
	my $self = shift;
	my $default_policy = ref($self)->default;
	return ($self == $default_policy);
}

=head2 note() - get or set the human readable notes (n=) tag

Human readable notes regarding the record. Undef if no notes specified.

=cut

sub note
{
	my $self = shift;

	(@_) and 
		$self->{tags}->{n} = shift;

	$self->{tags}->{n};
}

=head2 policy() - get or set the outbound signing policy (o=) tag

  my $sp = $policy->policy;

Outbound signing policy for the entity. Possible values are:

=over

=item C<~>

The entity signs some but not all email.

=item C<->

All mail from the entity is signed; unsigned email MUST NOT be
accepted, but email signed with a Verifier Acceptable Third
Party Signature SHOULD be accepted.

=back

Other values are possible as well, they just haven't been documented yet.

=cut

sub policy
{
	my $self = shift;

	(@_) and
		$self->{tags}->{o} = shift;

	if (defined $self->{tags}->{o})
	{
		return $self->{tags}->{o};
	}
	else
	{
		return "~";
	}
}

sub signall
{
	my $self = shift;

	$self->policy and $self->policy eq "-" and
		return 1;

	return;
}

sub signsome
{
	my $self = shift;

	$self->policy or
		return 1;

	$self->policy eq "~" and
		return 1;

	return;
}

=head2 testing() - checks the testing flag

  my $testing = $policy->testing;

If nonzero, the testing flag is set on the signing policy, and the
verify should not consider a message suspicious based on this policy.

=cut

sub testing
{
	my $self = shift;
	my $t = $self->flags;
	($t && $t =~ /y/i)
		and return 1;
	return;
}

1;

=head1 BUGS

=over

=item *

If a sender signing policy is not found for a given domain, the
fetch() method should search the parent domains, according to
section 4 of the dkim-ssp Internet Draft.

=back

=head1 AUTHOR

Jason Long, E<lt>jlong@messiah.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006-2007 by Messiah College

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut
