#!/usr/bin/perl

# Copyright 2007, 2012 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

use strict;
use warnings;

=head1 NAME

Mail::DKIM::DNS - performs DNS queries for Mail::DKIM

=head1 DESCRIPTION

This is the module that performs DNS queries for L<Mail::DKIM>.
It contains a few global variables that can be set by the caller
in order to change its behavior.

=head1 CONFIGURATION

There are a few global variables that can be set to modify the
behavior of this module.

=over

=item $Mail::DKIM::DNS::TIMEOUT

This specifies the maximum amount of time (in seconds) to wait for
a single DNS query to complete. The default is 10.

=item $Mail::DKIM::DNS::RESOLVER

This specifies the instance of L<Net::DNS::Resolver> that is used
to perform the queries. The default is undef, which causes a brand
new default instance of L<Net::DNS::Resolver> to be created for each
DNS query.

Use this if you want to provide additional options to Net::DNS::Resolver,
such as different timeouts or use of a persistent socket:

  use Mail::DKIM::DNS;
  $Mail::DKIM::DNS::RESOLVER = Net::DNS::Resolver->new(
                    udp_timeout => 3, tcp_timeout => 3, retry => 2,
                 );
  $Mail::DKIM::DNS::RESOLVER->udppacketsize(4096);
  $Mail::DKIM::DNS::RESOLVER->persistent_udp(1);

Note: to disable use of EDNS0 (enabled by default as of Mail::DKIM 0.40):

  $Mail::DKIM::DNS::RESOLVER->udppacketsize(512);

=back

=cut

# This class contains a method to perform synchronous DNS queries.
# Hopefully some day it will have a method to perform
# asynchronous DNS queries.

package Mail::DKIM::DNS;
use Net::DNS;
our $TIMEOUT = 10;
our $RESOLVER = Net::DNS::Resolver->new();
$RESOLVER->udppacketsize(2048); # enables EDNS0, sets acceptable UDP packet size

# query- returns a list of RR objects
#   or an empty list if the domain record does not exist
#       (e.g. in the case of NXDOMAIN or NODATA)
#   or throws an error on a DNS query time-out or other transient error
#       (e.g. SERVFAIL)
#
# if an empty list is returned, $@ is also set to a string explaining
# why no records were returned (e.g. "NXDOMAIN").
#
sub query
{
	my ($domain, $type) = @_;

	my $rslv = $RESOLVER || Net::DNS::Resolver->new();
	if (not $rslv)
	{
		die "can't create DNS resolver";
	}

	#
	# perform the DNS query
	#   if the query takes too long, we should generate an error
	#
	my $resp;
	my $remaining_time = alarm(0);  # check time left, stop the timer
	my $deadline = time + $remaining_time;
	eval
	{
		# set a 10 second timeout
		local $SIG{ALRM} = sub { die "DNS query timeout for $domain\n" };
		alarm $TIMEOUT;

		# the query itself could cause an exception, which would prevent
		# us from resetting the alarm before leaving the eval {} block
		# so we wrap the query in a nested eval {} block
		eval
		{
			$resp = $rslv->send($domain, $type);
		};
		my $E = $@;
		alarm 0;
		die $E if $E;
	};
	my $E = $@;
	alarm 0;
	# restart the timer if it was active
	if ($remaining_time > 0)
	{
		my $dt = $deadline - time;
		# make sure the timer expiration will trigger a signal,
		# even at the expense of stretching the interval by one second
		alarm($dt < 1 ? 1 : $dt);
	}
	die $E if $E;

	if ($resp)
	{
		my @result = grep { lc $_->type eq lc $type } $resp->answer;
		return @result if @result;
	}

	$@ = $rslv->errorstring;
	return () if ($@ eq "NOERROR" || $@ eq "NXDOMAIN");
	die "DNS error: $@\n";
}

# query_async() - perform a DNS query asynchronously
#
#   my $waiter = query_async("example.org", "TXT",
#                        Callbacks => {
#                                Success => \&on_success,
#                                Error => \&on_error,
#                                },
#                            );
#   my $result = $waiter->();
#
sub query_async
{
	my ($domain, $type, %prms) = @_;

	my $callbacks = $prms{Callbacks} || {};
	my $on_success = $callbacks->{Success} || sub { $_[0] };
	my $on_error = $callbacks->{Error} || sub { die $_[0] };

	my $waiter = sub {
		my @resp;
		my $warning;
		eval {
			@resp = query($domain, $type);
			$warning = $@;
			undef $@;
		};
		$@ and return $on_error->($@);
		$@ = $warning;
		return $on_success->(@resp);
	};
	return $waiter;
}

1;

=head1 AUTHOR

Jason Long, E<lt>jlong@messiah.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006-2007, 2012 by Messiah College

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut
