#!/usr/bin/perl -I../blib/lib

use strict;
use warnings;
use Test::Simple tests => 13;

use Mail::DKIM::DkPolicy;
use Mail::DKIM::DkimPolicy;

my $policy;
$policy = Mail::DKIM::DkPolicy->new();
ok($policy, "new() works");

$policy = Mail::DKIM::DkPolicy->parse(String => "o=~; t=y");
ok($policy, "parse() works");

$policy = Mail::DKIM::DkPolicy->fetch(
		Protocol => "dns",
		Domain => "messiah.edu");
ok($policy, "fetch() works (requires DNS)");
ok(!$policy->is_implied_default_policy, "not the default policy");

$policy = Mail::DKIM::DkPolicy->parse(String => "");
ok($policy, "parse() works (no tags)");

ok(!defined($policy->note), "note tag has default value");
$policy->note("hi there");
ok($policy->note eq "hi there", "note tag has been changed");

ok($policy->policy eq "~", "policy tag has default value");
$policy->policy("-");
ok($policy->policy eq "-", "policy tag has been changed");

ok(!$policy->testing, "testing flag has default value");
#$policy->testing(1);
#ok($policy->testing, "testing flag has been changed");

ok($policy->as_string, "as_string() method is implemented");

$policy = Mail::DKIM::DkPolicy->fetch(
		Protocol => "dns",
		Sender => 'alfred@nobody.messiah.edu',
		);
ok($policy, "fetch() returns policy for nonexistent domain");
ok($policy->is_implied_default_policy, "yep, it's the default policy");

#debug_policies(qw(yahoo.com hotmail.com gmail.com));
#debug_policies(qw(paypal.com ebay.com));
#debug_policies(qw(cisco.com sendmail.com));

sub debug_policies
{
	foreach my $domain (@_)
	{
		print "# $domain:\n";

		print "#  DomainKeys: ";
		my $policy = Mail::DKIM::DkPolicy->fetch(
			Protocol => "dns",
			Domain => $domain);
		if ($policy->is_implied_default_policy)
		{
			print "no policy\n";
		}
		else
		{
			print $policy->policy . " (";
			print $policy->as_string . ")\n";
		}

		print "#  DKIM: ";
		$policy = Mail::DKIM::DkimPolicy->fetch(
			Protocol => "dns",
			Domain => $domain);
		if ($policy->is_implied_default_policy)
		{
			print "no policy\n";
		}
		else
		{
			print $policy->policy . " (";
			print $policy->as_string . ")\n";
		}
	}
}
