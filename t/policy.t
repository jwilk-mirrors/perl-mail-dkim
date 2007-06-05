#!/usr/bin/perl -I../blib/lib

use strict;
use warnings;
use Test::Simple tests => 12;

use Mail::DKIM::Policy;

my $policy;
$policy = Mail::DKIM::Policy->new();
ok($policy, "new() works");

$policy = Mail::DKIM::Policy->parse(String => "o=~; t=y");
ok($policy, "parse() works");

$policy = Mail::DKIM::Policy->fetch(
		Protocol => "dns",
		Domain => "messiah.edu");
ok($policy, "fetch() works (requires DNS)");
ok(!$policy->is_implied_default_policy, "not the default policy");

$policy = Mail::DKIM::Policy->parse(String => "");
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

$policy = Mail::DKIM::Policy->fetch(
		Protocol => "dns",
		Domain => "nobody.messiah.edu"
		);
ok($policy, "fetch() returns policy for nonexistent domain");
ok($policy->is_implied_default_policy, "yep, it's the default policy");
