#!/usr/bin/perl -I../lib

use strict;
use warnings;
use Test::More tests => 3;

use Mail::DKIM::Verifier;

my $pubkey = Mail::DKIM::PublicKey->fetch(
		Protocol => "dns",
		Selector => "test1",
		Domain => "messiah.edu",
		);
ok($pubkey);

$pubkey = eval { Mail::DKIM::PublicKey->fetch(
		Protocol => "dns",
		Selector => "foo",
		Domain => "blackhole.messiah.edu",
		) };
my $E = $@;
print "# error was $E\n";
ok(!$pubkey
	and $E and $E =~ /timeout/);

$pubkey = eval { Mail::DKIM::PublicKey->fetch(
		Protocol => "dns",
		Selector => "foo",
		Domain => "blackhole2.messiah.edu",
		) };
$E = $@;
print "# error was $E\n";
ok(!$pubkey
	and $E);
