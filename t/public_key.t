#!/usr/bin/perl -I../lib

use strict;
use warnings;
use Test::More tests => 1;

use Mail::DKIM::Verifier;

my $pubkey = Mail::DKIM::PublicKey->fetch(
		Protocol => "dns",
		Selector => "test1",
		Domain => "messiah.edu",
		);
ok($pubkey);
