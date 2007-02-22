#!/usr/bin/perl -I../lib

use strict;
use warnings;
use Test::Simple tests => 5;

use Mail::DKIM::Signer;

my $keyfile = -f "t/test.key" ? "t/test.key" : "test.key";
my $dkim = Mail::DKIM::Signer->new(
		Algorithm => "rsa-sha1",
		Method => "relaxed",
		Domain => "example.org",
		Selector => "test",
		KeyFile => $keyfile);
ok($dkim, "new() works");

my $sample_email = <<END_OF_SAMPLE;
From: jason <jason\@example.org>
Subject: hi there

this is a sample message
END_OF_SAMPLE
$sample_email =~ s/\n/\015\012/gs;

$dkim->PRINT($sample_email);
$dkim->CLOSE;

my $signature = $dkim->signature;
ok($signature, "signature() works");

print "# signature=" . $signature->as_string . "\n";
ok($signature->as_string =~ /Z8eOKAa79Wp7GSL1m6Ss/,
	"got expected signature value");

# now try a SHA256 signature
$dkim = Mail::DKIM::Signer->new(
		Algorithm => "rsa-sha256",
		Method => "relaxed",
		Domain => "example.org",
		Selector => "test",
		KeyFile => $keyfile);
ok($dkim, "new() works");

$dkim->PRINT($sample_email);
$dkim->CLOSE;

ok($dkim->signature, "signature() works");
