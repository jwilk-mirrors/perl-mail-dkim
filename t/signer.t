#!/usr/bin/perl

use strict;
use warnings;
use Test::Simple tests => 4;

use Mail::DKIM::Signer;

my $dkim = Mail::DKIM::Signer->new_object(
		Algorithm => "rsa-sha1",
		Method => "relaxed",
		Domain => "example.org",
		Selector => "test",
		KeyFile => "t/test.key");
ok($dkim, "new_object() works");

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

print "signature=" . $signature->as_string . "\n";

# now try a SHA256 signature
$dkim = Mail::DKIM::Signer->new_object(
		Algorithm => "rsa-sha256",
		Method => "relaxed",
		Domain => "example.org",
		Selector => "test",
		KeyFile => "t/test.key");
ok($dkim, "new_object() works");

$dkim->PRINT($sample_email);
$dkim->CLOSE;

ok($dkim->signature, "signature() works");
