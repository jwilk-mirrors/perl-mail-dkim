#!/usr/bin/perl -I../lib

use strict;
use warnings;
use Test::Simple tests => 12;

use Mail::DKIM::Signer;

my $EXPECTED_RE = qr/Z8eOKAa79Wp7GSL1m6Ss/;

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
Comment: what is a comment

this is a sample message
END_OF_SAMPLE
$sample_email =~ s/\n/\015\012/gs;

$dkim->PRINT($sample_email);
$dkim->CLOSE;

my $signature = $dkim->signature;
ok($signature, "signature() works");

print "# signature=" . $signature->as_string . "\n";
ok($signature->as_string =~ /$EXPECTED_RE/,
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

# add some headers to the first email
$sample_email = "Received: from x\015\012"
	. "Received: from y\015\012"
	. $sample_email;
$sample_email =~ s/^Comments:.*?$/comments: this can be changed/m;

$dkim = Mail::DKIM::Signer->new(
		Algorithm => "rsa-sha1",
		Method => "relaxed",
		Domain => "example.org",
		Selector => "test",
		KeyFile => $keyfile);
ok($dkim, "new() works");

$dkim->PRINT($sample_email);
$dkim->CLOSE;

ok($dkim->signature, "signature() works");
print "# signature=" . $signature->as_string . "\n";
my $sigstr = $dkim->signature->as_string;
ok($sigstr =~ /subject/i, "subject was signed");
ok($sigstr =~ /from/i, "from was signed");
ok($sigstr !~ /received/i, "received was excluded");
ok($sigstr !~ /comments/i, "comments was excluded");
ok($sigstr =~ /$EXPECTED_RE/, "got expected signature value");
