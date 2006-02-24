#!/usr/bin/perl

use strict;
use warnings;
use Test::Simple tests => 7;

use Mail::DKIM::Signature;

my $signature = Mail::DKIM::Signature->new();
ok($signature, "new() works");

$signature->algorithm("rsa-sha1");
ok($signature->algorithm eq "rsa-sha1", "algorithm() works");

$signature->canonicalization("relaxed", "simple");
my ($header_can, $body_can) = $signature->canonicalization;
ok($header_can eq "relaxed", "canonicalization() works (I)");
ok($body_can eq "simple", "canonicalization() works (II)");
my $combined = $signature->canonicalization;
ok($combined eq "relaxed/simple", "canonicalization() works (III)");

$signature->canonicalization("simple/relaxed");
ok($signature->canonicalization eq "simple/relaxed",
	"canonicalization() works (IV)");

my $unparsed = "DKIM-Signature: a=rsa-sha1; c=relaxed";
$signature = Mail::DKIM::Signature->parse($unparsed);
ok($signature, "parse() works");
