#!/usr/bin/perl -I../lib

use strict;
use warnings;
use Test::Simple tests => 9;

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
ok($signature, "parse() works (I)");

$unparsed = "DKIM-Signature: a 	 = 	 rsa-sha1;  c 	 = 	 simple/simple;
	d 	 = 	example.org ;
 h 	 = 	 Date : From : MIME-Version : To : Subject : Content-Type :
Content-Transfer-Encoding; s 	 = 	 foo;
 b=aqanVhX/f1gmXSdVeX3KdmeKTZb1mkj1y111tZRp/8tXWX/srpGu2SJ/+O06fQv8YtgP0BrSRpEC
 WEtFgMHcDf0ZFLQgtm0f7vPBO98vDtB7dpDExzHyTsK9rxm8Cf18";
$signature = Mail::DKIM::Signature->parse($unparsed);
ok($signature, "parse() works (II)");
ok($signature->domain eq "example.org", "parse() correctly handles spaces");

print "#BEFORE->\n" . $signature->as_string . "\n";
$signature->prettify_safe;
print "#SAFE--->\n" . $signature->as_string . "\n";
$signature->prettify;
print "#PRETTY->\n" . $signature->as_string . "\n";
