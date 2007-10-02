#!/usr/bin/perl -I../lib

use strict;
use warnings;
use Test::More tests => 47;

use Mail::DKIM::Verifier;

my $dkim = Mail::DKIM::Verifier->new();
ok($dkim, "new() works");

$dkim = Mail::DKIM::Verifier->new_object();
ok($dkim, "new_object() works");

my $srcfile = "t/test5.txt";
unless (-f $srcfile)
{
	$srcfile = "test5.txt" if (-f "test5.txt");
}
my $sample_email = read_file($srcfile);
ok($sample_email, "able to read sample email");
ok($sample_email =~ /\015\012/, "sample has proper line endings");

$dkim->PRINT($sample_email);
$dkim->CLOSE;

my $result = $dkim->result;
ok($result eq "pass", "result() works and gave expected answer");
if ($result ne "pass")
{
	print "result=$result\n";
	print "result detail=" . $dkim->result_detail . "\n";
}

test_email("mine_ietf01_1.txt", "pass");
test_email("mine_ietf01_2.txt", "pass");
test_email("mine_ietf01_3.txt", "pass");
test_email("mine_ietf01_4.txt", "pass");
test_email("mine_ietf05_1.txt", "pass");
test_email("good_ietf00_1.txt", "pass");
test_email("good_ietf00_2.txt", "pass");
test_email("good_ietf00_3.txt", "pass");
test_email("good_ietf00_4.txt", "pass");
test_email("good_ietf00_5.txt", "pass");
test_email("good_ietf01_1.txt", "pass");
test_email("good_ietf01_2.txt", "pass");
test_email("multiple_1.txt", "pass");

test_email("bad_ietf01_1.txt", "fail");
ok($dkim->result_detail =~ /body/, "determined body had been altered");
test_email("bad_ietf01_2.txt", "fail");
ok($dkim->result_detail =~ /message/, "determined message had been altered");
test_email("bad_ietf01_3.txt", "fail");
ok($dkim->result_detail =~ /RSA/, "determined RSA failure");
test_email("bad_1.txt", "fail"); #openssl error
print "# " . $dkim->result_detail . "\n";
SKIP:
{
	skip "did not recognize OpenSSL error", 1
		unless ($dkim->result_detail =~ /OpenSSL/i);
	like($dkim->result_detail,
		qr/OpenSSL/i,
		"determined OpenSSL error");
}

# test older DomainKeys messages, from Gmail and Yahoo!
test_email("good_dk_gmail.txt", "pass");
test_email("good_dk_yahoo.txt", "pass");
test_email("good_dk_1.txt", "pass");
test_email("good_dk_2.txt", "pass");
test_email("dk_headers_1.txt", "pass");
test_email("dk_headers_2.txt", "pass");

# test empty/missing body - simple canonicalization
test_email("no_body_1.txt", "pass");
test_email("no_body_2.txt", "pass");
test_email("no_body_3.txt", "pass");

#
# test various problems with the signature itself
#
test_email("ignore_1.txt", "invalid"); # unsupported v= tag (v=5)
test_email("ignore_2.txt", "invalid"); # unsupported a= tag (a=rsa-md5)
test_email("ignore_3.txt", "invalid"); # unsupported a= tag (a=dsa-sha1)
test_email("ignore_4.txt", "invalid"); # unsupported c= tag (c=future)
test_email("ignore_5.txt", "invalid"); # unsupported q= tag (q=http)
test_email("ignore_6.txt", "invalid"); # unsupported q= tag (q=dns/special)

#
# test problems with the public key
#
test_email("badkey_1.txt", "invalid"); # public key NXDOMAIN
test_email("badkey_2.txt", "invalid"); # public key REVOKED
test_email("badkey_3.txt", "invalid"); # public key unsupported v= tag
test_email("badkey_4.txt", "invalid"); # public key syntax error
test_email("badkey_5.txt", "invalid"); # public key unsupported k= tag
test_email("badkey_6.txt", "invalid"); # public key unsupported s= tag


sub read_file
{
	my $srcfile = shift;
	open my $fh, "<", $srcfile
		or die "Error: can't open $srcfile: $!\n";
	binmode $fh;
	local $/;
	my $content = <$fh>;
	close $fh;
	return $content;
}

sub test_email
{
	my ($file, $expected_result) = @_;
	print "# verifying message '$file'\n";
	$dkim = Mail::DKIM::Verifier->new();
	my $path = "t/corpus/" . $file;
	unless (-f $path)
	{
		$path = "corpus/$file" if (-f "corpus/$file");
	}
	my $email = read_file($path);
	$dkim->PRINT($email);
	$dkim->CLOSE;
	my $result = $dkim->result;
	print "#   result: " . $dkim->result_detail . "\n";
	ok($result eq $expected_result, "'$file' should '$expected_result'");
}
