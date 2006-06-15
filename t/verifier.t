#!/usr/bin/perl -I../lib

use strict;
use warnings;
use Test::Simple tests => 22;

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
test_email("good_ietf00_1.txt", "pass");
test_email("good_ietf00_2.txt", "pass");
test_email("good_ietf00_3.txt", "pass");
test_email("good_ietf00_4.txt", "pass");
test_email("good_ietf00_5.txt", "pass");
test_email("good_ietf01_1.txt", "pass");
test_email("good_ietf01_2.txt", "pass");
test_email("bad_ietf01_1.txt", "fail");
ok($dkim->result_detail =~ /body/, "determined body had been altered");
test_email("bad_ietf01_2.txt", "fail");
ok($dkim->result_detail =~ /header/, "determined header had been altered");
test_email("bad_ietf01_3.txt", "fail");
ok($dkim->result_detail =~ /RSA/, "determined RSA failure");

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
	print "# verifying message '$file'\n";
	print "#   result: " . $dkim->result_detail . "\n";
	ok($result eq $expected_result, "'$file' should '$expected_result'");
}
