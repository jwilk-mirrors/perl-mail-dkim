#!/usr/bin/perl

use strict;
use warnings;
use Test::Simple tests => 5;

use Mail::DKIM::Verifier;

my $dkim = Mail::DKIM::Verifier->new();
ok($dkim, "new() works");

$dkim = Mail::DKIM::Verifier->new_object();
ok($dkim, "new_object() works");

my $srcfile = "t/test5.txt";
my $sample_email = read_file($srcfile);
ok($sample_email, "able to read sample email");
ok($sample_email =~ /\015\012/, "sample has proper line endings");

$dkim->PRINT($sample_email);
$dkim->CLOSE;

my $result = $dkim->result;
ok($result eq "pass", "result() works and gave expected answer");

sub read_file
{
	open my $fh, "<", $srcfile
		or die "Error: can't open $srcfile: $!\n";
	local $/;
	my $content = <$fh>;
	close $fh;
	return $content;
}
