#!/usr/bin/perl -I../..

use strict;
use warnings;

use Mail::DKIM::SigningFilter;

my $signing_filter = Mail::DKIM::SigningFilter->new_object(
		Policy => "MySignerPolicy",
		KeyFile => "private.key");

while (<STDIN>)
{
	chomp;
	$signing_filter->PRINT("$_\015\012");
}
$signing_filter->CLOSE;


package MySignerPolicy;
use Mail::DKIM::SignerPolicy;
use base "Mail::DKIM::SignerPolicy";

sub apply
{
	my ($self, $signer) = @_;

	return (
		"rsa-sha1",
		"nowsp",
		$signer->message_sender->host,
		"selector1" );
}
