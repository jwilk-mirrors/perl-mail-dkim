#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::Canonicalization::Base;
use base "Mail::DKIM::MessageParser";
use Carp;

sub new
{
	my $class = shift;
	return $class->new_object(@_);
}

sub init
{
	my $self = shift;
	$self->SUPER::init;
}

sub output
{
	my $self = shift;
	my ($output) = @_;

	my $out_fh = $self->{output_fh};
	if ($out_fh)
	{
		print $out_fh $output;
	}
	elsif (my $out_obj = $self->{output})
	{
		$out_obj->PRINT($output);
	}
	else
	{
		$self->{result} .= $output;
	}
}

sub result
{
	my $self = shift;
	return $self->{result};
}

1;

__END__

=head1 NAME

Mail::DKIM::Canonicalization::Base - base class for canonicalization methods

=head1 SYNOPSIS

  # canonicalization results get output to STDOUT
  my $method = new Mail::DKIM::Canonicalization::nowsp(
                    output_fh => *STDOUT,
                    Signature => $dkim_signature);

  # add headers
  $method->add_header("Subject: this is the subject\015\012");
  $method->finish_header;

  # add body
  $method->add_body("This is the body.\015\012");
  $method->add_body("Another line of the body.\015\012");
  $method->finish_body;

  # this adds the signature to the end
  $method->finish_message;

=cut
