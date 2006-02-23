#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#
# Written by Jason Long <jlong@messiah.edu>

use strict;
use warnings;

package Mail::DKIM::SignerPolicy;

1;

__END__

=head1 NAME

Mail::DKIM::SignerPolicy - determines signing parameters for a message

=head1 DESCRIPTION

Objects of type Mail::DKIM::SignerPolicy are used by Mail::DKIM::Signer.
To take advantage of policy objects, create your own Perl class that
extends this class. The only method you need to provide is the apply()
method.

The apply() method takes as a parameter the Mail::DKIM::Signer object.
Using this object, it can determine some properties of the message (e.g.
what the From: address or Sender: address is). Then it sets various
signer properties as desired. The apply() method should
return a nonzero value if the message should be signed. If a false value
is returned, then the message is "skipped" (i.e. not signed).

Here is an example of a policy that always returns the same values:

  package MySignerPolicy;
  use base "Mail::DKIM::SignerPolicy";

  sub apply
  {
      my $self = shift;
      my $signer = shift;
  
      $signer->algorithm("rsa-sha1");
      $signer->method("relaxed");
      $signer->domain("example.org");
      $signer->selector("selector1");
  
      return 1;
  }

To use this policy, simply specify the name of the class as the Policy
parameter...

  my $dkim = Mail::DKIM::Signer->new_object(
                  Policy => "MySignerPolicy",
                  KeyFile => "private.key"
             );

=cut
