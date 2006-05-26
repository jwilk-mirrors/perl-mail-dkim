use 5.008;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	NAME           => 'Mail::DKIM',
	VERSION_FROM   => 'lib/Mail/DKIM.pm', # finds $VERSION
	PREREQ_PM      => {
			Crypt::OpenSSL::Bignum => 0,
			Crypt::OpenSSL::RSA => 0,
			Crypt::RSA => 0,
			Digest::SHA1 => 0,
			Digest::SHA => 0,
			Error => 0,
			Mail::Address => 0,
			MIME::Base64 => 0,
			Net::DNS => 0,
		},
	ABSTRACT_FROM  => 'lib/Mail/DKIM.pm', # retrieve abstract from module
	AUTHOR         => 'Jason Long <jlong@messiah.edu>',
);
