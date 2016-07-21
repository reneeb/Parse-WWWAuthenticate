package Parse::WWWAuthenticate;

# ABSTRACT: Parse the WWW-Authenticate HTTP header

use strict;
use warnings;

use base 'Exporter';

use Carp qw(croak);
use HTTP::Headers::Util qw(_split_header_words);

our $VERSION = 0.02;

our @EXPORT_OK = qw(parse_wwwa);

sub parse_wwwa {
   my ($string) = @_;

   my @parts = split_header_words( $string);

   my $challenge = $parts[0]->[0];
   my %challenges;

   PART:
   for my $part ( @parts ) {
      my ($maybe_challenge, $challenge_check) = @{$part};

      if ( !defined $challenge_check ) {
         $challenge = ucfirst lc $maybe_challenge;
      }

      my ($key, $value) = ($part->[-2], $part->[-1]);
      if ( !defined $value ) {
         if ( !exists $challenges{$challenge} ) {
            $challenges{$challenge} = {};
         }
         next PART;
      }

      my $lc_key = lc $key;
      if ( $challenge eq 'Basic' &&
         $lc_key eq 'realm' &&
         exists $challenges{$challenge}->{$lc_key}
      ) {
         croak 'only one realm is allowed';
      }

      $challenges{$challenge}->{lc $key} = $value;
   }

   if ( exists $challenges{Basic} && !exists $challenges{Basic}->{realm} ) {
      croak 'realm parameter is missing';
   }

   return %challenges;
}

sub split_header_words {
    my @res = &_split_header_words;
    for my $arr (@res) {
      for (my $i = @$arr - 2; $i >= 0; $i -= 2) {
          $arr->[$i] = $arr->[$i];
      }
    }
    return @res;
}

1;

=head1 SYNOPSIS

  use Parse::WWWAuthenticate qw(parse_wwwa);
  
  my $header = 'Basic realm="test"';
  my %challenges = parse_wwwa( $header );
  if ( $challenges{Basic} ) {
      print "Need credentials for realm " . $challenges{Basic}->{realm};
  }
  
  print "Those challenges are allowed: " . join ', ', sort keys %challenges;

kinda more real life:

  use LWP::UserAgent;
  use Parse::WWWAuthenticate qw(parse_wwwa);
  
  my $ua       = LWP::UserAgent->new;
  my $response = $ua->get('http://some.domain.example');
  my $header   = $response->header('WWW-Authenticate');
  
  my %challenges = parse_wwwa( $header );
  if ( $challenges{Basic} ) {
      print "Need credentials for realm " . $challenges{Basic}->{realm};
  }
  
  print "Those challenges are allowed: " . join ', ', sort keys %challenges;

=head1 FUNCTIONS

=head2 parse_wwwa

parses the content of the I<WWW-Authenticate> header and returns a hash of all the challenges and their data.

  my $header = 'Basic realm="test"';
  my %challenges = parse_wwwa( $header );
  if ( $challenges{Basic} ) {
      print "Need credentials for realm " . $challenges{Basic}->{realm};
  }
  
  print "Those challenges are allowed: " . join ', ', sort keys %challenges;

=head2 split_header_words

=head1 ACKNOWLEDGEMENTS

The testcases were generated with the httpauth.xml file from L<https://greenbyte.de/tech/tc/httpauth>.
