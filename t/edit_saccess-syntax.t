use Test::Strict tests => 3;                      # last test to print

syntax_ok( 'edit_saccess.cgi' );
strict_ok( 'edit_saccess.cgi' );
warnings_ok( 'edit_saccess.cgi' );
