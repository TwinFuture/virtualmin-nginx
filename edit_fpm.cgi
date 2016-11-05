#!/usr/bin/perl
# Show the config for one HTTP server

use strict;
use warnings;
require 'virtualmin-nginx-lib.pl';
our (%text, %in, %access, %config);
&ReadParse();
	my $fpm_loc = $config{'php_fpm_loc'}.'/';
my $server;
if ($in{'new'}) {
	$access{'vhosts'} && &error($text{'server_ecannotcreate'});
	&ui_print_header(undef, $text{'server_create'}, "");
	$server = { 'name' => 'server',
		    'members' => [ ] };
	}
else {
	&foreign_require("phpini");
	$server = &phpini::get_config($fpm_loc.substr($in{'id'}, 0, -1).'.conf');
    my $user = &phpini::find_value('user', $server);
	$server || &error($text{'server_egone'});
    &can_edit_server($server) || &error($text{'server_ecannot'});
	&ui_print_header('For '.$user, "Configure PHP-FPM", "");
	}
if ($in{'id'}) {
	# Show icons for server settings types
	print &ui_subheading($fpm_loc.substr($in{'id'}, 0, -1).'.conf');
	my @spages = ( "sdocs", "ssl", "fcgi", "sssi", "sgzip", "sproxy",
		       "saccess", "srewrite", );
	&icons_table(
		[ map { "edit_".$_.".cgi?id=".&urlize($in{'id'}) } @spages ],
		[ map { $text{$_."_title"} } @spages ],
		[ map { "images/".$_.".gif" } @spages ],
		);
		print &ui_columns_end();
		}
	else {
		print "<b>$text{'server_noneloc'}</b><p>\n";
		}

&ui_print_footer("", $text{'index_return'});
