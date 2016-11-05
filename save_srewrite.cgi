#!/usr/bin/perl
# Save virtual host rewrite options

use strict;
use warnings;
require 'virtualmin-nginx-lib.pl';
our (%text, %in, %access);
&lock_all_config_files();
&error_setup($text{'rewrite_err'});
&ReadParse();
my $server = &find_server($in{'id'});
$server || &error($text{'server_egone'});
&can_edit_server($server) || &error($text{'server_ecannot'});

&nginx_rewrite_parse("rewrite", $server);

&nginx_onoff_parse("rewrite_log", $server);

&flush_config_file_lines();
&unlock_all_config_files();
my $name = &find_value("server_name", $server);
&webmin_log("rewrite", "server", $name);
&redirect("edit_server.cgi?id=".&urlize($in{'id'}));

