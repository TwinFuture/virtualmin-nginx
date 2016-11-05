#!/usr/bin/perl
# Show other random options

use strict;
use warnings;
require 'virtualmin-nginx-lib.pl';
our (%text, %access);
my $parent = &get_config_parent();
my $events = &find("events", $parent);
my $http = &find("http", $parent);
$access{'global'} || &error($text{'index_eglobal'});

&ui_print_header(undef, $text{'misc_title'}, "");

print &ui_form_start("save_misc.cgi", "post");
print &ui_table_start($text{'misc_header'}, undef, 2);

print &nginx_user_input("user", $parent);

print &nginx_opt_input("worker_processes", $parent, 5);

print &nginx_opt_input("worker_priority", $parent, 5, $text{'misc_pri'},
		       $text{'misc_prisuffix'});

print &nginx_opt_input("index", $http, 60);

print &nginx_opt_input("default_type", $http, 20);

print &ui_table_end();
print &ui_form_end([ [ undef, $text{'save'} ] ]);

&ui_print_footer("", $text{'index_return'});
