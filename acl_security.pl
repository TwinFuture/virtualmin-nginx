
do 'virtualmin-nginx-lib.pl';
our (%in);

# acl_security_form(&options)
# Output HTML for editing security options for the acl module
sub acl_security_form
{
my ($o) = @_;

# Allowed virtual hosts
print &ui_table_row($text{'acl_vhosts'},
	&ui_radio("vhosts_def", $o->{'vhosts'} ? 0 : 1,
		  [ [ 1, $text{'acl_hosts1'} ],
		    [ 0, $text{'acl_hosts0'} ] ])."<br>\n".
	&ui_textarea("vhosts",
		     join("\n", split(/\s+/, $o->{'vhosts'})), 5, 30), 3);

# Can edit server settings?
print &ui_table_row($text{'acl_edit'},
	&ui_yesno_radio("edit", $o->{'edit'}));

# Can stop and start Nginx?
print &ui_table_row($text{'acl_stop'},
	&ui_yesno_radio("stop", $o->{'stop'}));

# Allowed directories for locations
print &ui_table_row($text{'acl_root'},
	&ui_textarea("root", $o->{'root'}, 60), 3);

# Can edit global settings?
print &ui_table_row($text{'acl_global'},
	&ui_yesno_radio("global", $o->{'global'}));

# Can edit log files?
print &ui_table_row($text{'acl_logs'},
	&ui_yesno_radio("logs", $o->{'logs'}));

# Write password files as user
print &ui_table_row($text{'acl_user'},
	&ui_user_textbox("user", $o->{'user'}));

}

# acl_security_save(&options)
# Parse the form for security options for the acl module
sub acl_security_save
{
my ($o) = @_;
$o->{'vhosts'} = $in{'vhosts_def'} ? ""
				   : join(" ", split(/\s+/, $in{'vhosts'}));
$o->{'edit'} = $in{'edit'};
$o->{'root'} = $in{'root'};
$o->{'global'} = $in{'global'};
$o->{'logs'} = $in{'logs'};
$o->{'user'} = $in{'user'};
$o->{'stop'} = $in{'stop'};
}

