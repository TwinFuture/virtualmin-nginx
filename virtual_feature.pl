# Virtualmin API plugins for Nginx

use strict;
use warnings;
use Time::Local;
use Socket;
require 'virtualmin-nginx-lib.pl';
our (%text, %config, $module_name, %access);

# feature_name()
# Returns a short name for this feature
sub feature_name
{
return $text{'feat_name'};
}

# feature_losing(&domain)
# Returns a description of what will be deleted when this feature is removed
sub feature_losing
{
return $text{'feat_losing'};
}

# feature_disname(&domain)
# Returns a description of what will be turned off when this feature is disabled
sub feature_disname
{
return $text{'feat_disname'};
}

# feature_label(in-edit-form)
# Returns the name of this feature, as displayed on the domain creation and
# editing form
sub feature_label
{
my ($edit) = @_;
return $edit ? $text{'feat_label2'} : $text{'feat_label'};
}

sub feature_hlink
{
return "label";
}

# feature_check()
# Checks if Nginx is actually installed, returns an error if not
sub feature_check
{
if (!-r $config{'nginx_config'}) {
	return &text('feat_econfig', "<tt>$config{'nginx_config'}</tt>");
	}
elsif (!&has_command($config{'nginx_cmd'})) {
	return &text('feat_ecmd', "<tt>$config{'nginx_cmd'}</tt>");
	}
else {
	return undef;
	}
}

# feature_depends(&domain)
# Nginx needs a Unix login for the domain
sub feature_depends
{
my ($d) = @_;
return $text{'feat_edepunix'} if (!$d->{'unix'} && !$d->{'parent'});
return $text{'feat_edepdir'} if (!$d->{'dir'} && !$d->{'alias'});
return $text{'feat_eapache'} if ($d->{'web'});
return undef;
}

# feature_clash(&domain, [field])
# Returns undef if there is no clash for this domain for this feature, or
# an error message if so
sub feature_clash
{
my ($d, $field) = @_;
if (!$field || $field eq 'dom') {
	my $s = &find_domain_server($d);
	return $text{'feat_clash'} if ($s);
	}
return undef;
}

# feature_suitable([&parentdom], [&aliasdom], [&subdom])
# Returns 1 if some feature can be used with the specified alias and
# parent domains
sub feature_suitable
{
my ($parentdom, $aliasdom, $subdom) = @_;
return $subdom ? 0 : 1;
}

# feature_import(domain-name, user-name, db-name)
# Returns 1 if this feature is already enabled for some domain being imported,
# or 0 if not
sub feature_import
{
my ($dname, $user, $db) = @_;
return &find_domain_server({ 'dom' => $dname }) ? 1 : 0;
}

# feature_setup(&domain)
# Called when this feature is added, with the domain object as a parameter
sub feature_setup
{
my ($d) = @_;

if (!$d->{'alias'}) {
	&lock_all_config_files();
	my $conf = &get_config();
	my $http = &find("http", $conf);

	# Pick ports
	my $tmpl = &virtual_server::get_template($d->{'template'});
	$d->{'web_port'} ||= $tmpl->{'web_port'} || 80;

	if ($d->{'virt6'}) {
		# Disable IPv6 default listen in default server
		foreach my $dserver (&find("server", $http)) {
			foreach my $l (&find("listen", $dserver)) {
				if ($l->{'words'}->[0] eq
				    "[::]:".$d->{'web_port'}) {
					my $name = &find_value("server_name",
							       $dserver);
					&$virtual_server::first_print(
					  &text('feat_setupdefault', $name));
					&save_directive($dserver, [ $l ], [ ]);
					&$virtual_server::second_print(
					  $virtual_server::text{'setup_done'});
					last;
					}
				}
			}
		}

	# Bump up server_names_hash if too low
	my $snh = &find_value("server_names_hash_bucket_size", $http);
	$snh ||= int(&get_default("server_names_hash_bucket_size"));
	if ($snh <= 32) {
		&save_directive($http, "server_names_hash_bucket_size",
				[ 128 ]);
		}

	# Create a whole new server
	&$virtual_server::first_print($text{'feat_setup'});
    
    # Add limit_zone_request for domain in nginx.conf
    if ($config{'add_to'})
    {
		my $limit_zone = { 'name' => 'limit_req_zone',
    		'words' => [ '$binary_remote_addr', 'zone='.$d->{'dom'}.':10m', 'rate=2r/s' ] };
    	$limit_zone->{'file'} = &get_add_to_file($d->{'dom'});
        &save_directive($http, [ ], [ $limit_zone ]);
    }
    
    # Create the server object
	my $server = { 'name' => 'server',
                   'type' => 1,
                   'words' => [ ],
                   'members' => [ ] };
    $server->{'file'} = &get_add_to_file($d->{'dom'});
    
	push(@{$server->{'members'}},
		{ 'name' => 'server_name',
		  'words' => [ $d->{'dom'} ] });

	# Add listen on the correct IP and port
	my $portstr = $d->{'web_port'} == 80 ? '' : ':'.$d->{'web_port'};
	push(@{$server->{'members'}},
		{ 'name' => 'listen',
		  'words' => [ $d->{'ip'}.$portstr ] });
	if ($d->{'ip6'}) {
		push(@{$server->{'members'}},
			{ 'name' => 'listen',
			  'words' => [ '['.$d->{'ip6'}.']'.$portstr,
				       'default', 'ipv6only=on' ] });
		}
	
	# Add log files
	my $alog = &virtual_server::get_apache_template_log($d, 0);
	push(@{$server->{'members'}},
                { 'name' => 'access_log',
		  'words' => [ $alog, 'main' ] });
	my $elog = &virtual_server::get_apache_template_log($d, 1);
	push(@{$server->{'members'}},
                { 'name' => 'error_log',
		  'words' => [ $elog ] });
          
    # Add a 301 redirect all non www to www.
	push(@{$server->{'members'}},
	{ 'name' => 'return',
		  'words' => [ '301', 'http://www.'.$d->{'dom'}.'$request_uri' ] });
	
    # 2nd server block.
	my $server1 = { 'name' => 'server',
                       'type' => 1,
                       'words' => [ ],
                       'members' => [ ] };
    $server1->{'file'} = &get_add_to_file($d->{'dom'});
    
    push(@{$server1->{'members'}},
	{ 'name' => 'client_body_timeout',
		  'words' => [ '10' ] });
    
    push(@{$server1->{'members'}},
	{ 'name' => 'client_header_timeout',
		  'words' => [ '10' ] });
          
    push(@{$server1->{'members'}},
	{ 'name' => 'send_timeout',
		  'words' => [ '10' ] });
          
    push(@{$server1->{'members'}},
	{ 'name' => 'client_body_buffer_size',
		  'words' => [ '16k' ] });
          
    push(@{$server1->{'members'}},
	{ 'name' => 'client_header_buffer_size',
		  'words' => [ '16k' ] });
          
    push(@{$server1->{'members'}},
	{ 'name' => 'large_client_header_buffers',
		  'words' => [ '4', '2k' ] });
          
    push(@{$server1->{'members'}},
	{ 'name' => 'client_max_body_size',
		  'words' => [ '26m' ] });
    
    push(@{$server1->{'members'}},
	{ 'name' => 'fastcgi_read_timeout',
		  'words' => [ '90' ] });

    # Add domain name field
	push(@{$server1->{'members'}},
		{ 'name' => 'server_name',
		  'words' => [ 'www.'.$d->{'dom'} ] });
	
	# Add listen on the correct IP and port
	push(@{$server1->{'members'}},
		{ 'name' => 'listen',
		  'words' => [ $d->{'ip'}.$portstr ] });
	if ($d->{'ip6'}) {
		push(@{$server1->{'members'}},
			{ 'name' => 'listen',
			  'words' => [ '['.$d->{'ip6'}.']'.$portstr,
				       'default', 'ipv6only=on' ] });
		}
    
    # Add log files
	push(@{$server1->{'members'}},
                { 'name' => 'access_log',
		  'words' => [ $alog, 'main' ] });
	push(@{$server1->{'members'}},
                { 'name' => 'error_log',
		  'words' => [ $elog ] });

	# Add location block.
    push(@{$server1->{'members'}},
	 	{ 'name' => 'location',
	 	  'words' => [ '=', '/' ],
	 	  'type' => 1,
	 	  'members' => [
	 		{ 'name' => 'root',
	 		  'words' => [ &virtual_server::public_html_dir($d) ],
            },
            { 'name' => 'index',
	          'words' => [ 'index.html', 'index.htm', 'index.php' ] 
            },
            { 'name' => 'try_files',
	          'words' => [ '$uri', '$uri/', '/index.php?$args' ] 
            },
	 	   ],
	 	});
          
    # Add a location for the root
	push(@{$server1->{'members'}},
	 	{ 'name' => 'location',
	 	  'words' => [ '~*', '\.(html|jpg|jpeg|gif|png|ico|css|zip|tgz|gz|rar|bz2|doc|xls|exe|pdf|ppt|txt|tar|mid|midi|wav|bmp|rtf|js)$' ],
	 	  'type' => 1,
	 	  'members' => [
	 		{ 'name' => 'root',
	 		  'words' => [ &virtual_server::public_html_dir($d) ],
            },
            { 'name' => 'expires',
	 	      'words' => [ '360d' ],
            },
            { 'name' => 'access_log',
	 	      'words' => [ 'off' ],
            },
	 	      # { 'name' => 'if',
	 	      # 'type' => 1,
	 	      # 'words' => [ '($http_user_agent', '~*', '"Yandex|Google|Yahoo|Bing|Bingbot|Googlebot")' ],
	 	      # 'members' => [ 
	 	      # { 'name' => '##testcookie',
	 	      # 'words' => [ 'off' ],
	 	      # },
	 	      # ],
	 	      # },
	 	   ],
	 	});
    
    # 405 html page
    push(@{$server1->{'members'}},
	{ 'name' => 'error_page',
		  'words' => [ '445', '/445.html' ] });
          
    # 445 html page.
    push(@{$server1->{'members'}},
	 	{ 'name' => 'location',
	 	  'words' => [ '=', '/445.html' ],
	 	  'type' => 1,
	 	  'members' => [
	 		{ 'name' => 'root',
	 		  'words' => [ &virtual_server::public_html_dir($d) ],
            },
	 	   ],
	 	});
     
    # 50x error page.
    push(@{$server1->{'members'}},
	{ 'name' => 'error_page',
		  'words' => [ '500', '502', '503', '504', '/50x.html' ] });
          
    push(@{$server1->{'members'}},
	 	{ 'name' => 'location',
	 	  'words' => [ '=', '/50x.html' ],
	 	  'type' => 1,
	 	  'members' => [
	 		{ 'name' => 'root',
	 		  'words' => [ &virtual_server::public_html_dir($d) ],
            },
	 	   ],
	 	});
        
    # Get default php version and file path.
    my ($ver, $cmd) = &get_default_php_version();
    my $srcini = &virtual_server::get_global_php_ini($ver, 'fcgi');
    # Get default location of php-fpm.conf
    my $fpm_loc = &php_fpm_loc($srcini).'/';  
	my $localip = &to_ipaddress('localhost');
    my $phppass;
    my $listen;
    # if using php-fpm.
    if ($config{'php_fpm'}) {
    	# TCP
        if (!$config{'php_socket'}) {
        	my $portnum = &fpm_port($d);
        	$phppass = $localip.':'.$portnum;
            $listen = $phppass;
            $d->{'nginx_php_port'} = $portnum;
        # Sockets.
        } else {
        	$phppass = 'unix:'.&fpm_sock_loc($srcini).'/'.$d->{'dom'}.'.sock';
            $listen = &fpm_sock_loc($srcini).'/'.$d->{'dom'}.'.sock';
            $d->{'nginx_php_port'} = $listen;
        }
    # Using fastcgi.
    } else {
		&$virtual_server::first_print($text{'feat_phpfcgid'});
		$d->{'nginx_php_children'} = $config{'child_procs'} ||
		$tmpl->{'web_phpchildren'} || 1;
        # This function sets up php.ini for the domain. This has to be done
        # first to create the .ini files used by the PHP server process
        &virtual_server::save_domain_php_mode($d, "fcgid");
        
		if (!$config{'php_socket'}) {
        	my $portnum = &fpm_port($d);
        	$phppass = $localip.':'.$portnum;
            $listen = $phppass;
            $d->{'nginx_php_port'} = $portnum;
        } else {
        	# Setup fcgi server.
        	my ($ok, $port) = &setup_php_fcgi_server($d);
        	if ($ok) {
            	$phppass = 'unix:'.$port;
            	$listen = $port;
                $d->{'nginx_php_port'} = $port;
				&$virtual_server::second_print($virtual_server::text{'setup_done'});
			} else {
				delete($d->{'nginx_php_port'});
				&$virtual_server::second_print(&text('feat_failed', $port));
			}
        }    
    }
    push(@{$server1->{'members'}},
	 	{ 'name' => 'location',
	 	  'words' => [ '~', '\.php$' ],
	 	  'type' => 1,
	 	  'members' => [
            { 'name' => 'limit_req',
	 		  'words' => [ 'zone='.$d->{'dom'}, 'burst=6' ],
            },
	 		{ 'name' => 'root',
	 		  'words' => [ &virtual_server::public_html_dir($d) ],
            },
            { 'name' => 'try_files',
	 	      'words' => [ '$uri', '=404' ],
            },
            { 'name' => 'fastcgi_index',
	 	      'words' => [ 'index.php' ],
            },
            { 'name' => 'fastcgi_param',
	 	      'words' => [ 'SCRIPT_FILENAME', &virtual_server::public_html_dir($d).'$fastcgi_script_name' ],
            },
            { 'name' => 'fastcgi_param',
	 	      'words' => [ 'PHP_VALUE', '"error_log='.$elog.'"' ],
            },
            { 'name' => 'include',
	 	      'words' => [ 'fastcgi_params' ],
            },
	 	      { 'name' => 'if',
	 	        'type' => 1,
	 	        'words' => [ '-f', '$request_filename' ],
	 	        'members' => [ 
	 	        { 'name' => 'fastcgi_pass',
	 	          'words' => [ $phppass ],
	 	        },
	 	        ],
	 	      },
	 	   ],
	 	});
          
    push(@{$server1->{'members'}},
	 	{ 'name' => 'location',
	 	  'words' => [ '~', '/\.ht' ],
	 	  'type' => 1,
	 	  'members' => [
	 		{ 'name' => 'deny',
	 		  'words' => [ 'all' ],
            },
	 	   ],
	 	});
        
    push(@{$server1->{'members'}},
	 	{ 'name' => 'location',
	 	  'words' => [ '=', '/favicon.ico' ],
	 	  'type' => 1,
	 	  'members' => [
	 		{ 'name' => 'log_not_found',
	 		  'words' => [ 'off' ],
            },
            { 'name' => 'access_log',
	 		  'words' => [ 'off' ],
            },
	 	   ],
	 	});
    
    push(@{$server1->{'members'}},
	 	{ 'name' => 'location',
	 	  'words' => [ '=', '/robots.txt' ],
	 	  'type' => 1,
	 	  'members' => [
            { 'name' => 'allow',
	 		  'words' => [ 'all' ],
            },
	 		{ 'name' => 'log_not_found',
	 		  'words' => [ 'off' ],
            },
            { 'name' => 'access_log',
	 		  'words' => [ 'off' ],
            },
	 	   ],
	 	});
        
	# Add custom directives
	if ($config{'extra_dirs'}) {
		my $temp = &transname();
		my $fh = "EXTRA";
		&open_tempfile($fh, ">$temp", 0, 1);
		&print_tempfile($fh, 
			join("\n", split(/\t+/, $config{'extra_dirs'}))."\n");
		&close_tempfile($fh);
		my $econf = &read_config_file($temp);
		&recursive_clear_lines(@$econf);
		push(@{$server->{'members'}}, @$econf);
		&unlink_file($temp);
		}
    
    # Save server blocks in the right order depending if creating new file or inside nginx.conf
    if ($config{'add_to'}) 
    {
    	&save_directive($http, [ ], [ $server1 ]);
        # Subdomain
    	if ($d->{'dom'} =~ /.*[\.].*[\.]/) {
        } else {
        	&save_directive($http, [ ], [ $server ]);
        }
    } else {
    	if ($d->{'dom'} =~ /.*[\.].*[\.]/) {
        } else {
        	&save_directive($http, [ ], [ $server ]);
        }
    	&save_directive($http, [ ], [ $server1 ]);
        my $params1 = {};
    	$params1->{'file'} = $config{'nginx_config'};
        my @p = &find("http", $params1);
		push(@p, { 'name' => 'limit_req_zone',
			   'words' => [ '$binary_remote_addr', 'zone='.$d->{'dom'}.':10m', 'rate=2r/s' ] });     
        &save_directive($http, [ ], \@p);
    }
	&flush_config_file_lines();
	&unlock_all_config_files();
	&create_server_link($server);
	&virtual_server::setup_apache_logs($d, $alog, $elog);
	&virtual_server::link_apache_logs($d, $alog, $elog);
	&virtual_server::register_post_action(\&print_apply_nginx);
	$d->{'proxy_pass_mode'} ||= 0;
	$d->{'proxy_pass'} ||= "";
	if ($d->{'proxy_pass_mode'}) {
		&setup_nginx_proxy_pass($d);
		}
	&$virtual_server::second_print($virtual_server::text{'setup_done'});
    ######## SET UP PHP-FPM ########
    &lock_all_config_files();
    &$virtual_server::first_print($text{'feat_setup_fpm'});
		
    # Creates an PHP-FPM config file for domain.
    &create_fpm_conf($fpm_loc, $d);
    # Edit values in domains PHP-FPM file.
    &foreign_require("phpini");
    # Clear any caching on file
	&unflush_file_lines($fpm_loc.$d->{'dom'}.'.conf');
	undef($phpini::get_config_cache{$fpm_loc.$d->{'dom'}.'.conf'});
    # Get config.
	my $pconf = &phpini::get_config($fpm_loc.$d->{'dom'}.'.conf');
	# Set default values for domain
	&phpini::save_directive($pconf, 'user', $d->{'user'});
    &phpini::save_directive($pconf, 'group', 'nginx');        
    &phpini::save_directive($pconf, 'listen', $listen);
    &phpini::save_directive($pconf, 'listen.owner', 'nginx');
    &phpini::save_directive($pconf, 'listen.group', 'nginx');
    &phpini::save_directive($pconf, 'listen.allowed_clients', $localip);
    # Get old session path and append the domain to it.
    # Check config session path and wsdl for domain name so we don't insert the values twice.
    my $sesspath = &phpini::find_value('php_value[session.save_path]', $pconf);
	if (index($sesspath, $d->{'dom'}) == -1) { 
  		&phpini::save_directive($pconf, 'php_value[session.save_path]', $sesspath.'.'.$d->{'dom'});
	}        
    # Same with wsdl cache.
    # to do set permissions for nginx and user.
    my $wsdl = &phpini::find_value('php_value[soap.wsdl_cache_dir]', $pconf);
    if (index($wsdl, $d->{'dom'}) == -1) {
       	&phpini::save_directive($pconf, 'php_value[soap.wsdl_cache_dir]', $wsdl.'.'.$d->{'dom'});
    }
    # Set SElinux rules to access home dir and error and access logs for domain.
    &backquote_logged("chcon -t httpd_sys_rw_content_t $alog -R 2>&1 </dev/null");
    &backquote_logged("chcon -t httpd_sys_rw_content_t $elog -R 2>&1 </dev/null");
    my $homedir = $d->{'home'};
    &backquote_logged("chcon -t httpd_sys_content_t $homedir -R 2>&1 </dev/null");

    ## Apply PHP-FPM configuration.
    &virtual_server::register_post_action(\&print_apply_fpm);
        
    # Setup cache directories and permissions for php-fpm.
    my $nuser = &get_nginx_user();
    my $scache = $sesspath.'.'.$d->{'dom'};
    if (!-d $scache) {
       	&make_dir($scache, 0770);
        &set_ownership_permissions($d->{'user'}, $nuser, undef, $scache);
    }
        
    my $wcache = $wsdl.'.'.$d->{'dom'};
    if (!-d $wcache) {
    	&make_dir($wcache, 0770);
        &set_ownership_permissions($d->{'user'}, $nuser, undef, $wcache);
    }
        
    # Set default values for domain
    &flush_file_lines($fpm_loc.$d->{'dom'}.'.conf');
	&unlock_all_config_files();

	## Reserved function for editing a single value for later use.
    #&edit_fpm_config($fpm_loc.$d->{'dom'}.'.conf', 'user', 'nginx');

    # Chanege pool name from [www] to [user].
    &change_pool_name($fpm_loc.$d->{'dom'}.'.conf', $d->{'user'});
    &$virtual_server::second_print($virtual_server::text{'setup_done'});

	# Add the user nginx runs as to the domain's group
	my $web_user = &get_nginx_user();
	if ($web_user && $web_user ne 'none') {
		&virtual_server::add_user_to_domain_group($d, $web_user, 'setup_webuser');
	}

	# Create empty log files and make them writable by Nginx and
	# the domain owner
	foreach my $l ($alog, $elog) {
		my $fh = "LOG";
		&open_tempfile($fh, ">>$l", 0, 1);
		&close_tempfile($fh);
		&set_nginx_log_permissions($d, $l);
	}

	return 1;
	}
else {
	# Add to existing one as an alias
	&$virtual_server::first_print($text{'feat_setupalias'});
	&lock_all_config_files();
	my $target = &virtual_server::get_domain($d->{'alias'});
	my $server = &find_domain_server($target);
	if (!$server) {
		&unlock_all_config_files();
		&$virtual_server::second_print(
			&text('feat_efind', $target->{'dom'}));
		return 0;
		}

	my $obj = &find("server_name", $server);
	foreach my $n (&domain_server_names($d)) {
		if (&indexoflc($n, @{$obj->{'words'}}) < 0) {
			push(@{$obj->{'words'}}, $n);
			}
		}
	&save_directive($server, "server_name", [ $obj ]);

	$d->{'web_port'} = 80;
	&flush_config_file_lines();
	&unlock_all_config_files();
	&virtual_server::register_post_action(\&print_apply_nginx);

	&$virtual_server::second_print($virtual_server::text{'setup_done'});
	return 1;
	}
}

sub find_server_count
{
my ($d) = @_;
my @rv;
my $conf = &get_config();
my $http = &find("http", $conf);
return undef if (!$http);
my @servers = &find("server", $http);
foreach my $s (@servers) {
	my $obj = &find("server_name", $s);
	foreach my $name (@{$obj->{'words'}}) {
		if (lc($name) eq lc($d->{'dom'}) ||
		    lc($name) eq "www.".lc($d->{'dom'}) ||
		    lc($name) eq "*.".lc($d->{'dom'})) {
			push(@rv, $s);
			}
		}
	}
return (@rv);
}

sub feature_modify
{
my ($d, $oldd) = @_;

# Special case - converting an alias domain into a non-alias. Just delete and
# re-create
if ($oldd->{'alias'} && !$d->{'alias'}) {
	&feature_delete($oldd);
	&feature_setup($d);
	return 1;
	}

if (!$d->{'alias'}) {
	# Changing a real virtual host
	&lock_all_config_files();
	my $changed = 0;
	my $old_alog = &get_nginx_log($oldd, 0);
	my $old_elog = &get_nginx_log($oldd, 1);

	# Update domain name in server_name
	if ($d->{'dom'} ne $oldd->{'dom'}) {
		&$virtual_server::first_print($text{'feat_modifydom'});
        my $fpm_loc = $config{'php_fpm_loc'}.'/';
        # Change username in domains php-fpm conf.
        &foreign_require("phpini");
    	# Clear any caching on file
		&unflush_file_lines($fpm_loc.$oldd->{'dom'}.'.conf');
		undef($phpini::get_config_cache{$fpm_loc.$oldd->{'dom'}.'.conf'});
    	# Get config.
		my $pconf = &phpini::get_config($fpm_loc.$oldd->{'dom'}.'.conf');
       
        if ($config{'php_socket'}) {
        	my $listen = $config{'php_fpm_socks'}.'/'.$d->{'dom'}.'.sock';
            &phpini::save_directive($pconf, 'listen', $listen);
        }
        
        #Update session paths for domain.
        my $sesspath = &phpini::find_value('php_value[session.save_path]', $pconf);
        my $oldv = $oldd->{'dom'};
        my $newv = $d->{'dom'};
        my $nuser = &get_nginx_user();
        if ($sesspath =~ /\Q$oldv\E/) {
        	my $oldpath = $sesspath;
			$sesspath =~ s/\Q$oldv\E/$newv/g;
            &phpini::save_directive($pconf, 'php_value[session.save_path]', $sesspath);
            &rename_logged($oldpath, $sesspath);
		}

        my $wsdl = &phpini::find_value('php_value[soap.wsdl_cache_dir]', $pconf);
        if ($wsdl =~ /\Q$oldv\E/) {
        	my $oldwsdl = $wsdl;
			$wsdl =~ s/\Q$oldv\E/$newv/g;
            &phpini::save_directive($pconf, 'php_value[soap.wsdl_cache_dir]', $wsdl);
            &rename_logged($oldwsdl, $wsdl);
		}
		&flush_file_lines($fpm_loc.$oldd->{'dom'}.'.conf');
        
        #rename config file for php-fpm.
        &rename_logged($fpm_loc.$oldd->{'dom'}.'.conf', $fpm_loc.$d->{'dom'}.'.conf');
        
        # search nginx.conf for domain name to change for example in limit_zone_request.
        # Rmemove limit_zone_request for domain in nginx.conf.
        my $conf = &get_config();
        my @http = &find("http", $conf);
        foreach my $f (@http)
        {
        	&recursive_change_directives($f, $oldd->{'dom'}, $d->{'dom'}, 0, 0, 1);
        }
        # Get number of server blocks
        my @numserv = &find_server_count($d);
		# Loop through server blocks
        foreach my $server (@numserv) {
			if (!$server) {
				&$virtual_server::second_print(
					&text('feat_efind', $oldd->{'dom'}));
				return 0;
			}
        	&recursive_change_directives($server, $oldd->{'dom'}, $d->{'dom'}, 0, 0, 1);
            &$virtual_server::second_print($virtual_server::text{'setup_done'});
			$changed++;
        }
 	}    

	# Update home directory in all directives
	if ($d->{'home'} ne $oldd->{'home'}) {
		&$virtual_server::first_print($text{'feat_modifyhome'});
        # Get number of server blocks
        my @numserv = &find_server_count($d);
        # Loop through server blocks
        foreach my $server (@numserv) {
			if (!$server) {
				&$virtual_server::second_print(
					&text('feat_efind', $d->{'dom'}));
				return 0;
			}
            
			&recursive_change_directives($server, $oldd->{'home'}, $d->{'home'}, 0, 0, 0);
			&recursive_change_directives($server, $oldd->{'home'}.'/', $d->{'home'}.'/', 0, 1,0);
			&$virtual_server::second_print($virtual_server::text{'setup_done'});
			$changed++;
		}
  	}

	# Update IPv4 address
	if ($d->{'ip'} ne $oldd->{'ip'}) {
		&$virtual_server::first_print($text{'feat_modifyip'});
		my @numserv = &find_server_count($d);
        # Loop through server blocks
        foreach my $server (@numserv) {
		if (!$server) {
			&$virtual_server::second_print(
				&text('feat_efind', $d->{'dom'}));
			return 0;
			}
		my @listen = &find("listen", $server);
		foreach my $l (@listen) {
			if ($l->{'words'}->[0] eq $oldd->{'ip'}) {
				$l->{'words'}->[0] = $d->{'ip'};
				}
			elsif ($l->{'words'}->[0] =~ /^(\S+):(\d+)$/ &&
			       $1 eq $oldd->{'ip'}) {
				$l->{'words'}->[0] = $d->{'ip'}.":".$2;
				}
			}
		&save_directive($server, "listen", \@listen);

		# Remove IP in server_names
		my $obj = &find("server_name", $server);
		my $idx = &indexof($oldd->{'ip'}, @{$obj->{'words'}});
		if ($idx >= 0) {
			splice(@{$obj->{'words'}}, $idx, 0);
			&save_directive($server, "server_name", [ $obj ]);
			}

		&$virtual_server::second_print(
			$virtual_server::text{'setup_done'});
		$changed++;
		}
    }

	# Update IPv6 address (or add or remove)
	if (($d->{'ip6'} || "") ne ($oldd->{'ip6'} || "") ||
	    ($d->{'virt6'} || 0) ne ($oldd->{'virt6'} || 0)) {
		&$virtual_server::first_print($text{'feat_modifyip6'});
		my @numserv = &find_server_count($d);
        # Loop through server blocks
        foreach my $server (@numserv) {
		if (!$server) {
			&$virtual_server::second_print(
				&text('feat_efind', $d->{'dom'}));
			return 0;
			}
		my @listen = &find("listen", $server);
		my @newlisten;
		my $ob = $oldd->{'ip6'} ? "[".$oldd->{'ip6'}."]" : "";
		my $nb = $d->{'ip6'} ? "[".$d->{'ip6'}."]" : "";
		foreach my $l (@listen) {
			my @w = @{$l->{'words'}};
			if ($ob && $w[0] eq $ob) {
				# Found old address with no port - replace
				# or remove
				if ($nb) {
					$w[0] = $nb;
					push(@newlisten, { 'words' => \@w });
					}
				}
			elsif ($ob && $w[0] =~ /^\Q$ob\E:(\d+)$/) {
				# Found old address with a port - replace with
				# same port or remove
				if ($nb) {
					$w[0] = $nb.":".$1;
					push(@newlisten, { 'words' => \@w });
					}
				}
			else {
				# Found un-related address, save it
				push(@newlisten, { 'words' => \@w });
				}
			}
		if ($d->{'ip6'} && !$oldd->{'ip6'}) {
			push(@newlisten, { 'words' => [ $nb ] });
			}
		&save_directive($server, "listen", \@newlisten);
		&$virtual_server::second_print(
			$virtual_server::text{'setup_done'});
		$changed++;
		}
    }

	# Update port, if changed
	if ($d->{'web_port'} != $oldd->{'web_port'}) {
		&$virtual_server::first_print($text{'feat_modifyport'});
		my @numserv = &find_server_count($d);
        # Loop through server blocks
        foreach my $server (@numserv) {
		if (!$server) {
			&$virtual_server::second_print(
				&text('feat_efind', $d->{'dom'}));
			return 0;
			}
		my @listen = &find("listen", $server);
		my @newlisten;
		foreach my $l (@listen) {
			my @w = @{$l->{'words'}};
			my $p = $w[0] =~ /:(\d+)$/ ? $1 : 80;
			if ($p == $oldd->{'web_port'}) {
				$w[0] =~ s/:\d+$//;
				$w[0] .= ":".$d->{'web_port'}
					if ($d->{'web_port'} != 80);
				}
			push(@newlisten, { 'words' => \@w });
			}
		&save_directive($server, "listen", \@newlisten);
		&$virtual_server::second_print(
			$virtual_server::text{'setup_done'});
		$changed++;
		}
    }

	# Update proxy settings if needed
	if ($d->{'proxy_pass_mode'} ne $oldd->{'proxy_pass_mode'} ||
	    $d->{'proxy_pass'} ne $oldd->{'proxy_pass'}) {
		&$virtual_server::first_print($text{'feat_modifyproxy'});
		&remove_nginx_proxy_pass($oldd);
		&setup_nginx_proxy_pass($d);
		&$virtual_server::second_print(
			$virtual_server::text{'setup_done'});
		}

	# Rename log files if needed
	my $new_alog = &virtual_server::get_apache_template_log($d, 0);
	my $new_elog = &virtual_server::get_apache_template_log($d, 1);
	if ($old_alog ne $new_alog) {
		&$virtual_server::first_print($text{'feat_modifylog'});
		my $server = &find_domain_server($d);
		if (!$server) {
			&$virtual_server::second_print(
				&text('feat_efind', $oldd->{'dom'}));
			return 0;
			}
		&feature_change_web_access_log($d, $new_alog);
		&rename_logged($old_alog, $new_alog);
		if ($old_elog ne $new_elog) {
			&feature_change_web_error_log($d, $new_elog);
			&rename_logged($old_elog, $new_elog);
			}
		&virtual_server::link_apache_logs($d, $new_alog, $new_elog);
		&$virtual_server::second_print(
			$virtual_server::text{'setup_done'});
		}

	# Flush files and restart
	&flush_config_file_lines();
	&unlock_all_config_files();
	if ($changed) {
		&virtual_server::register_post_action(\&print_apply_nginx);
        &virtual_server::register_post_action(\&print_apply_fpm);
	}

	# Update fcgid user, by tearing down and re-running. Killing needs to
	# be done in the new home, as it may have been moved already
    if (!$config{'php_fpm'}) {
		if ($d->{'user'} ne $oldd->{'user'} ||
	    $d->{'home'} ne $oldd->{'home'}) {
			&$virtual_server::first_print($text{'feat_modifyphp'});
			my $oldd_copy = { %$oldd };
			$oldd_copy->{'home'} = $d->{'home'};
			&delete_php_fcgi_server($oldd_copy);
			&delete_php_fcgi_server($oldd);
			&setup_php_fcgi_server($d);
			&$virtual_server::second_print(
				$virtual_server::text{'setup_done'});
		}
	}
    
	# Update owner of log files also apply edits to domains php-fpm conf.
	if ($d->{'user'} ne $oldd->{'user'}) {
		my $alog = &virtual_server::get_apache_template_log($d, 0);
		my $elog = &virtual_server::get_apache_template_log($d, 1);

        my $fpm_loc = $config{'php_fpm_loc'}.'/';
        &change_pool_name($fpm_loc.$d->{'dom'}.'.conf', $d->{'user'});
        # Change username in domains php-fpm conf.
        &foreign_require("phpini");
    	# Clear any caching on file
		&unflush_file_lines($fpm_loc.$d->{'dom'}.'.conf');
		undef($phpini::get_config_cache{$fpm_loc.$d->{'dom'}.'.conf'});
    	# Get config.
		my $pconf = &phpini::get_config($fpm_loc.$d->{'dom'}.'.conf');
		# Set default values for domain
        # Find sessionpath folders to change user permissionm.
        my $sesspath = &phpini::find_value('php_value[session.save_path]', $pconf);
        # Find wsdl folders to change user permissionm.
        my $wsdl = &phpini::find_value('php_value[soap.wsdl_cache_dir]', $pconf);
		&phpini::save_directive($pconf, 'user', $d->{'user'});
        my $nuser = &get_nginx_user();
        &set_ownership_permissions($d->{'user'}, $nuser, undef, $wsdl);
        &set_ownership_permissions($d->{'user'}, $nuser, undef, $sesspath);
        &flush_file_lines($fpm_loc.$d->{'dom'}.'.conf');
		foreach my $l ($alog, $elog) {
        	&set_ownership_permissions($d->{'user'}, $nuser, undef, $l);
		}
	}

	# Rename config file name, if changed
	if ($d->{'dom'} ne $oldd->{'dom'}) {
		my $newfile = &get_add_to_file($d->{'dom'});
		my $server = &find_domain_server($d);
		if ($server->{'file'} ne $newfile &&
		    $server->{'file'} =~ /\Q$oldd->{'dom'}\E/) {
			&$virtual_server::first_print($text{'feat_modifyfile'});
			&delete_server_link($server);
			&rename_logged($server->{'file'}, $newfile);
			$server->{'file'} = $newfile;
			&create_server_link($server);
			&flush_config_cache();
			&$virtual_server::second_print(
				$virtual_server::text{'setup_done'});
			}
		}
	
	# Add Nginx user to the group for the new domain
	if ($d->{'user'} ne $oldd->{'user'}) {
		my $web_user = &get_nginx_user();
		if ($web_user && $web_user ne 'none') {
			&virtual_server::add_user_to_domain_group(
				$d, $web_user, 'setup_webuser');
			}
		}
	if (!$config{'php_fpm'}) {
		if ($d->{'home'} ne $oldd->{'home'}) {
			# Update session dir and upload path in php.ini files
			my @fixes = (
                  [ "session.save_path", $oldd->{'home'}, $d->{'home'}, 1 ],
                  [ "upload_tmp_dir", $oldd->{'home'}, $d->{'home'}, 1 ],
            );
            &virtual_server::fix_php_ini_files($d, \@fixes);
		}
    }
} else {
	# Changing inside an alias
	&lock_all_config_files();
	my $changed = 0;

	# Change domain name in alias target
	if ($d->{'dom'} ne $oldd->{'dom'}) {
		&$virtual_server::first_print($text{'feat_modifyalias'});
		my $target = &virtual_server::get_domain($d->{'alias'});
		my $server = &find_domain_server($target);
		if (!$server) {
			&unlock_all_config_files();
			&$virtual_server::second_print(
				&text('feat_efind', $target->{'dom'}));
			return 0;
			}
		my $obj = &find("server_name", $server);
		foreach my $n (&domain_server_names($oldd)) {
			@{$obj->{'words'}} = grep { $_ ne $n }
						  @{$obj->{'words'}};
			}
		foreach my $n (&domain_server_names($d)) {
			push(@{$obj->{'words'}}, $n);
			}
		my $oldstar = &indexof("*.".$oldd->{'dom'}, @{$obj->{'words'}});
		if ($oldstar >= 0) {
			$obj->{'words'}->[$oldstar] = "*.".$d->{'dom'};
			}
		&save_directive($server, "server_name", [ $obj ]);
		$changed++;
		&$virtual_server::second_print(
			$virtual_server::text{'setup_done'});
		}

	# Flush files and restart
	&flush_config_file_lines();
	&unlock_all_config_files();
	if ($changed) {
		&virtual_server::register_post_action(\&print_apply_nginx);
		}

	}
}

# feature_delete(&domain)
# Remove the Nginx virtual host for a domain
sub feature_delete
{
my ($d) = @_;

if (!$d->{'alias'}) {
	# Remove the whole server
	&$virtual_server::first_print($text{'feat_delete'});
	&lock_all_config_files();
	my $server = &find_domain_server($d);
	if (!$config{'add_to'}) {
    	my $conf = &get_config();
		my $http = &find("http", $conf);
		# Remove limit req zone from nginx.conf.
    	my @zone = &find_recursive("limit_req_zone", $http);
		my $changed;
    	my $oldv = $d->{'dom'};

		foreach my $j (@zone) {
    		if ($j->{'words'}->[1] =~ /\Q$oldv\E/) {
				&save_directive($http, [ $j ], [ ]);
			}
    	}
    
		my @numserv = &find_server_count($d);
		# Loop through server blocks
    	foreach my $servn (@numserv) {
			if (!$servn) {
				&$virtual_server::second_print(
					&text('feat_efind', $d->{'dom'}));
				return 0;
			}
    		&save_directive($http, [ $servn ], [ ]);
    	}
    
		&flush_config_file_lines();
		&unlock_all_config_files();
    }
	&delete_server_link($server);
	&delete_server_file_if_empty($server);
    if ($config{'add_to'}) {
    	&unlink_logged($server->{'file'});
    	&unlink_logged($server->{'file'}.'.lock');
    }
    if (!$config{'php_fpm'}) {
		&delete_php_fcgi_server($d);
   	}
	&virtual_server::register_post_action(\&print_apply_nginx);
	&$virtual_server::second_print($virtual_server::text{'setup_done'});
	
	#rmemove all the php-fpm stuff.
    &$virtual_server::second_print($virtual_server::text{'feat_delete_fpm'});
	my $fpm_loc = $config{'php_fpm_loc'}.'/';
    &foreign_require("phpini");
    # Clear any caching on file
	&unflush_file_lines($fpm_loc.$d->{'dom'}.'.conf');
	undef($phpini::get_config_cache{$fpm_loc.$d->{'dom'}.'.conf'});
    # Get config.
	my $pconf = &phpini::get_config($fpm_loc.$d->{'dom'}.'.conf');
    #Update session paths for domain.
    my $sesspath = &phpini::find_value('php_value[session.save_path]', $pconf);
	my $wsdl = &phpini::find_value('php_value[soap.wsdl_cache_dir]', $pconf);
    &unlink_file($sesspath);
    &unlink_file($wsdl);
	&unlink_file($fpm_loc.$d->{'dom'}.'.conf');
    ## Apply configuration. May return error if no hosts left.
    &virtual_server::register_post_action(\&print_apply_fpm);
    &$virtual_server::second_print($virtual_server::text{'setup_done'});
    # end of removing php-fpm stuff
    my $alog = &virtual_server::get_apache_template_log($d, 0);
	my $elog = &virtual_server::get_apache_template_log($d, 1);
	# Remove log files too, if outside home
    &$virtual_server::first_print($text{'feat_deletelogs'});
	if ($alog) {
		&unlink_file($alog);
	}
    if ($elog) {
		&unlink_file($elog);
	}
    &$virtual_server::second_print($virtual_server::text{'setup_done'});

	return 1;
	}
else {
	# Delete from alias
	&$virtual_server::first_print($text{'feat_deletealias'});
	&lock_all_config_files();
	my $target = &virtual_server::get_domain($d->{'alias'});
	my $server = &find_domain_server($target);
	if (!$server) {
		&unlock_all_config_files();
		&$virtual_server::second_print(
			&text('feat_efind', $target->{'dom'}));
		return 0;
		}

	my $obj = &find("server_name", $server);
	foreach my $n (&domain_server_names($d), "*.".$d->{'dom'}) {
		@{$obj->{'words'}} = grep { $_ ne $n } @{$obj->{'words'}};
		}
	&save_directive($server, "server_name", [ $obj ]);

	&flush_config_file_lines();
	&unlock_all_config_files();
	&virtual_server::register_post_action(\&print_apply_nginx);

	&$virtual_server::second_print($virtual_server::text{'setup_done'});
	return 1;
	}
}

# feature_disable(&domain)
# Disable the website by adding a redirect from /
sub feature_disable
{
my ($d) = @_;
if ($d->{'alias'}) {
	# Disabling is the same as deletion for an alias
	my $target = &virtual_server::get_domain($d->{'alias'});
	if ($target->{'disabled'}) {
		return 1;
		}
	$d->{'disable_alias_nginx_delete'} = 1;
	return &feature_delete($d);
	}
else {
	&$virtual_server::first_print($text{'feat_disable'});
	&lock_all_config_files();
    
    my $i = 0;
    my @numserv = &find_server_count($d);
    my $num = $#numserv;
    foreach my $server (@numserv) {
		if (!$server) {
			&$virtual_server::second_print(&text('feat_efind', $d->{'dom'}));
			return 0;
		}
    	if ($i == 1 || $num < 1) {
    		my $tmpl = &virtual_server::get_template($d->{'template'});
			my @locs = &find("location", $server);
			my ($clash) = grep { $_->{'words'}->[0] eq '~' &&
			     $_->{'words'}->[1] eq '/.*' } @locs;

			if ($tmpl->{'disabled_url'} eq 'none') {
				# Disable is done via local HTML
				my $dis = &virtual_server::disabled_website_html($d);
				my $msg = $tmpl->{'disabled_web'} eq 'none' ?
					"<h1>Website Disabled</h1>\n" :
				join("\n", split(/\t/, $tmpl->{'disabled_web'}));
				$msg = &virtual_server::substitute_domain_template($msg, $d);
				my $fh = "DISABLED";
				&open_lock_tempfile($fh, ">$dis");
				&print_tempfile($fh, $msg);
				&close_tempfile($fh);
				&set_ownership_permissions(
					undef, undef, 0644, $virtual_server::disabled_website);

				# Add location to force use of it
				if (!$clash) {
					$dis =~ /^(.*)(\/[^\/]+)$/;
					my ($disdir, $disfile) = ($1, $2);
					my $loc =
			    		{ 'name' => 'location',
			      		  'words' => [ '~', '/.*' ],
			      		  'type' => 1,
			      		  'members' => [
								{ 'name' => 'root',
				  				  'words' => [ $disdir ] },
								{ 'name' => 'rewrite',
				  				  'words' => [ '^/.*', $disfile, 'break' ] },
			      		  ],
			    	};
					&save_directive($server, [ ], [ $loc ], $locs[0]);
				}
			} else {
				# Disable is done via redirect
				my $url = &virtual_server::substitute_domain_template(
						$tmpl->{'disabled_url'}, $d);
				if (!$clash) {
					my $loc =
			    		{ 'name' => 'location',
			      		'words' => [ '~', '/.*' ],
			      		'type' => 1,
			      		'members' => [
							{ 'name' => 'rewrite',
				  			'words' => [ '^/.*', $url, 'break' ] },
			      		],
			    	};
					&save_directive($server, [ ], [ $loc ], $locs[0]);
				}
			}
     	}
     	$i++;	
    }
    
	&flush_config_file_lines();
    &unlock_all_config_files();
    &virtual_server::register_post_action(\&print_apply_nginx);
	&$virtual_server::second_print($virtual_server::text{'setup_done'});
	}
}

# feature_enable(&domain)
# Undo the effects of feature_disable
sub feature_enable
{
my ($d) = @_;
if ($d->{'alias'}) {
	# Enabling alias is the same as re-setting it up
	if ($d->{'disable_alias_nginx_delete'}) {
		delete($d->{'disable_alias_nginx_delete'});
		return &feature_setup($d);
		}
	return 1;
	}
else {
	&$virtual_server::first_print($text{'feat_enable'});
	&lock_all_config_files();
    
    
    my $i = 0;
    my @numserv = &find_server_count($d);
    my $num = $#numserv;
    
    foreach my $server (@numserv) {
		if (!$server) {
        	&unlock_all_config_files();
            &$virtual_server::second_print(
                    &text('feat_efind', $d->{'dom'}));
            return 0;
		}
		if ($i == 1 || $num < 1) {
			my @locs = &find("location", $server);
			my ($loc) = grep { $_->{'words'}->[0] eq '~' &&
			   			$_->{'words'}->[1] eq '/.*' } @locs;
			if ($loc) {
				my $rewrite = &find_value("rewrite", $loc);
				if ($rewrite eq '^/.*') {
					&save_directive($server, [ $loc ], [ ]);
				}
			}
        }
        $i++;
    }

	&flush_config_file_lines();
    &unlock_all_config_files();
    &virtual_server::register_post_action(\&print_apply_nginx);
	&$virtual_server::second_print($virtual_server::text{'setup_done'});
    
	}
}

# feature_validate(&domain)
# Checks if this feature is properly setup for the virtual server, and returns
# an error message if any problem is found
sub feature_validate
{
my ($d) = @_;

# Does server exist?
my $server = &find_domain_server($d);
return &text('feat_evalidate',
	"<tt>".&virtual_server::show_domain_name($d)."</tt>") if (!$server);

# Check root directory
if (!$d->{'alias'}) {
	my $rootdir = &find_value("root", $server);
	my $phd = &virtual_server::public_html_dir($d);
	return &text('feat_evalidateroot',
		      "<tt>".&html_escape($rootdir)."</tt>",
		      "<tt>".&html_escape($phd)."</tt>") if ($rootdir ne $phd);
	}

# Is alias target what we expect?
if ($d->{'alias'}) {
	my $target = &virtual_server::get_domain($d->{'alias'});
	my $targetserver = &find_domain_server($target);
	return &text('feat_evalidatetarget',
		     "<tt>".&virtual_server::show_domain_name($target)."</tt>")
		if (!$targetserver);
	return &text('feat_evalidatediff',
		     "<tt>".&virtual_server::show_domain_name($target)."</tt>")
		if ($targetserver ne $server);
	}

# Check for IPs and port
if (!$d->{'alias'}) {
	my @listen = &find_value("listen", $server);
	my $found = 0;
	foreach my $l (@listen) {
		$found++ if ($l eq $d->{'ip'} &&
			      $d->{'web_port'} == 80 ||
			     $l =~ /^\Q$d->{'ip'}\E:(\d+)$/ &&
			      $d->{'web_port'} == $1);
		}
	$found || return &text('feat_evalidateip',
			       $d->{'ip'}, $d->{'web_port'});
	if ($d->{'virt6'}) {
		my $found6 = 0;
		foreach my $l (@listen) {
			$found6++ if ($l eq "[".$d->{'ip6'}."]" &&
				       $d->{'web_port'} == 80 ||
				      $l =~ /^\[\Q$d->{'ip6'}\E\]:(\d+)$/ &&
				       $d->{'web_port'} == $1);
			}
		$found6 || return &text('feat_evalidateip6',
					$d->{'ip6'}, $d->{'web_port'});
		}
	}

return undef;
}

# feature_webmin(&main-domain, &all-domains)
# Returns a list of webmin module names and ACL hash references to be set for
# the Webmin user when this feature is enabled
# (optional)
sub feature_webmin
{
my ($d, $alld) = @_;
my @doms = map { $_->{'dom'} } grep { $_->{$module_name} } @$alld;
if (@doms) {
	return ( [ $module_name,
		   { 'vhosts' => join(' ', @doms),
		     'root' => $d->{'home'},
		     'global' => 0,
		     'logs' => 0,
		     'user' => $d->{'user'},
		     'edit' => 0,
		     'stop' => 0,
		   } ] );
	}
else {
	return ( );
	}
}

# feature_modules()
# Returns a list of the modules that domain owners with this feature may be
# granted access to. Used in server templates.
sub feature_modules
{
return ( [ $module_name, $text{'feat_module'} ] );
}

# feature_links(&domain)
# Returns an array of link objects for webmin modules for this feature
sub feature_links
{
my ($d) = @_;
my @rv;
my @numserv = &find_server_count($d);
foreach my $server (@numserv) {
return ( ) if (!$server);
my @servername = &find("server_name", $server);
		foreach my $l (@servername) {
# Link to edit Nginx config for domain
push(@rv, { 'mod' => $module_name,
	     'desc' => 'Configure '.$l->{'words'}->[0],
	     'page' => 'edit_server.cgi?id='.$l->{'words'}->[0],
	     'cat' => 'services' });
}
}
# my $server = &find_domain_server($d);
# push(@rv, { 'mod' => $module_name,
# 	     'desc' => 'Configure PHP-FPM',
# 	     'page' => 'edit_fpm.cgi?id='.&server_id($server),
# 	     'cat' => 'services' });
# my $server = &find_domain_server($d);
# return ( ) if (!$server);

# # Link to edit Nginx config for domain
# my @rv = ( { 'mod' => $module_name,
# 	     'desc' => $text{'feat_edit'},
# 	     'page' => 'edit_server.cgi?id='.&server_id($server),
# 	     'cat' => 'services' } );

# Links to logs
foreach my $log ([ 0, $text{'links_anlog'} ],
		 [ 1, $text{'links_enlog'} ]) {
	my $lf = &get_nginx_log($d, $log->[0]);
	if ($lf) {
		my $param = &virtual_server::master_admin() ? "file" : "extra";
		push(@rv, { 'mod' => 'syslog',
			    'desc' => $log->[1],
			    'page' => "save_log.cgi?view=1&".
				      "$param=".&urlize($lf),
			    'cat' => 'logs',
			  });
		}
	}

# # Links to edit PHP configs
# my @inis;   
# if ($config{'php_fpm'}) {
# 	 my $tfpm_loc = $config{'php_fpm_loc'};
#         my $iniloc = substr($tfpm_loc, 0, -9).'php.ini';
#         push(@inis, [ 'php.ini', $iniloc ]);
# } else {
# 	@inis = &virtual_server::find_domain_php_ini_files($d);
# }
##Place edit php-fpm HERE.   
foreach my $ini (&virtual_server::find_domain_php_ini_files($d)) {
        push(@rv, { 'mod' => 'phpini',
                    'desc' => $ini->[0] ?
                        &text('links_phpini2', $ini->[0]) :
                        &text('links_phpini'),
                    'page' => 'list_ini.cgi?file='.
                                &urlize($ini->[1]),
                    'cat' => 'services',
                  });
        }

return @rv;
}

# fpm_port(&domain)
# Finds an available port to use for php-fpm to listen on.
sub fpm_port
{
my ($d) =  @_;
my $port;
		# Find ports used by domains
		my %used;
		foreach my $od (&virtual_server::list_domains()) {
			if ($od->{'id'} ne $d->{'id'} && $od->{'nginx_php_port'}) {
				$used{$od->{'nginx_php_port'}}++;
			}
		}
		# Find a free port
		$port = 9000;
		my $s;
		socket($s, PF_INET, SOCK_STREAM, getprotobyname('tcp')) ||
			return (0, "Socket failed : $!");
		setsockopt($s, SOL_SOCKET, SO_REUSEADDR, pack("l", 1));
		while(1) {
			last if (!$used{$port} && $port != 9001 &&
			 bind($s, sockaddr_in($port, INADDR_ANY)));
			$port++;
		}
		close($s);
    if ($port < 9030) {
    	###### Don't go wild here and start putting every port on php-fpm... Limit is 30.
        ## Sets selinux rule to allow php-fpm to use this port!
    	&backquote_logged("semanage port -a -t http_port_t -p tcp $port 2>&1 </dev/null");
    }
    return $port;
}

# create_fpm_conf(config, &domain)
# Copies www.conf file for domain and renames to www.conf.default.
sub create_fpm_conf
{
	my ($conf, $d) = @_;
    if (!-r $conf.$d->{'dom'}.'.conf') {
    	if (!-r $conf.'www.conf.default') {
			if (!-r $conf.'www.conf') {
			} else {
            	# This is the first time setup
                &copy_source_dest($conf.'www.conf', $conf.$d->{'dom'}.'.conf');
            	&rename_logged($conf.'www.conf', $conf.'www.conf.default');
    		}
    	} else {
    		&copy_source_dest($conf.'www.conf.default', $conf.$d->{'dom'}.'.conf');
    	}
    }
}

# php_fpm_loc(srcini)
# returns the direcotoy of default PHP-FPM
sub php_fpm_loc
{
	my ($srcini) = @_;
    my $loc_php;
    if (!$config{'php_fpm_loc'}) {
    	#### Is the directory to PHP-FPM listed in the configuration options?
    	## Does the default php-fpm direcotry exist in etc?
    	if (-d '/etc/php-fpm.d') {
    		$loc_php = '/etc/php-fpm.d';
   		} else {
			$loc_php = substr($srcini, 0, -7).'php-fpm.d';
   		}
    } else {
    	return $config{'php_fpm_loc'};
    }
    # Save it in module conf.
    $config{'php_fpm_loc'} = $loc_php;
	&save_module_config(\%config);
    return $loc_php;
}

# fpm_sock_loc(srcini)
# Returns the directory of the PHP-FPM socket.
sub fpm_sock_loc
{
	my ($srcini) = @_;
    my $loc_sock;
    if (!$config{'php_fpm_socks'}) {
    	if (-d '/var/run/php-fpm') {
      			$loc_sock = '/var/run/php-fpm';
    	} else {
			$loc_sock = substr($srcini, 0, -12).'/var/run/php-fpm';
    	}
    } else {
    	return $config{'php_fpm_socks'};
    }
    $config{'php_fpm_socks'} = $loc_sock;
	&save_module_config(\%config);
    return $loc_sock;
}

# change_pool_name(file, newname)
# Changes the name of the fpm pool inside domain.conf
sub change_pool_name
{
	my ($file, $name) = @_;
	&lock_all_config_files();
    &unflush_file_lines($file);
    
    my $in = "CFILE".int(rand(1000000));
	&open_readfile($in, $file) || return [];
	my @lines = <$in>;
	close($in);
    
    my $out = "CFILE".int(rand(1000000));
    &open_tempfile($out, ">$file");
	foreach my $line (@lines)
	{
    	$line =~ s/\[(.*)\]$/\[$name\]/g;
        &print_tempfile($out, $line);
	}
    &close_tempfile($out);
    &flush_config_file_lines($file);
    &unlock_all_config_files();
}

# print_apply_nginx()
# Restart Nginx, and print a message - Removed check if nginx is started.
sub print_apply_nginx
{
&$virtual_server::first_print($text{'feat_apply'});
#if (&is_nginx_running()) {
	my $test = &test_config();
	if ($test && $test =~ /Cannot\s+assign/i) {
		# Maybe new address has just come up .. wait 5 secs and re-try
		sleep(5);
		$test = &test_config();
		}
	if ($test) {
		&$virtual_server::second_print(
		    &text('feat_econfig2', "<tt>".&html_escape($test)."</tt>"));
		}
	else {
		my $err = apply_nginx();
		if ($err) {
			&$virtual_server::second_print(
			    &text('feat_eapply',
				  "<tt>".&html_escape($test)."</tt>"));
			}
		else {
			&$virtual_server::second_print(
				$virtual_server::text{'setup_done'});
			}
		}
# 	}
# else {
# 	&$virtual_server::second_print($text{'feat_notrunning'});
# 	}
}

# apply_fpm()
# Attempt to apply the PHP-FPM config, return an error on failure or undef
# on success
sub apply_fpm
{
	my $out;
    my $file;
    my $restart;
	if ($config{'fpm_apply_cmd'}) {
		$out = &backquote_logged("$config{'fpm_apply_cmd'} 2>&1 </dev/null");
        
	} else {
		opendir(DIR, "/lib/systemd/system");
		my @files = grep(/php(.*)fpm/,readdir(DIR));
		closedir(DIR);

		foreach $file (@files) {
    		$restart = substr($file, 0, -8); 
		}
        if ($restart) {
        	$config{'fpm_apply_cmd'} = 'service '.$restart.' restart';
            $config{'fpm_start_cmd'} = 'service '.$restart.' start';
            $config{'fpm_stop_cmd'} = 'service '.$restart.' stop';
			&save_module_config(\%config);
    		$out = &backquote_logged("service $restart restart 2>&1 </dev/null");
    	} else {
        	return $text{'feat_find_fpm'};
        }
	}
	return $? ? $out : undef;
}

# print_apply_fpm()
# Restart PHP-FPM, and print a message.
sub print_apply_fpm
{
	&$virtual_server::first_print($text{'feat_apply_fpm'});
	my $err = apply_fpm();
	if ($err) {
		&$virtual_server::second_print($err);
	} else {
		&$virtual_server::second_print($virtual_server::text{'setup_done'});
	}
}

# feature_provides_web()
sub feature_provides_web
{
return 1;	# Nginx is a webserver
}

sub feature_web_supports_suexec
{
return -1;		# PHP is always run as domain owner
}

sub feature_web_supports_cgi
{
return 0;		# No CGI support
}

sub feature_web_supported_php_modes
{
return ('fcgid');	# Only mode we can run
}

# feature_get_web_php_mode(&domain)
sub feature_get_web_php_mode
{
my ($d) = @_;
return 'fcgid';		# Only mode we can run
}

# feature_save_web_php_mode(&domain, mode)
sub feature_save_web_php_mode
{
my ($d, $mode) = @_;
$mode eq 'fcgid' || &error($text{'feat_ephpmode'});
}

# feature_list_web_php_directories(&domain)
# Only one version is supported in Nginx
sub feature_list_web_php_directories
{
my ($d) = @_;
my ($defver) = &get_default_php_version();
return ( { 'dir' => &virtual_server::public_html_dir($d),
	   'mode' => 'fcgid',
	   'version' => $defver } );
}

# feature_save_web_php_directory(&domain, dir, version)
# Cannot set the version for any sub-directory
sub feature_save_web_php_directory
{
my ($d, $dir, $ver) = @_;
$dir eq &virtual_server::public_html_dir($d) ||
	&error($text{'feat_ephpdir'});
my ($defver) = &get_default_php_version();
$defver eq $ver ||
	&error($text{'feat_ephpdirver'});
}

# feature_delete_web_php_directory(&domain, dir)
# Cannot delete the PHP version for a directory ever, so this does nothing
sub feature_delete_web_php_directory
{
my ($d, $dir) = @_;
}

# feature_get_fcgid_max_execution_time(&domain)
# Returns the timeout set by fastcgi_read_timeout
sub feature_get_fcgid_max_execution_time
{
my ($d) = @_;
my $server = &find_domain_server($d);
if ($server) {
	my $ver = &get_nginx_version();
	$ver =~ s/^(\d+\.\d+)(.*)/$1/;
	if ($ver >= 1.6) {
		# New format directive
		my ($t) = grep { $_->{'words'}->[0] eq "read_timeout" }
			     &find("fastcgi_param", $server);
		my $v = $t ? $t->{'words'}->[1] : undef;
		return !$v ? undef : $v == 9999 ? undef : $v;
		}
	else {
		# Old format directive
		my $t = &find_value("fastcgi_read_timeout", $server);
		return $t == 9999 ? undef : $t if ($t);
		}
	return &get_default("fastcgi_read_timeout");
	}
}

# feature_set_fcgid_max_execution_time(&domain, timeout)
# Sets the fcgi timeout with fastcgi_read_timeout
sub feature_set_fcgid_max_execution_time
{
my ($d, $max) = @_;
&lock_all_config_files();
my $server = &find_domain_server($d);
if ($server) {
	my $ver = &get_nginx_version();
	$ver =~ s/^(\d+\.\d+)(.*)/$1/;
	if ($ver >= 1.6) {
		# New format directive
		my @p = &find("fastcgi_param", $server);
		@p = grep { $_->{'words'}->[0] ne 'read_timeout' } @p;
		push(@p, { 'name' => 'fastcgi_param',
			   'words' => [ "read_timeout", ($max || 9999) ] });
		&save_directive($server, "fastcgi_param", \@p);
		}
	else {
		# Old format directive
		&save_directive($server, "fastcgi_read_timeout",
			        [ $max || 9999 ]);
		}
	}
&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
}

# feature_restart_web_php(&domain)
# Restart the fcgi server for this domain, if one is running
sub feature_restart_web_php
{
my ($d) = @_;
if ($d->{'nginx_php_port'}) {
	&stop_php_fcgi_server_command($d, 0);
	my ($cmd, $envs_to_set, $log, $pidfile) = &get_php_fcgi_server_command(
			$d, $d->{'nginx_php_port'});
	if ($cmd) {
		&start_php_fcgi_server_command(
			$d, $cmd, $envs_to_set, $log, $pidfile);
		}
	}
}

# feature_restart_web()
# Applies the webserver configuration
sub feature_restart_web
{
&print_apply_nginx();
}

# feature_restart_web_command()
# Returns the Nginx restart command
sub feature_restart_web_command
{
return $config{'apply_cmd'};
}

# feature_get_web_php_children(&domain)
# Defaults to 1, but can be changed by environment variable
sub feature_get_web_php_children
{
my ($d) = @_;
return $d->{'nginx_php_children'} || 1;
}

# feature_save_web_php_children(&domain, children)
# Update the PHP init script and running process with the new child count
sub feature_save_web_php_children
{
my ($d, $children) = @_;
$d->{'nginx_php_children'} ||= 1;
if ($children != $d->{'nginx_php_children'}) {
	$d->{'nginx_php_children'} = $children;
	&delete_php_fcgi_server($d);
	&setup_php_fcgi_server($d);
	&virtual_server::save_domain($d);
	}
return undef;
}

# feature_startstop()
# Returns info for restarting Nginx
sub feature_startstop
{
my $pid = &is_nginx_running();
my @links = ( { 'link' => '/'.$module_name.'/',
		'desc' => $text{'feat_manage'},
		'manage' => 1 } );
if ($pid) {
	return ( { 'status' => 1,
		   'name' => $text{'feat_sname'},
		   'desc' => $text{'feat_sstop'},
		   'restartdesc' => $text{'feat_srestart'},
		   'longdesc' => $text{'feat_sstopdesc'},
		   'links' => \@links } );
	}
else {
	return ( { 'status' => 0,
		   'name' => $text{'feat_sname'},
		   'desc' => $text{'feat_sstart'},
		   'longdesc' => $text{'feat_sstartdesc'},
		   'links' => \@links } );
	}
}

# feature_stop_service()
# Stop the Nginx webserver, from the System Information page
sub feature_stop_service
{
return &stop_nginx();
}

# feature_start_service()
# Start the Nginx webserver, from the System Information page
sub feature_start_service
{
return &start_nginx();
}

# feature_bandwidth(&domain, start, &bw-hash)
# Searches through log files for records after some date, and updates the
# day counters in the given hash
sub feature_bandwidth
{
my ($d, $start, $bwinfo) = @_;
my @logs = ( &get_nginx_log($d, 0) );
return if ($d->{'alias'} || $d->{'subdom'}); # never accounted separately
my $max_ltime = $start;
foreach my $l (&unique(@logs)) {
	foreach my $f (&virtual_server::all_log_files($l, $max_ltime)) {
		local $_;
		if ($f =~ /\.gz$/i) {
			open(LOG, "gunzip -c ".quotemeta($f)." |");
			}
		elsif ($f =~ /\.Z$/i) {
			open(LOG, "uncompress -c ".quotemeta($f)." |");
			}
		else {
			open(LOG, $f);
			}
		while(<LOG>) {
			if (/^(\S+)\s+(\S+)\s+(\S+)\s+\[(\d+)\/(\S+)\/(\d+):(\d+):(\d+):(\d+)\s+(\S+)\]\s+"([^"]*)"\s+(\S+)\s+(\S+)/ && $12 ne "206") {
				# Valid-looking log line .. work out the time
				my $ltime = timelocal($9, $8, $7, $4, $virtual_server::apache_mmap{lc($5)}, $6-1900);
				if ($ltime > $start) {
					my $day = int($ltime / (24*60*60));
					$bwinfo->{"web_".$day} += $13;
					}
				$max_ltime = $ltime if ($ltime > $max_ltime);
				}
			}
		close(LOG);
		}
	}
return $max_ltime;
}

# feature_get_web_domain_star(&domain)
# Checks if all sub-domains are matched for this domain
sub feature_get_web_domain_star
{
my ($d) = @_;
my $server = &find_domain_server($d);
return undef if (!$server);
my $obj = &find("server_name", $server);
foreach my $w (@{$obj->{'words'}}) {
	if ($w eq "*.".$d->{'dom'}) {
		return 1;
		}
	}
return 0;
}

# feature_save_web_domain_star(&domain, star)
# Add *.domain to server_name if missing
sub feature_save_web_domain_star
{
my ($d, $star) = @_;
&lock_all_config_files();
my $server = &find_domain_server($d);
return undef if (!$server);
my $obj = &find("server_name", $server);
my $idx = &indexof("*.".$d->{'dom'}, @{$obj->{'words'}});
if ($star && $idx < 0) {
	# Need to add
	push(@{$obj->{'words'}}, "*.".$d->{'dom'});
	&save_directive($server, "server_name", [ $obj ]);
	}
elsif (!$star && $idx >= 0) {
	# Need to remove
	splice(@{$obj->{'words'}}, $idx, 1);
	&save_directive($server, "server_name", [ $obj ]);
	}
&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
}

# feature_get_web_log(&domain, errorlog)
# Returns the path to the access or error log
sub feature_get_web_log
{
my ($d, $errorlog) = @_;
return &get_nginx_log($d, $errorlog);
}

sub feature_supports_web_redirects
{
return 1;	# Always supported
}

# feature_list_web_redirects(&domain)
# Finds redirects from rewrite directives in the Nginx config
sub feature_list_web_redirects
{
my ($d) = @_;
my $server = &find_domain_server($d);
return () if (!$server);
my @rv;
my $phd = &virtual_server::public_html_dir($d);
foreach my $r (&find("rewrite", $server)) {
	if ($r->{'words'}->[0] =~ /^\^\\Q(\/.*)\\E(\(\.\*\))?/ &&
	    $r->{'words'}->[2] eq 'break') {
		my $redirect = { 'path' => $1,
				 'dest' => $r->{'words'}->[1],
				 'object' => $r,
			       };
		if ($2) {
			if ($redirect->{'dest'} =~ s/\$1$//) {
				$redirect->{'regexp'} = 0;
				}
			else {
				$redirect->{'regexp'} = 1;
				}
			}
		if ($r->{'words'}->[1] =~ /^(http|https):/) {
			$redirect->{'alias'} = 0;
			}
		else {
			$redirect->{'dest'} = $phd.$redirect->{'dest'};
			$redirect->{'alias'} = 1;
			}
		push(@rv, $redirect);
		}
	}
return @rv;
}

# feature_create_web_redirect(&domain, &redirect)
# Add a redirect using a rewrite directive
sub feature_create_web_redirect
{
my ($d, $redirect) = @_;
my $server = &find_domain_server($d);
return &text('redirect_efind', $d->{'dom'}) if (!$server);
my $phd = &virtual_server::public_html_dir($d);
my $dest = $redirect->{'dest'};
if ($dest !~ /^(http|https):/) {
	$dest =~ s/^\Q$phd\E// || return &text('redirect_ephd', $phd);
	}
my $r = { 'name' => 'rewrite',
	  'words' => [ '^\\Q'.$redirect->{'path'}.'\\E',
		       $dest,
		       'break' ],
	};
if ($redirect->{'regexp'}) {
	# All sub-directories go to same dest path
	$r->{'words'}->[0] .= "(.*)";
	}
else {
	# Redirect sub-directory to same sub-dir on dest
	$r->{'words'}->[0] .= "(.*)";
	$r->{'words'}->[1] .= "\$1";
	}
&lock_all_config_files();
&save_directive($server, [ ], [ $r ]);
&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
return undef;
}

# feature_delete_web_redirect(&domain, &redirect)
# Remove a redirect using a rewrite directive
sub feature_delete_web_redirect
{
my ($d, $redirect) = @_;
my $server = &find_domain_server($d);
return &text('redirect_efind', $d->{'dom'}) if (!$server);
return $text{'redirect_eobj'} if (!$redirect->{'object'});
&lock_all_config_files();
&save_directive($server, [ $redirect->{'object'} ], [ ]);
&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
return undef;
}

sub feature_supports_web_balancers
{
return 2;	# Supports multiple backends
}

# feature_list_web_balancers(&domain)
# Finds location blocks that just have a proxy_pass in them
sub feature_list_web_balancers
{
my ($d) = @_;
my $server = &find_domain_server($d);
return &text('redirect_efind', $d->{'dom'}) if (!$server);
my @rv;
my @locations = &find("location", $server);
my $conf = &get_config();
my $http = &find("http", $conf);
my %upstreams = map { $_->{'words'}->[0], $_ } &find("upstream", $http);
foreach my $l (@locations) {
	next if (@{$l->{'words'}} > 1);
	my $pp = &find_value("proxy_pass", $l);
	next if (!$pp && @{$l->{'members'}});
	my $b = { 'path' => $l->{'words'}->[0],
		  'location' => $l };
	if (!$pp) {
		# No URL, so proxying disabled
		$b->{'none'} = 1;
		}
	elsif ($pp =~ /^http:\/\/([^\/]+)$/ && $upstreams{$1}) {
		# Mapped to an upstream block, with multiple URLs
		$b->{'balancer'} = $1;
		my $u = $upstreams{$1};
		$b->{'urls'} = [ map { &upstream_to_url($_) }
				     &find_value("server", $u) ];
		$b->{'upstream'} = $u;
		}
	else {
		# Just one URL
		$b->{'urls'} = [ $pp ];
		}
	push(@rv, $b);
	}
return @rv;
}

# feature_create_web_balancer(&domain, &balancer)
# Create a location block for proxying to some URLs
sub feature_create_web_balancer
{
my ($d, $balancer) = @_;
my $server = &find_domain_server($d);
return &text('redirect_efind', $d->{'dom'}) if (!$server);
my ($clash) = grep { $_->{'words'}->[0] eq $balancer->{'path'} }
		   &find("location", $server);
$clash && return &text('redirect_eclash', $balancer->{'path'});
&lock_all_config_files();
my @urls = $balancer->{'none'} ? ( ) : @{$balancer->{'urls'}};
my $err = &validate_balancer_urls(@urls);
return $err if ($err);
my $url;
if (@urls > 1) {
	$balancer->{'balancer'} ||= 'virtualmin_'.time().'_'.$$;
	$url = 'http://'.$balancer->{'balancer'};
	my $conf = &get_config();
	my $http = &find("http", $conf);
	my ($clash) = grep { $_->{'words'}->[0] eq $balancer->{'balancer'} }
			   &find("upstream", $http);
	$clash && return &text('redirect_eupstream', $balancer->{'balancer'});
	my $u = { 'name' => 'upstream',
		  'words' => [ $balancer->{'balancer'} ],
		  'type' => 1,
		  'members' => [
			map { { 'name' => 'server',
				'words' => [ &url_to_upstream($_) ] } } @urls,
		  	]
		};
	$balancer->{'upstream'} = $u;
	&save_directive($http, [ ], [ $u ]);
	}
elsif (!$balancer->{'none'}) {
	$url = $urls[0];
	}
my $l = { 'name' => 'location',
	  'words' => [ $balancer->{'path'} ],
	  'type' => 1,
	  'members' => [ ],
        };
if ($url) {
	# Add rewrites to make URL sent to the proxy not include the original
	# path, like Apache does. Also fix up redirects
	my $p = $balancer->{'path'};
	if ($p ne '/') {
		$p =~ s/\/$//;
		push(@{$l->{'members'}},
		     { 'name' => 'rewrite',
		       'words' => [ '^'.$p.'$', $p.'/', 'redirect' ],
		     },
		     { 'name' => 'rewrite',
		       'words' => [ '^'.$p.'(/.*)', '$1', 'break' ],
		     },
		     { 'name' => 'proxy_redirect',
		       'words' => [ $url, $p ],
		     },
		    );
		}
	push(@{$l->{'members'}},
	     { 'name' => 'proxy_pass',
	       'words' => [ $url ],
	     },
	    );
	}
$balancer->{'location'} = $l;
my $before = &find_before_location($server, $balancer->{'path'});
&save_directive($server, [ ], [ $l ], $before);
&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
return undef;
}

# feature_delete_web_balancer(&domain, &balancer)
# Deletes the location block for a proxy, and the balancer if created by
# Virtualmin
sub feature_delete_web_balancer
{
my ($d, $balancer) = @_;
my $server = &find_domain_server($d);
return &text('redirect_efind', $d->{'dom'}) if (!$server);
return $text{'redirect_eobj2'} if (!$balancer->{'location'});
&lock_all_config_files();
my $pp = &find_value("proxy_pass", $balancer->{'location'});
if ($balancer->{'upstream'}) {
	# Has associated upstream block .. check for other users
	my $conf = &get_config();
	my $http = &find("http", $conf);
	my @pps = &find_recursive("proxy_pass", $http);
	my @users = grep { $_->{'words'}->[0] =~
			   /^http:\/\/\Q$balancer->{'balancer'}\E/ } @pps;
	if (@users <= 1) {
		&save_directive($http, [ $balancer->{'upstream'} ], [ ]);
		}
	}
&save_directive($server, [ $balancer->{'location'} ], [ ]);
&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
return undef;
}

# feature_modify_web_balancer(&domain, &balancer, &old-balancer)
# Change the path or URLs of a proxy
sub feature_modify_web_balancer
{
my ($d, $balancer, $oldbalancer) = @_;
my $server = &find_domain_server($d);
return &text('redirect_efind', $d->{'dom'}) if (!$server);
return $text{'redirect_eobj2'} if (!$oldbalancer->{'location'});
&lock_all_config_files();
my $l = $oldbalancer->{'location'};
if ($balancer->{'path'} ne $oldbalancer->{'path'}) {
	$l->{'words'}->[0] = $balancer->{'path'};
	&save_directive($server, [ $l ], [ $l ]);
	}
my $u = $oldbalancer->{'upstream'};
my @urls = $balancer->{'none'} ? ( ) : @{$balancer->{'urls'}};
my $err = &validate_balancer_urls(@urls);
return $err if ($err);
my $url;
if ($u) {
	# Change URLs in upstream block
	&save_directive($u, "server", [ map { &url_to_upstream($_) } @urls ]);
	$url = "http://".$oldbalancer->{'balancer'};
	}
elsif (@urls > 1) {
	# Need to add an upstream block
	&error("Converting a proxy to a balancer can never happen!");
	}
else {
	# Just change one URL
	&save_directive($l, "proxy_pass", \@urls);
	$url = @urls ? $urls[0] : undef;
	}
if (@urls && $balancer->{'path'} ne '/') {
	# Add rewrites for the path
	my $p = $balancer->{'path'};
	$p =~ s/\/$//;
	&save_directive($l, 'rewrite',
	     { 'name' => 'rewrite',
	       'words' => [ '^'.$p.'$', $p.'/', 'redirect' ],
	     },
	     { 'name' => 'rewrite',
	       'words' => [ '^'.$p.'(/.*)', '$1', 'break' ],
	     },
	     { 'name' => 'proxy_redirect',
	       'words' => [ $url, $p ],
	     },
	     );
	}
esle {
	&save_directive($l, 'rewrite', [ ]);
	}
&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
return undef;
}

sub feature_supports_webmail_redirect
{
return 1;	# Can be setup using Nginx rewrites
}

# feature_add_web_webmail_redirect(&domain, &tmpl)
# Add server names for webmail and admin, and rewrite rules to redirect to
# Webmin and Usermin
sub feature_add_web_webmail_redirect
{
my ($d, $tmpl) = @_;
my $server = &find_domain_server($d);
return &text('redirect_efind', $d->{'dom'}) if (!$server);
&lock_all_config_files();
foreach my $r ('webmail', 'admin') {
	next if (!$tmpl->{'web_'.$r});

	# Work out the URL to redirect to
	my $url = $tmpl->{'web_'.$r.'dom'};
	if ($url) {
		# Sub in any template
		$url = &virtual_server::substitute_domain_template($url, $d);
		}
	else {
		# Work out URL
		my ($port, $proto);
		if ($r eq 'webmail') {
			# From Usermin
			if (&foreign_installed("usermin")) {
				&foreign_require("usermin", "usermin-lib.pl");
				my %miniserv;
				&usermin::get_usermin_miniserv_config(
					\%miniserv);
				$proto = $miniserv{'ssl'} ? 'https' : 'http';
				$port = $miniserv{'port'};
				}
			# Fall back to standard defaults
			$proto ||= "http";
			$port ||= 20000;
			}
		else {
			# From Webmin
			($port, $proto) = &virtual_server::get_miniserv_port_proto();
			}
		$url = "$proto://$d->{'dom'}:$port/";
		}

	# Update server_name
	my $obj = &find("server_name", $server);
	my $rhost = $r.".".$d->{'dom'};
	if (&indexof($rhost, @{$obj->{'words'}}) < 0) {
		push(@{$obj->{'words'}}, $rhost);
		&save_directive($server, "server_name", [ $obj ]);
		}

	# Add rewrite directive, inside if block
	&save_directive($server, [ ], [
		{ 'name' => 'if',
		  'type' => 2,
		  'words' => [ '$host', '=', $rhost ],
		  'members' => [
			{ 'name' => 'rewrite',
			  'words' => [ '^/(.*)$', $url.'$1', 'redirect' ],
			},
			]
		},
		]);
	}
&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
return undef;
}

# feature_remove_web_webmail_redirect(&domain)
# Delete the additional server names and rewrite rules
sub feature_remove_web_webmail_redirect
{
my ($d) = @_;
my $server = &find_domain_server($d);
return &text('redirect_efind', $d->{'dom'}) if (!$server);
&lock_all_config_files();
foreach my $r ('webmail', 'admin') {
	# Update server_name
	my $obj = &find("server_name", $server);
	my $rhost = $r.".".$d->{'dom'};
	my $idx = &indexof($rhost, @{$obj->{'words'}});
	if ($idx >= 0) {
		splice(@{$obj->{'words'}}, $idx, 1);
		&save_directive($server, "server_name", [ $obj ]);
		}

	# Remove if block for the rewrite
	my @ifs = &find("if", $server);
	foreach my $i (@ifs) {
		if ($i->{'words'}->[0] eq '$host' &&
		    $i->{'words'}->[1] eq '=' &&
		    $i->{'words'}->[2] eq $rhost) {
			&save_directive($server, [ $i ], [ ]);
			}
		}
	}
&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
return undef;
}

# feature_get_web_webmail_redirect(&domain)
# Check if the webmail and admin server_names are in place
sub feature_get_web_webmail_redirect
{
my ($d) = @_;
my $server = &find_domain_server($d);
return 0 if (!$server);
my $obj = &find("server_name", $server);
my @rv;
foreach my $r ("webmail", "admin") {
	my $rhost = $r.".".$d->{'dom'};
	push(@rv, $rhost) if (&indexof($rhost, @{$obj->{'words'}}) >= 0);
	}
return @rv;
}

sub feature_supports_web_default
{
return 1;	# Websites can be made the default
}

# feature_set_web_default(&domain)
# Make this domain's site the default by adding it's IP to server_name
sub feature_set_web_default
{
my ($d) = @_;
my $server = &find_domain_server($d);
return &text('redirect_efind', $d->{'dom'}) if (!$server);
&lock_all_config_files();

# Add IP to server_name for this server
my $obj = &find("server_name", $server);
my $idx = &indexof($d->{'ip'}, @{$obj->{'words'}});
if ($idx < 0) {
	push(@{$obj->{'words'}}, $d->{'ip'});
	&save_directive($server, "server_name", [ $obj ]);
	}

# Remove IP from server_name for other servers
my $conf = &get_config();
my $http = &find("http", $conf);
foreach my $os (&find("server", $http)) {
	next if ($os eq $server);
	my $obj = &find("server_name", $os);
	my $idx = &indexof($d->{'ip'}, @{$obj->{'words'}});
	if ($idx >= 0) {
		splice(@{$obj->{'words'}}, $idx, 1);
		&save_directive($os, "server_name", [ $obj ]);
		}
	}

&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
return undef;
}

# feature_is_web_default(&domain)
# Returns 1 if the server's IP is in server_names
sub feature_is_web_default
{
my ($d) = @_;
my $server = &find_domain_server($d);
return 0 if (!$server);
my $obj = &find("server_name", $server);
return &indexof($d->{'ip'}, @{$obj->{'words'}}) >= 0 ? 1 : 0;
}

# feature_save_web_passphrase(&domain)
# Not possible with Nginx
sub feature_save_web_passphrase
{
my ($d) = @_;
if ($d->{'ssl_pass'}) {
	&error($text{'feat_epassphrase'});
	}
}

# feature_get_web_ssl_file(&domain, mode)
# Return the SSL cert or key file in the Nginx config
sub feature_get_web_ssl_file
{
my ($d, $mode) = @_;
my $server = &find_domain_server($d);
return undef if (!$server);
if ($mode eq 'cert') {
	return &find_value($server, "ssl_certificate");
	}
elsif ($mode eq 'key') {
	return &find_value($server, "ssl_certificate_key");
	}
elsif ($mode eq 'ca') {
	# Always appeneded to the cert file
	return $d->{'ssl_chain'};
	}
return undef;
}

# feature_save_web_ssl_file(&domain, mode, file)
# Set the SSL cert or key file in the Nginx config
sub feature_save_web_ssl_file
{
my ($d, $mode, $file) = @_;
&lock_all_config_files();
my $server = &find_domain_server($d);
return &text('feat_efind', $d->{'dom'}) if (!$server);
if ($mode eq 'cert') {
	&save_directive($server, "ssl_certificate",
			$file ? [ $file ] : [ ]);
	}
elsif ($mode eq 'key') {
	&save_directive($server, "ssl_certificate_key",
			$file ? [ $file ] : [ ]);
	}
elsif ($mode eq 'ca') {
	# Append to cert file as well
	my $certfile = &find_value("ssl_certificate", $server);
	$certfile || return $text{'feat_echainfile'};
	my @certs = &split_ssl_certs(&read_file_contents($certfile));
	my $fh = "CERT";
	if ($file) {
		# Append chained cert to main cert
		my $chain = &read_file_contents($file);
		&open_tempfile($fh, ">$certfile");
		&print_tempfile($fh, join("", $certs[0], $chain));
		&close_tempfile($fh);
		}
	else {
		# Use only main cert
		&open_tempfile($fh, ">$certfile");
		&print_tempfile($fh, $certs[0]);
		&close_tempfile($fh);
		}
	}
&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
return undef;
}

# feature_backup(&domain, file, &opts, homeformat?, incremental?, as-owner,
# 		 &all-opts)
# Backup this domain's Nginx directives to a file
sub feature_backup
{
my ($d, $file, $opts, $homefmt, $increment, $asd, $allopts) = @_;
return 1 if ($d->{'alias'});

# Write config directives from the server block to a file
&$virtual_server::first_print($text{'feat_backup'});
&lock_all_config_files();

my $conf = &get_config();
my $http = &find("http", $conf);

# Find limit zone req so we can save to the backed up file.
my @zone = &find_recursive("limit_req_zone", $http);
my $oldv = $d->{'dom'};
my $limit_zone;

foreach my $j (@zone) {
   	if ($j->{'words'}->[1] =~ /\Q$oldv\E/) {
		$limit_zone = $j;
	}
}
my $server = &find_domain_server($d);
if (!$server) {
	&unlock_all_config_files();
	&$virtual_server::second_print(
		&text('feat_efind', $d->{'dom'}));
	return 0;
	}
    
if ($config{'php_fpm'}) {
	# Get default php version and file path.
    my ($ver, $cmd) = &get_default_php_version();
    my $srcini = &virtual_server::get_global_php_ini($ver, 'fcgi');
    # Get default location of php-fpm.conf
    my $fpm_loc = &php_fpm_loc($srcini).'/';
    &copy_source_dest($fpm_loc.$d->{'dom'}.'.conf', $file."_php-fpm");
}

my @numserv = &find_server_count($d);
my $fh = "BACKUP";
&virtual_server::open_tempfile_as_domain_user($d, $fh, ">>$file");
my %adoms = map { $_->{'dom'}, 1 }
&virtual_server::get_domain_by("alias", $d->{'id'});
foreach my $server1 (@numserv) {
	my $lref = &read_file_lines($server1->{'file'}, 1);
    # Add limit zone request from nginx.conf to backup file.
    #
	foreach my $l (@$lref[($server1->{'line'}) .. ($server1->{'eline'})]) {
		$l = &fix_server_name_line($l, \%adoms);
		&print_tempfile($fh, $l."\n") if ($l);
	}
    
    if ($server1 eq $numserv[-1] && $limit_zone) {
    	&print_tempfile($fh, $limit_zone->{'name'}." ".$limit_zone->{'words'}->[0]." "
        .$limit_zone->{'words'}->[1]." ".$limit_zone->{'words'}->[2].";\n");
    }
}

&virtual_server::close_tempfile_as_domain_user($d, $fh);
&unlock_all_config_files();
&$virtual_server::second_print($virtual_server::text{'setup_done'});

# Save log files, if outside home
my $alog = &get_nginx_log($d, 0);
if ($alog && !&is_under_directory($d->{'home'}, $alog) &&
    !$allopts->{'dir'}->{'dirnologs'}) {
	&$virtual_server::first_print($text{'feat_backuplog'});
	&virtual_server::copy_write_as_domain_user($d, $alog, $file."_alog");
	my $elog = &get_nginx_log($d, 1);
	if ($elog && !&is_under_directory($d->{'home'}, $elog)) {
		&virtual_server::copy_write_as_domain_user(
			$d, $elog, $file."_elog");
		}
	&$virtual_server::second_print($virtual_server::text{'setup_done'});
	}

return 1;
}

# feature_restore(&domain, file, &opts, &all-opts, home-format, &old-domain)
# Re-created this domain's Nginx directives from a file
sub feature_restore
{
my ($d, $file, undef, undef, undef, $oldd) = @_;
return 1 if ($d->{'alias'});

# Replace lines in the server block with those from the backup file
&$virtual_server::first_print($text{'feat_restore'});
&lock_all_config_files();
my $server = &find_domain_server($d);
if (!$server) {
	&unlock_all_config_files();
	&$virtual_server::second_print(
		&text('feat_efind', $d->{'dom'}));
	return 0;
	}
my $alog = &get_nginx_log($d, 0);
my $elog = &get_nginx_log($d, 1);
my $conf = &get_config();
my $http = &find("http", $conf);

if ($server->{'file'} eq &get_add_to_file($d->{'dom'}) &&
    -d $config{'add_to'}) {
		# Domain is in its own file, and backup includes the whole file .. so
		# just copy it into place
		&copy_source_dest($file, $server->{'file'});
    	# Also copy php-fpm configs in place.
   	 	if ($config{'php_fpm'}) {
        	# Get default php version and file path.
    		my ($ver, $cmd) = &get_default_php_version();
    		my $srcini = &virtual_server::get_global_php_ini($ver, 'fcgi');
    		# Get default location of php-fpm.conf
    		my $fpm_loc = &php_fpm_loc($srcini).'/';
    		&copy_source_dest($file."_php-fpm", $fpm_loc.$d->{'dom'}.'.conf');
    	}
	}
else {
    # find limit zone req and remove it so we can restore backup parameters.
	my @zone = &find_recursive("limit_req_zone", $http);
	my $oldv = $d->{'dom'};

	foreach my $j (@zone) {
   		if ($j->{'words'}->[1] =~ /\Q$oldv\E/) {
			&save_directive($http, [ $j ], [ ]);
		}
	}
    my $server1;
	my @numserv = &find_server_count($d);
    my $lref = &read_file_lines($server->{'file'});
    my $line;
	foreach $server1 (@numserv) {
    	if (!$line) {
        	$line = $server->{'line'};
        }
    	&save_directive($http, [ $server1 ], [ ]);
	}
    my $srclref = &read_file_lines($file, 1);
    splice(@$lref, $line, 0, @$srclref);
    &flush_file_lines($server1->{'file'});
    &flush_config_cache();
}

$server = &find_domain_server($d);
if (!$server) {
	&$virtual_server::second_print(
		&text('feat_erestorefind', $d->{'dom'}));
	return 0;
	}

# Put back old log file paths
&save_directive($server, "access_log", [ $alog ]) if ($alog);
&save_directive($server, "error_log", [ $elog ]) if ($elog);

# Remove IP from server_name if changed
if ($oldd && $oldd->{'ip'} ne $d->{'ip'}) {
	my @numserv = &find_server_count($d);
    # Loop through server blocks
    foreach my $server (@numserv) {
		my @listen = &find("listen", $server);
		foreach my $l (@listen) {
			if ($l->{'words'}->[0] eq $oldd->{'ip'}) {
				$l->{'words'}->[0] = $d->{'ip'};
			}
			elsif ($l->{'words'}->[0] =~ /^(\S+):(\d+)$/ &&
			       $1 eq $oldd->{'ip'}) {
				$l->{'words'}->[0] = $d->{'ip'}.":".$2;
			}
		}
		&save_directive($server, "listen", \@listen);

		# Remove IP in server_names
		my $obj = &find("server_name", $server);
		my $idx = &indexof($oldd->{'ip'}, @{$obj->{'words'}});
		if ($idx >= 0) {
			splice(@{$obj->{'words'}}, $idx, 0);
			&save_directive($server, "server_name", [ $obj ]);
		}
	}
}
# Fix up home directory if changed
if ($oldd && $d->{'home'} ne $oldd->{'home'}) {
	# Get number of server blocks
    my @numserv = &find_server_count($d);
    # Loop through server blocks
    foreach my $server (@numserv) {
		&recursive_change_directives($server, $oldd->{'home'}, $d->{'home'}, 0, 0, 0);
		&recursive_change_directives($server, $oldd->{'home'}.'/', $d->{'home'}.'/', 0, 1,0);
	}
}

&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
&$virtual_server::second_print($virtual_server::text{'setup_done'});
    
# Correct system-specific entries in PHP config files
if (!$config{'php_fpm'}) {
	if ($oldd) {
		my $sock = &virtual_server::get_php_mysql_socket($d);
		my @fixes = (
		  [ "session.save_path", $oldd->{'home'}, $d->{'home'}, 1 ],
		  [ "upload_tmp_dir", $oldd->{'home'}, $d->{'home'}, 1 ],
		  );
		if ($sock ne 'none') {
			push(@fixes, [ "mysql.default_socket", undef, $sock ]);
		}
		&virtual_server::fix_php_ini_files($d, \@fixes);
	}
}

# Fix broken PHP extension_dir directives
&virtual_server::fix_php_extension_dir($d);

if (!$config{'php_fpm'}) {
	# Restart PHP server, in case php.ini got changed by the restore
	&feature_restart_web_php($d);
}

# Restore log files
if (-r $file."_alog") {
	&$virtual_server::first_print($text{'feat_restorelog'});
	&copy_source_dest($file."_alog", $alog);
	&set_nginx_log_permissions($d, $alog);
	if (-r $file."_elog") {
		&copy_source_dest($file."_elog", $elog);
		&set_nginx_log_permissions($d, $elog);
		}
	&$virtual_server::second_print($virtual_server::text{'setup_done'});
	}

return 1;
}

# feature_clone(&domain, &old-domain)
# Create a new Nginx virtualhost that copies from this one one
sub feature_clone
{
my ($d, $oldd) = @_;
&$virtual_server::first_print($text{'feat_clone'});
if ($d->{'alias'}) {
	# Nothing needs to be done, as the re-create as part of the cloning
	# will already have done everything
	&$virtual_server::second_print($text{'feat_clonealias'});
	return 1;
	}
&lock_all_config_files();
my $server = &find_domain_server($d);
if (!$server) {
	&unlock_all_config_files();
	&$virtual_server::second_print(&text('feat_efind', $d->{'dom'}));
	return 0;
	}
my $oldserver = &find_domain_server($d);
if (!$oldserver) {
	&unlock_all_config_files();
	&$virtual_server::second_print(&text('feat_efind', $oldd->{'dom'}));
	return 0;
	}

# Preserve some settings from the clone target
my $alog = &get_nginx_log($d, 0);
my $elog = &get_nginx_log($d, 1);
my $obj = &find("server_name", $server);

# Copy across all directives to the new server block, fixing the server_name
# so that it can be found
my $oldlref = &read_file_lines($oldserver->{'file'}, 1);
my $lref = &read_file_lines($server->{'file'});
my @lines = @$oldlref[$oldserver->{'line'}+1 .. $oldserver->{'eline'}-1];
foreach my $l (@lines) {
	if ($l =~ /^(\s*server_name\s+)/) {
		$l = $1.&join_words(@{$obj->{'words'}}).';';
		}
	}
splice(@$lref, $server->{'line'}+1, $server->{'eline'}-$server->{'line'}-1,
       @lines);
&flush_file_lines($server->{'file'});
&flush_config_cache();

# Re-get the new server block
$server = &find_domain_server($d);
if (!$server) {
	&unlock_all_config_files();
	&$virtual_server::second_print(&text('feat_eclonefind', $d->{'dom'}));
	return 0;
	}

# Put back old log file paths
&save_directive($server, "access_log", [ $alog ]) if ($alog);
&save_directive($server, "error_log", [ $elog ]) if ($elog);

# Fix home dir, which is incorrect in copied directives
&recursive_change_directives(
	$server, $oldd->{'home'}, $d->{'home'}, 0, 0, 0);
&recursive_change_directives(
	$server, $oldd->{'home'}.'/', $d->{'home'}.'/', 0, 1, 0);

# Fix domain name, which is incorrect in copied directives
&recursive_change_directives($server, $oldd->{'dom'},
			     $d->{'dom'}, 0, 0, 1);

# Fix PHP server port, which is incorrect in copied directives
my ($l) = grep { $_->{'words'}->[1] eq '\.php$' }
	       &find("location", $server);
if ($l) {
	&save_directive($l, "fastcgi_pass",
		$d->{'nginx_php_port'} =~ /^\d+$/ ?
		    [ "localhost:".$d->{'nginx_php_port'} ] :
		    [ "unix:".$d->{'nginx_php_port'} ]);
	}

&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);

&$virtual_server::second_print($virtual_server::text{'setup_done'});
return 1;
}

# feature_set_web_public_html_dir(&domain, subdir)
# Change the root path in the domain's server object
sub feature_set_web_public_html_dir
{
my ($d, $subdir) = @_;
my $server = &find_domain_server($d);
$server || return &text('redirect_efind', $d->{'dom'});
&lock_all_config_files();
&save_directive($server, "root", [ $d->{'home'}."/".$subdir ]);
&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);
return undef;
}

# feature_find_web_html_cgi_dirs(&domain)
# Use the root path in the domain's server to set public_html_dir and
# public_html_path
sub feature_find_web_html_cgi_dirs
{
my ($d) = @_;
my $server = &find_domain_server($d);
return undef if (!$server);
$d->{'public_html_path'} = &find_value("root", $server);
if ($d->{'public_html_path'} =~ /^\Q$d->{'home'}\E\/(.*)$/) {
	$d->{'public_html_dir'} = $1;
	}
elsif ($d->{'public_html_path'} eq $d->{'home'}) {
	# Same as home directory!
	$d->{'public_html_dir'} = ".";
	}
else {
	delete($d->{'public_html_dir'});
	}
}

# feature_change_web_access_log(&domain, logfile)
# Update the access log location
sub feature_change_web_access_log
{
my ($d, $logfile) = @_;
return &change_nginx_log_file($d, $logfile, "access_log");
}

# feature_change_web_error_log(&domain, logfile)
# Update the error log location
sub feature_change_web_error_log
{
my ($d, $logfile) = @_;
return &change_nginx_log_file($d, $logfile, "error_log");
}

# feature_supports_sni([&domain])
# Returns 1 if Nginx supports SNI
sub feature_supports_sni
{
my $out = &backquote_command("$config{'nginx_cmd'} -V 2>&1 </dev/null");
return $out =~ /TLS\s+SNI\s+support\s+enabled/i ? 1 : 0;
}

# change_nginx_log_file(&domain, file, name)
# Changes the log file for an access or error log
sub change_nginx_log_file
{
my ($d, $logfile, $name) = @_;

# Update Nginx config
my $server = &find_domain_server($d);
$server || return &text('redirect_efind', $d->{'dom'});
&lock_all_config_files();
my $obj = &find($name, $server);
my @w = $obj ? @{$obj->{'words'}} : ( );
my $old_logfile = shift(@w);
&save_directive($server, $name,
		[ { 'name' => $name,
		    'words' => [ $logfile, @w ] } ]);
&flush_config_file_lines();
&unlock_all_config_files();
&virtual_server::register_post_action(\&print_apply_nginx);

# Actually move the file
if ($old_logfile && (!&same_file($logfile, $old_logfile) || -l $logfile)) {
        if (-e $logfile) {
                &unlink_file($logfile);
                }
        if (-r $old_logfile) {
                &rename_logged($old_logfile, $logfile);
                }
        }

# Fix logrotate config
if ($d->{'logrotate'}) {
        my $lconf = &virtual_server::get_logrotate_section($old_logfile);
        if ($lconf) {
                my $parent = &logrotate::get_config_parent();
                foreach my $n (@{$lconf->{'name'}}) {
                        if ($n eq $old_logfile) {
                                $n = $logfile;
                                }
                        }
                &logrotate::save_directive($parent, $lconf, $lconf);
                &flush_file_lines($lconf->{'file'});
                }
        }

return undef;
}

# set_nginx_log_permissions(&domain, file)
# Sets the correct user and group perms on a log file
sub set_nginx_log_permissions
{
my ($d, $log) = @_;
my $web_user = &get_nginx_user();
my @uinfo = getpwnam($web_user);
my $web_group = getgrgid($uinfo[3]) || $uinfo[3];
&set_ownership_permissions($d->{'uid'}, $web_group, 0660, $log);
}

# domain_server_names(&domain)
# Returns the list of server_name words for a domain
sub domain_server_names
{
my ($d) = @_;
return ( $d->{'dom'}, "www.".$d->{'dom'} );
}

# get_nginx_log(&domain, [errorlog])
# Returns the location of a log file for a domain's virtual host, or undef.
sub get_nginx_log
{
my ($d, $want_error) = @_;
my $s = &find_domain_server($d);
if ($s) {
	return &find_value($want_error ? "error_log" : "access_log", $s);
	}
return undef;
}

# get_nginx_user()
# Returns the use nginx runs as
sub get_nginx_user
{
my $conf = &get_config();
my $user = &find_value("user", $conf);
$user ||= &get_default("user");
return $user;
}

# setup_nginx_proxy_pass(&domain)
# Add proxying or frame forward directives for a domain, if enabled
sub setup_nginx_proxy_pass
{
my ($d) = @_;
if (!$d->{'proxy_pass_mode'}) {
	return undef;
	}
elsif ($d->{'proxy_pass_mode'} == 1) {
	# Add proxy
	return &feature_create_web_balancer($d,
		{ 'path' => '/', 'urls' => [ $d->{'proxy_pass'} ] });
	}
elsif ($d->{'proxy_pass_mode'} == 2) {
	# Add frame forward
	my $server = &find_domain_server($d);
	$server || return &text('redirect_efind', $d->{'dom'});
	&lock_all_config_files();
	&virtual_server::create_framefwd_file($d);
	my $ff = &virtual_server::framefwd_file($d);
	my $phd = &virtual_server::public_html_dir($d);
	$ff =~ s/^\Q$phd\E//;
	&save_directive($server, [ ],
		[ { 'name' => 'rewrite',
		    'words' => [ '^/.*$', $ff, 'break' ] } ]);
	&flush_config_file_lines();
	&unlock_all_config_files();
	&virtual_server::register_post_action(\&print_apply_nginx);
	}
else {
	return "Unknown proxy mode $d->{'proxy_pass_mode'}";
	}
}

# remove_nginx_proxy_pass(&domain)
# Remove enabled proxying or frame forward directives for a domain
sub remove_nginx_proxy_pass
{
my ($d) = @_;
if (!$d->{'proxy_pass_mode'}) {
	return undef;
	}
elsif ($d->{'proxy_pass_mode'} == 1) {
	# Remove proxy for /
	my @bals = &feature_list_web_balancers($d);
	my ($balancer) = grep { $_->{'path'} eq '/' } @bals;
	return &feature_delete_web_balancer($d, $balancer) if ($balancer);
	return undef;
	}
elsif ($d->{'proxy_pass_mode'} == 2) {
	# Remove frame forward
	my $server = &find_domain_server($d);
	$server || return &text('redirect_efind', $d->{'dom'});
	&lock_all_config_files();
	my $ff = &virtual_server::framefwd_file($d);
	my $phd = &virtual_server::public_html_dir($d);
	$ff =~ s/^\Q$phd\E//;
	my ($rewrite) = grep { $_->{'words'}->[0] eq '^/.*$' &&
			       $_->{'words'}->[1] eq $ff }
			     &find("rewrite", $server);
	if ($rewrite) {
		&save_directive($server, [ $rewrite ], [ ]);
		}
	&flush_config_file_lines();
	&unlock_all_config_files();
	&virtual_server::register_post_action(\&print_apply_nginx);
	return undef;
	}
else {
	return "Unknown proxy mode $d->{'proxy_pass_mode'}";
	}
}

sub fix_server_name_line
{
my ($l, $adoms) = @_;
if ($l =~ /^(\s*)server_name(\s+.*);/) {
	# Exclude server_name entries for alias domains
	my $indent = $1;
	my @sa = &split_words($2);
	@sa = grep { !($adoms->{$_} ||
		       /^([^\.]+)\.(\S+)/ && $adoms->{$2}) } @sa;
	return undef if (!@sa);
	$l = $indent."server_name ".&join_words(@sa).";";
	}
return $l;
}

1;

