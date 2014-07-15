<?php
class ldap_class
{
	public $server 		= "";		#LDAP Server IP
	public $port   		= "";		#LDAP Port Number 
	public $basedn 		= "";		#LDAP Base Distinguish Name
	public $username 	= "";		#LDAP Username
	public $password 	= "";		#LDAP Password
	public $secure_type = false;	#To know if the LDAP Server has LDAP Username/Password
	
	function set_account($status = null, $username = null, $password = null)
	{
		/***
		Purpose: To store the Ldap Username and Ldap Password
		***/
		if($status==true)
		{
			$this->username 	= $username;
			$this->password 	= $password;
			$this->secure_type 	= true;
		}
	}

	function auth_type($service = null)
	{
		/***
		Purpose: To select which Server and connection will be going to use
		***/
		switch($service)
		{
			case "CONTAINER1":
				 $this->server = "x.x.x.x";
				 $this->port   = 389;
				 $this->basedn = "ou=groups,dc=nucloudglobal,dc=com";
				 break;
			default:
				 $this->server = "127.0.0.1";
				 $this->port   = 389;
				 $this->basedn = "ou=groups,dc=example,dc=com";
				 break;
		}
	}

	function connection()
	{
		/***
		Purpose: This is the connection in LDAP Server.
		***/
		$ldap_conn =ldap_connect( $this->server, $this->port );
		ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, 3);

		return $ldap_conn;
	}

	function authenticate_account($data)
	{	
		/***
		Purpose: To authenticate the username and password in the LDAP Server, 
				 even this is a Secure Connection or Anonymous Connection.
		***/
		error_reporting(0);
		$ldap_conn 	= $this->connection();

		$user      = $data['txt_user'];
		$filter	   = "(|(mail=" . $user ."))";
		$justthese = array(
							"givenname",
							"sn",
							"mail",
							"uid",
							"uidnumber",
							"gidnumber",
							"displayname"
						  );
		if($this->secure_type==true)
		{
		/**
		SECURE AUTHENTICATION
		**/
				#ACCESS THE RECORD USING LDAP ACCOUNT
				$ldapbind = ldap_bind($ldap_conn, $this->username, $this->password);
				if($ldapbind)
				{
					#SEARCH THE RECORD USING LDAP ACCOUNT
					$search   = ldap_search($ldap_conn, $this->basedn, $filter, $justthese);
					#FETCH THE RECORD TO GET THE UID WITH DN 
					#Ex: uid=jbaltazar,ou=Groups,dc=zentyal-domain,dc=lan
					$entries  = ldap_get_entries($ldap_conn, $search);

					#CHECK IF THE EMAIL IS ALREADY IN THE LDAP BDB
					if($entries['count']==1)
					{
						#CHECK IF THE PASSWORD IS SAME
						$check_password = ldap_bind($ldap_conn, $entries[0]["dn"], $data['txt_pass']);
						if($check_password){
							$this->show_record($entries,$data['txt_pass']);
						}else{
							$this->show_no_record($user,true);
						}
					}else{
						$this->show_no_record($user);
					}
				}
		}else{
			/**
			UNSECURE AUTHENTICATION
			**/
			#SEARCH THE RECORD USING LDAP ACCOUNT IN GENERAL
			$search 	= ldap_search($ldap_conn, $this->basedn, $filter, $justthese);
			#FETCH THE RECORD TO GET THE UID WITH DN 
			#Ex: uid=jbaltazar,ou=Groups,dc=zentyal-domain,dc=lan
			$entries    = ldap_get_entries($ldap_conn, $search);
			#CHECK IF DN IS NOT NULL
			if(isset($entries[0]["dn"]))
			{
				#TEST IF THE PASSWORD IS CORRECT
				$ldapbind = ldap_bind($ldap_conn, $entries[0]["dn"], $data['txt_pass']);
				if($ldapbind)
				{
					$this->show_record($entries,$data['txt_pass']);
				}else{
					$this->show_no_record($user,true);
				}
			}else{
				$this->show_no_record($user);
			}
		}

		#CLOSE CONNECTION
		ldap_close($ldap_conn);
	}

	function show_no_record($user,$password = null)
	{
		/***
		Purpose: To print the No Record content.
		***/
		if($password==true)
		{
			echo "Invalid Password for <b>" . $user . "</b>.";
		}else{
			echo "Failed authentication for <b>" . $user . "</b>.";
		}
		echo "<br><a href='index.php'>Back to Login</a>";
	}

	function show_record($entries,$password)
	{
		/***
		Purpose: To print all record coming from the LDAP Server
		***/
		echo "<span style='color:green;font-weight:bold;'>Successful authentication for " . $entries[0]['mail'][0] . ".</span>";
		echo "<br><strong>Account Details</strong>";
		echo "<ul>";
		echo "<li>First Name: ".$entries[0]['givenname'][0]." </li>";
		echo "<li>Last Name: ".$entries[0]['sn'][0]." </li>";
		echo "<li>Email: ".$entries[0]['mail'][0]." </li>";
		echo "<li>Password: ".$password."</li>";
		echo "<li>UID: ".$entries[0]['uid'][0]." </li>";
		echo "<li>UID Number: ".$entries[0]['uidnumber'][0]." </li>";
		echo "<li>GID Number: ".$entries[0]['gidnumber'][0]." </li>";
		echo "</ul>";					
		echo "<br><a href='index.php'>Back to Login</a>";
		echo "<hr><b>Full Record Detail</b><br>";
		echo "<pre>"; print_r($entries); echo "</pre>";
	}
}
