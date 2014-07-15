<link rel="stylesheet" type="text/css" href="style.css" />
<div class="header_part"></div>
<?php
require_once("ldap_class.php");

# LEGEND OF CONNECTION
# CONTAINER1 = OpenLDAP by Docker

$ldap_code = new ldap_class;
#THIS IS FOR LDAP WITH ACCOUNT INFO AND NOT ANONYMOUS ACCOUNT
$ldap_code->set_account(false,'cn=nucloud,dc=example,dc=com','password');
$ldap_code->auth_type('CONTAINER1');
$ldap_code->authenticate_account($_POST);
?>