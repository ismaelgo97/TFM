<?php

# Database management system to use
$DBMS = 'MySQL';

# Database variables
$_DVWA = array();
$_DVWA[ 'db_server' ]   = 'db';
$_DVWA[ 'db_database' ] = 'dvwa';
$_DVWA[ 'db_user' ]     = 'dvwa';
$_DVWA[ 'db_password' ] = 'dvwa_pass';
$_DVWA[ 'db_port']      = '3306';

# ReCAPTCHA settings (not needed for local testing)
$_DVWA[ 'recaptcha_public_key' ]  = '';
$_DVWA[ 'recaptcha_private_key' ] = '';

# Default security level — low so all vulnerabilities are exposed for scanning
$_DVWA[ 'default_security_level' ] = 'low';

# Default locale
$_DVWA[ 'default_locale' ] = 'en';

# Disable authentication (false = keep login enabled for authenticated scan tests)
$_DVWA[ 'disable_authentication' ] = false;

define ('MYSQL', 'mysql');
define ('SQLITE', 'sqlite');

# SQLi backend
$_DVWA['SQLI_DB'] = MYSQL;

?>
