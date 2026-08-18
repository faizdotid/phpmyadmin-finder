package main

import "regexp"

// Subdomains are probed as <sub>.<hostname> (no port).
var subdomains = []string{
	"adminer",
	"pma",
	"db",
	"dbadmin",
	"sql",
	"mysql",
	"mysqlmanager",
	"mariadb",
	"phpmyadmin",
}

// Paths are appended to the full host (including port, if any).
var paths = []string{
	"/admin/phpmyadmin/",
	"/phpmyadmin/",
	"/phpMyAdmin/",
	"/phpmyadmin/index.php",
	"/phpMyAdmin/index.php",
	"/adminer.php",
	"/adminer/",
	"/phpMyAdmin.php",
	"/phpmyadmin.php",
	"/pma.php",
	"/PMA/",
	"/pma/",
	"/myadmin/",
	"/database/",
	"/db/phpmyadmin/",
	"/sqlmanager/",
	"/mysqlmanager/",
	"/php-myadmin/",
	"/phpmy/",
	"/mysqladmin/",
	"/mysql-admin/",
	"/admin/mysql/",
	"/admin/mysql/index.php",
	"/admin/pma/",
	"/admin/db/",
	"/admin/adminer.php",
	"/mysql/db/",
	"/mysql/pma/",
	"/sql/myadmin/",
	"/sql/php-myadmin/",
	"/sql/phpMyAdmin/",
	"/sql/phpmyadmin/",
	"/db/myadmin/",
	"/db/phpMyAdmin/",
}

// markersRe detects phpMyAdmin / Adminer login pages specifically.
var markersRe = regexp.MustCompile(
	`(?i)pma_username|pma_password|auth\[username]|auth\[password]|server_select|` +
		`phpMyAdmin|PMA_token|pma_servername|input_username|input_password|` +
		`mysql-admin|adminer|MariaDB administration`,
)
