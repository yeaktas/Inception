#!/bin/bash

service mariadb start

if [ $? -eq 0 ]; then

    SECURE_MYSQL=$(expect -c "
        set timeout 10
        spawn mysql_secure_installation
        expect \"Enter current password for root (enter for none):\"
        send \"\r\"
        expect \"Switch to unix_socket authentication\"
        send \"n\r\"
        expect \"Change the root password?\"
        send \"y\r\"
        expect \"New password:\"
        send \"$DB_ROOT_PASSWORD\r\"
        expect \"Re-enter new password:\"
        send \"$DB_ROOT_PASSWORD\r\"
        expect \"Remove anonymous users?\"
        send \"y\r\"
        expect \"Disallow root login remotely?\"
        send \"y\r\"
        expect \"Remove test database and access to it?\"
        send \"y\r\"
        expect \"Reload privilege tables now?\"
        send \"y\r\"
        expect eof
    ")

    echo "$SECURE_MYSQL"

    mysql -uroot -p$DB_ROOT_PASSWORD <<EOF
        ALTER USER 'root'@'localhost' IDENTIFIED BY '$DB_ROOT_PASSWORD';
        CREATE DATABASE IF NOT EXISTS $DB_DATABASE;
        CREATE USER IF NOT EXISTS '$DB_USER_NAME'@localhost IDENTIFIED BY '$DB_USER_PASSWORD';
        GRANT ALL PRIVILEGES ON $DB_DATABASE.* TO '$DB_USER_NAME'@'%' IDENTIFIED BY '$DB_USER_PASSWORD';
        FLUSH PRIVILEGES;
EOF

    service mariadb stop

    mysqld

else
    exit 1

fi
