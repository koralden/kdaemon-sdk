#!/bin/sh

account_modify() {
    echo "longdong account modify"
    password=$1 && shift

    username="admin"
    (echo $password ; sleep 1; echo $password) | passwd $username

    username="root"
    (echo $password ; sleep 1; echo $password) | passwd $username
}

timezone_fix() {
    local timezone

    tz=$(uci get system.@system[-1].timezone)
    if [ "x$tz" != "xCST-8" ]; then
        uci batch << EOI
set system.@system[-1].zonename='Asia/Taipei'
set system.@system[-1].timezone='CST-8'
commit system
EOI
        /etc/init.d/system reload
    fi
}
