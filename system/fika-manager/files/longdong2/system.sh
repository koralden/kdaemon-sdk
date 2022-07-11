#!/bin/sh

account_modify() {
    echo "longdong account modify"
    password=$1 && shift

    username="admin"
    (echo $password ; sleep 1; echo $password) | passwd $username

    username="root"
    (echo $password ; sleep 1; echo $password) | passwd $username
}
