#!/bin/sh

DEBUG=0

my_log() {
    level=$1 && shift

    if [ -e /dev/log ]; then
        logger -s -t fika-manager-recovery -p ${level} "$@"
    else
        echo "[fika-manager-recovery][${level}] $@"
    fi

    [ $DEBUG -eq 1 ] && echo "[fika-manager-recovery][${level}] $@" >>/tmp/factory.log
}

my_log debug "[$0] $@"

json=$1 && shift
key=$1 && shift

[ $(redis-cli EXISTS $key.done) -ne 0 ] && exit 0

rootUrl=$(echo $json | jq -r .root_url)
accessToken=$(echo $json | jq -r .access_token)
otpPath=$(echo $json | jq -r .otp_path)

sed -e "s,--api-url .*$ ,--api-url $rootUrl ," \
    -e "s,--access-token .*$ ,--access-token $accessToken ," \
    -e "s,--otp-path .*$ ,--otp-path $otpPath ," \
    -i /etc/init.d/fika-easy-setup

redis-cli SET $key.done ok

