#!/bin/sh

KDAEMON_TOML_PATH="/userdata/kdaemon.toml"
RULE_TOML_PATH="/etc/fika_manager/rule.toml"

fika_log() {
    level=$1 && shift

    if [ -e /dev/log ]; then
        logger -p ${level} -- "$@"
    else
        echo -- "[${level}] $@"
    fi
}

load_kdaemon_toml() {
    local conf

    conf=$KDAEMON_TOML_PATH
    [ $# -gt 0 ] && conf=$1
    eval "$(sed -e '/^\[/d' -e '/^#/d' -e '/^\s*$/d' -e 's,^,kdaemon_,g' -e 's, = ,=,g' $conf)"
}

update_kdaemon_toml() {
    key=$1
    val=$(echo $2 | sed 's,",\\",g')

    sed "s,^[\t #]*$key =.*$,$key = \"$val\",g" -i $KDAEMON_TOML_PATH && sync
}

# no double-quote
update_kdaemon_toml_no_dq() {
    key=$1
    val=$2

    #echo $val | grep -q -E "^[0-9]+$" && str=$val
    #echo $val | grep -q -i -E "(false)|(true)" && str=$val

    sed "s,^#*$key.*$,$key = $val,g" -i $KDAEMON_TOML_PATH && sync
}

#loop() {
#    for var in "$@"; do
#        echo "=>$var"
#    done
#}

fika_redis() {
    fika_log debug "[redis-cache] $#/$@"
    cmd=$1 && shift
    if [ $# -ge 1 ]; then
        key=$1 && shift
        if [ $# -ge 1 ]; then
            val1=$1 && shift
            if [ $# -ge 1 ]; then
                val2=$1 && shift
                if [ $# -ge 1 ]; then 
                    val3=$1 && shift
                    redis-cli ${cmd} "${key}" "${val1}" "${val2}" "${val3}" $@
                else
                    redis-cli ${cmd} "${key}" "${val1}" "${val2}"
                fi
            else
                redis-cli ${cmd} "${key}" "${val1}"
            fi
        else
            redis-cli ${cmd} "${key}"
        fi
    else
        redis-cli ${cmd}
    fi
}

fika_jq() {
    jq $@
}
