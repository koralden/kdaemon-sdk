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
