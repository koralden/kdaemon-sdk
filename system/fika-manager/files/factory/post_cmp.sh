#!/bin/sh

DEBUG=0

my_log() {
    level=$1 && shift

    [ -e /dev/log ] && logger -s -t fika-manager -p ${level} "$@"
    echo "[fika-manager][${level}] $@"

    [ $DEBUG -eq 1 ] && echo "[fika-manager][${level}] $@" >>/tmp/factory.log
}

my_log debug "[$0] $@"
