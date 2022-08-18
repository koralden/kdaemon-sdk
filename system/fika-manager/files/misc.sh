#!/bin/sh

DEBUG=0

fika_log() {
    level=$1 && shift

    if [ -e /dev/log ]; then
        logger -p ${level} "$@"
    else
        echo "[${level}] $@"
    fi
}
