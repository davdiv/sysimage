#!/bin/sh
# initqueue hook: apply /etc/veritytab to create dm-verity mapper devices.
#
# Runs on each initqueue iteration until every entry succeeds, then stops
# retrying. The verity devices must appear before dracut looks for the root
# device (e.g. /dev/mapper/rootfs), so this runs in the initqueue phase —
# before root mount.

if [ ! -f /etc/veritytab ]; then
    exit 0
fi

[ -f /run/veritytab-apply.done ] && exit 0

if /usr/sbin/veritytab-apply.sh /etc/veritytab; then
    mkdir -p /run
    echo "" > /run/veritytab-apply.done
fi
