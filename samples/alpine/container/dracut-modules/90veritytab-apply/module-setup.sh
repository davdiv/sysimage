#!/bin/bash
# 90veritytab-apply — apply /etc/veritytab at boot to open dm-verity volumes.
#
# Installs the veritytab-apply.sh script and an initqueue hook that runs it
# during early boot. The hook creates dm-verity mapper devices (e.g.
# /dev/mapper/rootfs) so the root filesystem can be mounted from a
# verity-protected volume.

check() {
    require_binaries veritysetup || return 1
    return 0
}

depends() {
    return 0
}

install() {
    inst_script "$moddir/veritytab-apply.sh" /usr/sbin/veritytab-apply.sh
    inst_hook initqueue 30 "$moddir/veritytab-apply-hook.sh"
    inst_multiple veritysetup
}