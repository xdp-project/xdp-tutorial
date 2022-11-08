#!/usr/bin/env bash

#
# Install required packages
#
dnf install -y \
    bc \
    bpftool \
    clang \
    elfutils-libelf-devel \
    emacs-nox \
    fedora-packager \
    fedpkg \
    flex bison \
    kernel-headers \
    libpcap-devel \
    llvm \
    ncurses-devel \
    openssl-devel \
    perf \
    pesign \
    rpmdevtools

#
# Initialize the extra disk needed to build the kernel
#
if ! grep -q $(blkid /dev/sdb1 -o value -s UUID) /etc/fstab
then
    parted /dev/sdb mklabel gpt
    parted /dev/sdb mkpart primary 0% 100%
    mkfs.xfs /dev/sdb1
    mkdir /data
    echo "UUID=$(blkid /dev/sdb1 -o value -s UUID) /data                   xfs     defaults        0 0" >> /etc/fstab
    mount /data
fi

#
# Build the latest bpf-next kernel
#
cd /data
git clone https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git linux_kernel
# This was successfully tested with commit bdb15a29cc28f8155e20f7fb58b60ffc452f2d1b
cd linux_kernel
cp /boot/config-$(uname -r) .config
make olddefconfig
make -j $(nproc) bzImage
make -j $(nproc) modules
make modules_install
make headers_install
make install

#
# Boot the new kernel, and make sure IPv6 is enabled
#
grubby --set-default-index=1
sed -i 's/net.ipv6.conf.all.disable_ipv6 = 1/net.ipv6.conf.all.disable_ipv6 = 0/g' /etc/sysctl.conf
