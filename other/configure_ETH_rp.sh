#!/bin/bash

sudo touch /media/<user>/boot/ssh
echo 'denyinterfaces wlan0' | sudo tee --append /media/<user>/rootfs/etc/dhcpcd.conf
