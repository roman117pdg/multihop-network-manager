#!/bin/bash

sudo touch /media/mikolaj/boot/ssh
echo 'denyinterfaces wlan0' | sudo tee --append /media/mikolaj/rootfs/etc/dhcpcd.conf
