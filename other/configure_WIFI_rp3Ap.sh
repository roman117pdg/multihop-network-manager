#!/bin/bash

sudo touch /media/mikolaj/boot/ssh
sudo touch /media/mikolaj/boot/wpa_supplicant.conf
echo "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=PL

network={
	ssid=\"SSID_NAME\"
	psk=\"PASSWORD\"
	key_mgmt=WPA-PSK
}" > /media/mikolaj/boot/wpa_supplicant.conf
echo 'denyinterfaces wlan0' | sudo tee --append /media/mikolaj/rootfs/etc/dhcpcd.conf
echo "raspberrypi_ANT" > /media/mikolaj/rootfs/etc/hostname
echo "127.0.0.1	localhost
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters

127.0.1.1		raspberrypi_ANT" > /media/mikolaj/rootfs/etc/hosts 
