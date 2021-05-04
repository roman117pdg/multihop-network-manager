import time
import uuid
import subprocess
import logger

class AdhocInit:
    
    def __init__(self, main_logger):
        """AdhocInit initial function.

        Args:
            main_logger: Pointer to main logger class.
        """
        self.main_logger = main_logger
        self.IPV6 = ""


    def get_mac_from_inter(self, interface):
        """Get MAC address value from interface name.

        Args:
            interface: String value of interface name (i.e. "wlan0").

        Returns:
            String value of MAC address.
        """
        ifconfig_cmd = "sudo ifconfig "+interface
        proc = subprocess.Popen(ifconfig_cmd, shell=True, stdout=subprocess.PIPE)
        output = proc.stdout.read().decode()
        mac = output.split("ether ")[1].split("  txqueuelen")[0]
        return mac


    def get_ipv6_from_mac(self, mac):
        """Get IPv6 value from MAC address. Algorithm based on http://www.tcpipguide.com/free/t_IPv6InterfaceIdentifiersandPhysicalAddressMapping-2.htm.

        Args:
            mac: String value of MAC addres.

        Returns:
            Computed string value of IPv6 address.
        """
        # save MAC address as octets table 
        table_mac = mac.split(":")
        # add 2 special octets (they are implying that ipv6 is from MAC)
        table_mac.insert(3, "ff")
        table_mac.insert(4, "fe")
        # convert the first octet to bin
        first_octet = bin(int(table_mac[0],16))[2:]
        # invert 6-th bit
        inv_bit = "1" if first_octet[6] == "0" else "0"
        first_octet = first_octet[:6] + inv_bit + first_octet[7:]
        table_mac[0] = hex(int(first_octet,2))[2:]
        # create string with link-local prefix
        ipv6 = "fe80:"
        # write octets in ipv6 notation
        for i in range(4):
            ipv6 += ":"+table_mac[2*i]+table_mac[2*i+1]
        return ipv6


    def read_serial_num(self):
        """Reads serail number of device."""
        ifconfig_cmd = "sudo cat /proc/cpuinfo"
        proc = subprocess.Popen(ifconfig_cmd, shell=True, stdout=subprocess.PIPE)
        output = proc.stdout.read().decode()
        sn = output.split("Serial\t\t: ")[1].split("\nModel\t\t: ")[0]
        return sn
    
    def read_dev_model(self):
        """Reads model of device."""
        ifconfig_cmd = "sudo cat /proc/cpuinfo"
        proc = subprocess.Popen(ifconfig_cmd, shell=True, stdout=subprocess.PIPE)
        output = proc.stdout.read().decode()
        model = output.split("\nModel\t\t: ")[1]
        return model


    def iwconfig_set_network(self, channel, essid, key, cell):
        """Runs iwconfig command to set network.

        Args:
            channel: String value of number of WLAN channel (1-14).
            essid: String value of essid name.
            key: String value of WEP key used for encryption.
            cell: String value of cell/ap id.
        """
        try:
            # maybe add ap id
            cmd_set_net = "sudo iwconfig wlan0 mode ad-hoc essid "+essid+" key "+key+" channel "+channel+" ap "+cell
            subprocess.Popen(cmd_set_net, shell=True, stdout=subprocess.PIPE)
            self.main_logger.info('AD-HOC network has been set up:')
        except Exception as e:
            self.main_logger.error('Error occure while setting ad-hoc network excption: '+str(e))


    def ifconfig_int_state(self, interface, state):
        """Runs ifconfig command to change interface state.

        Args:
            interface: String value of interface name (i.e. "wlan0").
            state: String value of interface state ("up" or "down").
        """
        try:
            cmd_interface_up = "sudo ifconfig "+interface+" "+state
            subprocess.Popen(cmd_interface_up, shell=True, stdout=subprocess.PIPE)
            self.main_logger.info("interface "+interface+" is "+state)
        except Exception as e:
            self.main_logger.error("Error occure while setting "+interface+" "+state+", exception: "+str(e))


    def ifconfig_set_ip(self, ip, netmask, interface, action):
        """Runs ifconfig command to change ip address.

        Args:
            ip: String value of IPv6 address.
            netmask: String value of netmask value.
            interface: String value of interface name (i.e. "wlan0").
            action: String value of ip address action ("add" or "del").
        """
        try:
            # cmd_set_ip = "sudo ip "+action+" add "+ip+"/"+netmask+" dev "+interface <--- i think this is an error in syntax, but it have to be checked
            cmd_set_ip = "sudo ip addr "+action+" "+ip+"/"+netmask+" dev "+interface
            subprocess.Popen(cmd_set_ip, shell=True, stdout=subprocess.PIPE)
            self.main_logger.info('ip:'+ip+" was "+action+" to "+interface)
        except Exception as e:
            self.main_logger.error('Error occure while setting ip address, exception: '+str(e))


    def is_equal(self, ip_1, ip_2):
        """Checks if two IP addreses are equal.

        Args:
            ip_1, ip_2: String value of IPv6 address.

        Returns:
            Boolean value: True if they are equal or False if they are not.
        """
        ip1_t = ip_1.split(":")
        ip2_t = ip_2.split(":")
        for i in range(min(len(ip1_t), len(ip2_t))):
                if int("0"+ip1_t[i], 16) != int("0"+ip2_t[i], 16):
                    return False
        return True


    def wait_for_autoip(self):
        """Waits until ipv6 is autoconfigured. Every interface have autoconfigured ipv6 after it is set up. 
        In this program we don't want autoconfigured ipv6. That is why program waits for this to delete autoconfigured ipv6 and set proper ipv6."""
        self.main_logger.info('Waiting for autoconfigured ipv6 [this may take 10s]')
        ipv6_t = []
        for i in range(20):
            cmd = "ip addr show wlan0"
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            output = proc.stdout.read().decode()
            ipv6_split = output.split("inet6 ")
            if len(ipv6_split) > 1:
                ipv6 = ipv6_split[1].split("/")[0]
                return(ipv6)
            else:
                time.sleep(0.5)


    def enable_forwarding(self):
        """Runs commands in order to enable port forwarding."""
        try:
            cmd_1 = "sudo sysctl -w net.ipv6.conf.all.forwarding=1"
            subprocess.Popen(cmd_1, shell=True, stdout=subprocess.PIPE)
            cmd_2 = "sudo iptables -A FORWARD -i wlan0 -j ACCEPT"
            subprocess.Popen(cmd_2, shell=True, stdout=subprocess.PIPE)
            self.main_logger.info("ipv6 forwarding is enable")
        except Exception as e:
            self.main_logger.error('Error occure while enabling ipv6 forwarding, exception: '+str(e))


    def read_interface_index(self, interface):
        """Runs command for reading value of interface index.

        Args:
            interface: String value of interface name (i.e. "wlan0").

        Returns:
            Integer value of interface index.
        """
        ifconfig_cmd = "cat /sys/class/net/"+interface+"/ifindex"
        proc = subprocess.Popen(ifconfig_cmd, shell=True, stdout=subprocess.PIPE)
        output = proc.stdout.read().decode()
        index = int(output)
        return index


    def unblock_interfaces(self):
        """Runs command for unblocking interfaces."""
        try:
            cmd_unblock = "sudo rfkill unblock all"
            subprocess.Popen(cmd_unblock, shell=True, stdout=subprocess.PIPE)
            self.main_logger.info("All interfaces are unblocked")
        except Exception as e:
            self.main_logger.error('Error occure unblocking interfaces, exception: '+str(e))



    def run(self):
        """Runs function which are responsible for ad-hoc network configuration."""
        essid = "MESHNETWORK"
        wep_key = "55795d2076683f6a29516d2747"
        cell_id = "C6:7E:CC:0F:30:3E"
        channel = "1"
        interface = "wlan0"
        self.unblock_interfaces()
        self.ifconfig_int_state(interface=interface, state="down")
        self.iwconfig_set_network(channel=channel, essid=essid, key=wep_key, cell=cell_id)
        self.ifconfig_int_state(interface=interface, state="up")
        auto_ipv6 = self.wait_for_autoip()
        mac = self.get_mac_from_inter(interface)
        self.MAC = mac
        expected_ipv6 = self.get_ipv6_from_mac(mac)
        if self.is_equal(auto_ipv6, expected_ipv6) == False:
            self.ifconfig_set_ip(ip=auto_ipv6, netmask="64", interface=interface, action="del")
            self.ifconfig_set_ip(ip=expected_ipv6, netmask="64", interface=interface, action="add")
        self.IPV6 = expected_ipv6
        self.main_logger.info( interface+' ipv6 adress has been established:'+self.IPV6)
        self.enable_forwarding()
        self.SN = self.read_serial_num()
        self.main_logger.info('serial number: '+str(self.SN))
        self.model = self.read_dev_model()
        self.main_logger.info('model: '+str(self.model))
        self.IFACE_IDX = self.read_interface_index(interface=interface)


    def get_ipv6(self):
        """Returns string value of IPv6 address."""
        return self.IPV6


    def get_mac(self):
        """Returns string value of MAC address."""
        return self.MAC


    def get_iface_idx(self):
        """Returns integer value of interface index address."""
        return self.IFACE_IDX

    def get_sn(self):
        """Returns integer value of serial number."""
        return self.SN

    def get_model(self):
        """Returns string value of device model name."""
        return self.model
