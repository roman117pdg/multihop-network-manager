import time
import random
import uuid
import subprocess
import logger

class AdhocInit:
    
    def __init__(self, main_logger, iface_babel, iface_gateway, gateway, essid, wep_key, cell_id, channel):
        """AdhocInit initial function.

        Args:
            main_logger: Pointer to main logger class.
            iface_babel: String value of babel interface name (i.e. "wlan0").
            iface_gateway: String value of gateway interface name (i.e. "eth0").
            gateway: String value of ipv4 gateway destination  (i.e. "169.254.1.1").
            channel: String value of number of WLAN channel (1-14).
            essid: String value of essid name.
            wep_key: String value of WEP key used for encryption.
            cell_id: String value of cell/ap id.
        """
        self.main_logger = main_logger
        self.IFACE_BABEL = iface_babel
        self.IFACE_GATEWAY = iface_gateway
        self.GATEWAY = gateway
        self.ESSID = essid
        self.WEP_KEY = wep_key
        self.CELL_ID = cell_id
        self.CHANNEL = channel
        self.IPV6 = ""
        self.IPV4 = ""


    def get_mac_from_inter(self, interface):
        """Get MAC address value from interface name.

        Args:
            interface: String value of interface name (i.e. "wlan0").

        Returns:
            String value of MAC address.
        """
        try:
            ifconfig_cmd = "sudo ifconfig "+interface
            proc = subprocess.Popen(ifconfig_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = proc.stdout.read().decode()
            error = proc.stderr.read().decode()
            if error != "":
                self.main_logger.error("Error occure while reading model of a device, error: "+str(error)) 
            mac = output.split("ether ")[1].split("  txqueuelen")[0]
            return mac
        except Exception as e:
            self.main_logger.error('Error occure while reading MAC, excption: '+str(e))


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


    def get_mac_from_ipv6(self, ipv6):
        """Get IPv6 value from MAC address. Inverse of the function get_ipv6_from_mac().

        Args:
            ipv6: string value of IPv6 address.

        Returns:
            Computed string value of MAC addres.
        """
        table_ipv6 = ipv6.split("::")[1].split(":")
        first_octet = bin(int(table_ipv6[0][0:2],16))[2:]
        inv_bit = "1" if first_octet[6] == "0" else "0"
        first_octet = first_octet[:6] + inv_bit + first_octet[7:]
        mac = str(hex(int(first_octet,2))[2:])
        mac += ":"+str(table_ipv6[0][2:4])+":"+str(table_ipv6[1][0:2])+":"+str(table_ipv6[2][2:4])+":"+str(table_ipv6[3][0:2])+":"+str(table_ipv6[3][2:4])
        return mac


    def get_ipv4_from_mac(self, mac):
        """Get IPv4 value from MAC address. https://datatracker.ietf.org/doc/html/rfc3927

        Args:
            mac: String value of MAC addres.

        Returns:
            Computed string value of IPv4 address.
        """
        # save MAC address as octets table 
        table_mac = mac.split(":")
        # change 3 last osctets to int value
        int_mac = int(table_mac[3],16)*255*255 + int(table_mac[4],16)*255 + int(table_mac[5],16)
        # set mac addr as seed
        random.seed(int_mac % 2**32)
        # calculate pseudo random number
        rand_num = random.randint(1,255*255)
        # set number as ipv4 string
        ipv4_str = "169.254."+str(int(rand_num/255))+"."+str(int(rand_num%255))
        # set time as seed (random seed)
        random.seed()
        return ipv4_str


    def read_serial_num(self):
        """Reads serail number of device."""
        try:
            ifconfig_cmd = "sudo cat /proc/cpuinfo"
            proc = subprocess.Popen(ifconfig_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = proc.stdout.read().decode()
            error = proc.stderr.read().decode()
            if error != "":
                self.main_logger.error("Error occure while reading model of a device, error: "+str(error))        
            sn = output.split("Serial\t\t: ")[1].split("\nModel\t\t: ")[0]
            return sn
        except Exception as e:
            self.main_logger.error('Error occure while reading serial number, excption: '+str(e))
    
    
    def read_dev_model(self):
        """Reads model of device."""
        try:
            ifconfig_cmd = "sudo cat /proc/cpuinfo"
            proc = subprocess.Popen(ifconfig_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = proc.stdout.read().decode()
            error = proc.stderr.read().decode()
            if error != "":
                self.main_logger.error("Error occure while reading model of a device, error: "+str(error))                
            model = output.split("\nModel\t\t: ")[1]
            return model
        except Exception as e:
            self.main_logger.error('Error occure while reading model of a device, excption: '+str(e))


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
            proc = subprocess.Popen(cmd_set_net, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error = proc.stderr.read().decode()
            if error != "":
                self.main_logger.error("Error occure while setting ad-hoc network, error: "+str(error))
            else:
                self.main_logger.info('AD-HOC network has been set up:')
        except Exception as e:
            self.main_logger.error('Error occure while setting ad-hoc network, excption: '+str(e))


    def ifconfig_int_state(self, interface, state):
        """Runs ifconfig command to change interface state.

        Args:
            interface: String value of interface name (i.e. "wlan0").
            state: String value of interface state ("up" or "down").
        """
        try:
            cmd_interface_up = "sudo ifconfig "+interface+" "+state
            proc = subprocess.Popen(cmd_interface_up, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error = proc.stderr.read().decode()
            if error != "":
                self.main_logger.error("Error occure while setting "+interface+" "+state+", error: "+str(error))
            else:
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
            proc = subprocess.Popen(cmd_set_ip, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error = proc.stderr.read().decode()
            if error != "":
                self.main_logger.error('Error occure while setting ip address, error: '+str(error))
            else:
                self.main_logger.info('ip:'+ip+" was "+action+" to/from "+interface)
        except Exception as e:
            self.main_logger.error('Error occure while setting ip address, exception: '+str(e))


    def is_equal_ipv6(self, ip_1, ip_2):
        """Checks if two IPv6 addreses are equal.

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


    def is_equal_ipv4(self, ip_1, ip_2):
        """Checks if two IPv4 addreses are equal.

        Args:
            ip_1, ip_2: String value of IPv4 address.

        Returns:
            Boolean value: True if they are equal or False if they are not.
        """
        ip1_t = ip_1.split(".")
        ip2_t = ip_2.split(".")
        for i in range(min(len(ip1_t), len(ip2_t))):
                if int("0"+ip1_t[i]) != int("0"+ip2_t[i]):
                    return False
        return True


    def wait_for_autoipv6(self):
        """Waits until ipv6 is autoconfigured. Every interface have autoconfigured ipv6 after it is set up. 
        In this program we don't want autoconfigured ipv6. That is why program waits for this to delete autoconfigured ipv6 and set proper ipv6."""
        self.main_logger.info('Waiting for autoconfigured ipv6 [this may take 10s]')
        ipv6_t = []
        try:
            for i in range(20):
                cmd = "ip addr show wlan0"
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output = proc.stdout.read().decode()
                error = proc.stderr.read().decode()
                if error != "":
                    self.main_logger.error('Error occure while waiting for autoconfigured ipv6, error: '+str(error))
                ipv6_split = output.split("inet6 ")
                if len(ipv6_split) > 1:
                    ipv6 = ipv6_split[1].split("/")[0]
                    return(ipv6)
                else:
                    time.sleep(0.5)
            return ''
        except Exception as e:
            self.main_logger.error('Error occure while waiting for autoconfigured ipv6, exception: '+str(e))


    def read_ipv4(self, interface):
        """Reads value of ipv4 on given interface. If any ipv4 is set then return false."""
        try:
            ifconfig_cmd = "ifconfig "+interface
            proc = subprocess.Popen(ifconfig_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = proc.stdout.read().decode()
            error = proc.stderr.read().decode()
            if error != "":
                self.main_logger.error('Error occure while reading value of ipv4 on given interface, error: '+str(error))
            if output.find("inet ") == -1:
                return ""
            else: 
                ipv4 = output.split("inet ")[1].split("  netmask ")[0]
                return ipv4
        except Exception as e:
            self.main_logger.error('Error occure while reading value of ipv4 on given interface, exception: '+str(e))


    def enable_forwarding(self):
        """Runs commands in order to enable port forwarding."""
        try:
            cmd_1 = "sudo sysctl -w net.ipv4.ip_forward=1"
            proc = subprocess.Popen(cmd_1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error1 = proc.stderr.read().decode()
            cmd_1 = "sudo sysctl -w net.ipv6.conf.all.forwarding=1"
            proc = subprocess.Popen(cmd_1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error2 = proc.stderr.read().decode()
            cmd_2 = " iptables -A FORWARD -i wlan0 -j ACCEPT"
            proc = subprocess.Popen(cmd_2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error3 = proc.stderr.read().decode()
            if error1 != "" or error2 != "" or error3 != "":
                self.main_logger.error('Error occure while enabling ipv6/ipv4 forwarding, error1: '+str(error1)+', error2: '+str(error2)+', error3: '+str(error3))
            else:
                self.main_logger.info("ipv6 and ipv4 forwarding is enable")
        except Exception as e:
            self.main_logger.error('Error occure while enabling ipv6/ipv4 forwarding, exception: '+str(e))


    def read_interface_index(self, interface):
        """Runs command for reading value of interface index.

        Args:
            interface: String value of interface name (i.e. "wlan0").

        Returns:
            Integer value of interface index.
        """
        try:
            ifconfig_cmd = "cat /sys/class/net/"+interface+"/ifindex"
            proc = subprocess.Popen(ifconfig_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error = proc.stderr.read().decode()
            if error != "":
                self.main_logger.error('Error occure while reading interface index of '+str(interface)+', exception: '+str(error))
            output = proc.stdout.read().decode()
            index = int(output)
            return index
        except Exception as e:
            self.main_logger.error('Error occure while reading interface index of '+str(interface)+', exception: '+str(e))

    def unblock_interfaces(self):
        """Runs command for unblocking interfaces."""
        try:
            cmd_unblock = "sudo rfkill unblock all"
            proc = subprocess.Popen(cmd_unblock, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error = proc.stderr.read().decode()
            if error != "":
                self.main_logger.error('Error occure unblocking interfaces, error: '+str(error))
            else:
                self.main_logger.info("All interfaces are unblocked")
        except Exception as e:
            self.main_logger.error('Error occure unblocking interfaces, exception: '+str(e))


    def set_gateway(self, gateway, interface):
        """Setting internet gateway on given interface.

        Args:
            gateway: String value of gateway interface name (i.e. "eth0").
            interface: String value of babel interface name (i.e. "wlan0").
        """
        try:
            cmd_1 = "sudo iptables -A FORWARD -i "+str(interface)+" -o "+str(gateway)+" -j ACCEPT"
            proc = subprocess.Popen(cmd_1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error1 = proc.stderr.read().decode()
            cmd_1 = "sudo iptables -A FORWARD -i "+str(gateway)+" -o "+str(interface)+" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
            proc = subprocess.Popen(cmd_1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error2 = proc.stderr.read().decode()
            cmd_2 = "sudo iptables -t nat -A POSTROUTING -o "+str(gateway)+" -j MASQUERADE"
            proc = subprocess.Popen(cmd_2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error3 = proc.stderr.read().decode()
            if error1 != "" or error2 != "" or error3 != "":
                self.main_logger.error('Error occure while setting gateway '+str(gateway)+', error1: '+str(error1)+', error2: '+str(error2)+', error3: '+str(error3))
            else:
                self.main_logger.info("iptables rules for enabling gateway on"+str(gateway)+", were set")
        except Exception as e:
            self.main_logger.error('Error occure while setting gateway '+str(gateway)+', exception: '+str(e))


    def set_gateway_addr(self, gateway, interface):
        """Setting internet default internet gateway addr.

        Args:
            gateway: String value of gateway addr (i.e. "169.254.1.1"").
            interface: String value of babel interface name (i.e. "wlan0").
        """
        try:
            cmd = "sudo route add default gw "+str(gateway)+" "+str(interface)
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error = proc.stderr.read().decode()
            if error != "":
                self.main_logger.error('Error occure while setting default internet gateway addr set to'+str(gateway)+', error: '+str(error))
            else:
                self.main_logger.info("default internet gateway addr set to "+str(gateway)+'error: '+str(error))
        except Exception as e:
            self.main_logger.error('Error occure while setting default internet gateway addr set to'+str(gateway)+', exception: '+str(e))


    def run(self):
        """Runs function which are responsible for ad-hoc network configuration."""
        self.unblock_interfaces()
        self.ifconfig_int_state(interface=self.IFACE_BABEL, state="down")
        self.iwconfig_set_network(channel=self.CHANNEL, essid=self.ESSID, key=self.WEP_KEY, cell=self.CELL_ID)
        self.ifconfig_int_state(interface=self.IFACE_BABEL, state="up")
        auto_ipv6 = self.wait_for_autoipv6()
        mac = self.get_mac_from_inter(self.IFACE_BABEL)
        self.MAC = mac
        expected_ipv6 = self.get_ipv6_from_mac(mac)
        if self.is_equal_ipv6(auto_ipv6, expected_ipv6) == False:
            self.ifconfig_set_ip(ip=auto_ipv6, netmask="64", interface=self.IFACE_BABEL, action="del")
            self.ifconfig_set_ip(ip=expected_ipv6, netmask="64", interface=self.IFACE_BABEL, action="add")
        self.IPV6 = expected_ipv6
        self.main_logger.info(self.IFACE_BABEL+' ipv6 adress has been established:'+self.IPV6)
        self.enable_forwarding()
        self.IPV4 = self.get_ipv4_from_mac(self.MAC)
        self.main_logger.info('IPv4 addr: '+str(self.IPV4))
        if self.is_equal_ipv4(self.IPV4, self.read_ipv4(self.IFACE_BABEL)) == False:
            if self.read_ipv4(self.IFACE_BABEL) != "":
                self.ifconfig_set_ip(ip=self.read_ipv4(self.IFACE_BABEL), netmask="16", interface=self.IFACE_BABEL, action="del")
            self.ifconfig_set_ip(ip=self.IPV4, netmask="16", interface=self.IFACE_BABEL, action="add")
        self.SN = self.read_serial_num()
        self.main_logger.info('serial number: '+str(self.SN))
        self.model = self.read_dev_model()
        self.main_logger.info('model: '+str(self.model))
        self.IFACE_IDX = self.read_interface_index(interface=self.IFACE_BABEL)
        if self.IFACE_GATEWAY != 'None':
            self.main_logger.info('setting up gateway on '+str(self.IFACE_GATEWAY)+" interface")
            self.set_gateway(gateway=self.IFACE_GATEWAY, interface=self.IFACE_BABEL)
        if self.GATEWAY != 'None':
            self.main_logger.info('setting up defalut gateway addr '+str(self.GATEWAY))
            self.set_gateway_addr(gateway=self.GATEWAY, interface=self.IFACE_BABEL)


    def get_ipv6(self):
        """Returns string value of IPv6 address."""
        return self.IPV6


    def get_ipv4(self):
        """Returns string value of IPv4 address."""
        return self.IPV4


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

    
    def get_ipv4_from_ipv6(self, ipv6):
        """Get IPv4 address from ipv6 address."""
        mac = self.get_mac_from_ipv6(ipv6)
        return self.get_ipv4_from_mac(mac)
