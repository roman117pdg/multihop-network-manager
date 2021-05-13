# multihop_network_app
Application for creating multihop network. The Babel protocol was used to manage routing. IEEE 802.11 Ad Hoc mode was used for node communication.

## STEP BY STEP INSTRUCTION OF INSTALLING AND RUNNING THIS PROGRAM ON RASPBERRY PI DEVICE

1. Insert sd card into the computer
2. Using Raspberry PI imager write **RASPBERRY PI OS 32 BIT** to the injected sd card
3. After successful writing take the card out and put it back (again into computer)
4. Download necessary files on computer
   
        $ wget https://raw.githubusercontent.com/roman117pdg/multihop-network-manager/main/other/configure_ETH_rp3B.sh https://raw.githubusercontent.com/roman117pdg/multihop-network-manager/main/other/configure_WIFI_rp3Ap.sh

5. Run ***"configure_WIFI_rp3Ap.sh"*** or ***"configure_ETH_rp3B.sh"*** bash script with root privileges (this script is setting wifi configuration and enabling ssh service)

        $ sudo ./configure_ANT_rp3ap.sh
        
6. Take the card out and insert it to Raspberry PI device
7. After turning Raspberry PI device on wait few minutes for the operating system to be installed
8. TRy to connect with Raspberry PI device using ssh (default user pi:raspberry)

        $ ssh pi@IP_ADDR_OF_DEVICE
    If you don't know ip address of Raspberry PI device than you can scann local network

        $ nmap -sn 192.168.1.0/24

   **If you have any problems in this step, this might mean that you had problems with headless start configuration. Try to connect Raspberry PI device to monitor and keyboard in order to find the problem that makes it impossible*

9.  After login in download necessary files on Raspberry PI device
   
        $ wget https://github.com/roman117pdg/multihop-network-manager/archive/refs/tags/[release number].zip

10. Download necessary module graphviz

        $ sudo pip3 install graphviz
        $ sudo apt-get install graphviz -y

11. Run program with the proper arguments 

        $ sudo python3 ./main.py --verbose 1 --webapi 0
    
    **"verbose" argument define verbosity level of logger*  
    -   *0 - logger is not printing any informations*
    -   *1 - logger is printing warnning and error messages to the "logger.log" file*  
    -   *2 - logger is printing warrning and error messages to the "logger.log" file and to the system terminal*
    -   *3 - logger is printing info, warrning and error messages to the "logger.log" file*  
    -   *4 - logger is printing info, warrning and error messages to the "logger.log" file and to the system terminal*

    **"webapi" argument specify if web applicatgion for displaing information about network is enabled*
    -   *0 - web application is disabled*
    -   *1 - web application is enabled*

    **"interface" argument takes name of interface that will be used for multihop networking*
    *i.e. "wlan0"*

    **"gateway" argument takes name of interface that will be used for internet gateway*
    *i.e. "eth0"*
    
    **"essid" argument takes name of ESSID*
    *i.e. "MESHNETWORK"*
    
    **"wep_key" argument takes WEP key used for encryption*
    *i.e. "2f37424f574d4051665973437c"*
    
    **"cell_id" argument takes name of cell/ap id*
    *i.e. "C6:7E:CC:0F:30:3E"*
    
    **"channel" argument takes number of of WLAN channel (1-14)*
    *i.e. "1"*
