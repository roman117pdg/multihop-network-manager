#!/usr/bin/env python3

import babel_manager
import argparse
import sys
import os
import logger
import logging
import adhoc_init
from flask_app import flask_app
from threading import Thread 
import socket


def get_interface_list():
    interfaces_dict = socket.if_nameindex()
    interfaces_list = []
    for interface in interfaces_dict:
        interfaces_list.append(interface[1])
    return interfaces_list


def main():
    """Main function for starting program. Responsible for accepting flags which describe node mode and verbosity level.
    Runs main theread of BabelManager."""
    main_logger = logger.create_custome_logger("root")
    interfaces_list = get_interface_list()

    # check root privileges
    user = os.getuid()
    if user != 0:
        main_logger.error("This script requires root privileges!")
        raise Exception

    
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--verbose')
    argparser.add_argument('--webapi')
    argparser.add_argument('--interface')
    argparser.add_argument('--gateway')
    argparser.add_argument('--essid')
    argparser.add_argument('--wep_key')
    argparser.add_argument('--cell_id')
    argparser.add_argument('--channel')
    args = argparser.parse_args()
    # check if right arguments were provided
    if args.verbose!=None and args.verbose!='0' and args.verbose!='1' and args.verbose!='2' and args.verbose!='3' and args.verbose!='4':
        main_logger.warning("wrong input arguments: "+str(args))
        main_logger.warning("--verbose 0/1/2/3/4")
        sys.exit(0)
    if args.webapi!=None and args.webapi!='0' and args.webapi!='1':
        main_logger.warning("wrong input arguments: "+str(args))
        main_logger.warning("--webapi 0/1")
        sys.exit(0)
    if args.interface!=None and args.interface not in interfaces_list:
        main_logger.warning("wrong input arguments: "+str(args))
        main_logger.warning("--interface <string name of interface>")
        main_logger.warning("available interfaces:")
        main_logger.warning(interfaces_list)
        sys.exit(0)
    if args.gateway!=None and args.gateway not in interfaces_list:
        main_logger.warning("wrong input arguments: "+str(args))
        main_logger.warning("--gateway <string name of interface>")
        main_logger.warning("available interfaces:")
        main_logger.warning(interfaces_list)
        sys.exit(0)
    if args.wep_key!=None and len(args.wep_key)!=26:
        main_logger.warning("wrong input arguments: "+str(args))
        main_logger.warning("--wep_key <26 string of hex number>")
        sys.exit(0)
    if args.wep_key!=None and int(args.channel)<1  and  int(args.channel)>14:
        main_logger.warning("wrong input arguments: "+str(args))
        main_logger.warning("--channel 1/2/3/4/5/6/7/8/9/10/11/12/13/14")
        sys.exit(0)
    # default arguments
    verbose = args.verbose 
    if args.verbose == None:
        verbose = '3'
    webapi = args.webapi 
    if args.webapi == None:
        webapi = '0'
    interface = args.interface 
    if args.interface == None:
        interface = 'wlan0'
    gateway = args.gateway 
    if args.gateway == None:
        gateway = 'None'
    essid = args.essid 
    if args.essid == None:
        essid = 'MESHNETWORK'
    wep_key = args.wep_key 
    if args.wep_key == None:
        wep_key = '55795d2076683f6a29516d2747'
    cell_id = args.cell_id 
    if args.cell_id == None:
        cell_id = 'C6:7E:CC:0F:30:3E'
    channel = args.channel 
    if args.channel == None:
        channel = '1'
 
    main_logger.info("starting program with agruments (verbose: "+str(verbose)+", webapi: "+str(webapi)+", interface: "+str(interface)+", gateway: "+str(gateway)+
    "essid: "+str(essid)+", wep_key: "+str(wep_key)+", cell_id: "+str(cell_id)+", channel: "+str(channel)+")")
    
    # set verbosity level of logger
    if verbose == '0':
        # logger is not printing anything 
        main_logger.propagate = False
    elif verbose == '1':
        # logger is printing warrning and error messages to "logger.log" file
        main_logger.setLevel(logging.WARNING) 
        main_logger = logger.enable_print_file(main_logger)
    elif verbose == '2':
        # logger is printing warrning and error messages to "logger.log" file and to the system terminnal
        main_logger.setLevel(logging.WARNING) 
        main_logger = logger.enable_print_file(main_logger)
        main_logger = logger.enable_print_terminal(main_logger)
    elif verbose == '3':
        # logger is printing info, warrning and error messages to "logger.log" file
        main_logger.setLevel(logging.INFO) 
        main_logger = logger.enable_print_file(main_logger)
    elif verbose == '4':
        # logger is printing info, warrning and error messages to "logger.log" file and to the system terminnal
        main_logger.setLevel(logging.INFO) 
        main_logger = logger.enable_print_file(main_logger)
        main_logger = logger.enable_print_terminal(main_logger)

    ah_i = adhoc_init.AdhocInit(main_logger, interface, gateway, essid, wep_key, cell_id, channel)
    ah_i.run()
    ipv6 = ah_i.get_ipv6()
    ipv4 = ah_i.get_ipv4()
    mac = ah_i.get_mac()
    sn = ah_i.get_sn()
    model = ah_i.get_model()
    interface_index = ah_i.get_iface_idx()

    
    main_logger.info("creating BabelManager")
    bm = babel_manager.BabelManager(mac, ipv6, ipv4, interface, interface_index, sn, ah_i, main_logger)
    
    if webapi == '1':
        flask_thread = Thread(target = flask_app.run, name="flask", args =(main_logger, bm, mac, ipv6, ipv4, sn, model,  ), daemon=True)
        main_logger.info("starting flask thread...")
        flask_thread.start()

    main_logger.info("running BabelManager")
    bm.run()
    

if __name__ == "__main__":
    main()
