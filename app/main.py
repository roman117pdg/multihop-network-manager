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


def main():
    """Main function for starting program. Responsible for accepting flags which describe node mode and verbosity level.
    Runs main theread of BabelManager."""
    main_logger = logger.create_custome_logger("root")

    # check root privileges
    user = os.getuid()
    if user != 0:
        main_logger.error("This script requires root privileges!")
        raise Exception
    
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--verbose')
    argparser.add_argument('--webapi')
    args = argparser.parse_args()
    # check if right arguments were provided
    if args.verbose!='0' and args.verbose!='1' and args.verbose!='2' and args.verbose!='3' and args.verbose!='4' and args.verbose!=None:
        main_logger.warning("wrong input arguments: "+str(args))
        main_logger.warning("--verbose 0/1/2/3/4")
        sys.exit(0)
    if args.webapi!='0' and args.webapi!='1' and args.webapi!=None:
        main_logger.warning("wrong input arguments: "+str(args))
        main_logger.warning("--webapi 0/1")
        sys.exit(0)
    # default arguments
    verbose = args.verbose 
    if args.verbose == None:
        verbose = '3'
    webapi = args.webapi 
    if args.webapi == None:
        webapi = '0'
    main_logger.info("starting program with given agrument (verbose: "+str(verbose)+", webapi: "+str(webapi)+")")
    
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

    ah_i = adhoc_init.AdhocInit(main_logger)
    ah_i.run()
    ipv6 = ah_i.get_ipv6()
    mac = ah_i.get_mac()
    sn = ah_i.get_sn()
    model = ah_i.get_model()
    interface_index = ah_i.get_iface_idx()

    
    main_logger.info("creating BabelManager")
    bm = babel_manager.BabelManager(mac, ipv6, interface_index, sn, main_logger)
    
    if webapi == '1':
        flask_thread = Thread(target = flask_app.run, name="flask", args =(main_logger, bm, mac, ipv6, sn, model,  ), daemon=True)
        main_logger.info("starting flask thread...")
        flask_thread.start()

    main_logger.info("running BabelManager")
    bm.run()
    

if __name__ == "__main__":
    main()
