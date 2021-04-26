import logger
import logging
#from pyroute2 import IPRoute
import subprocess

class Routing:

    def __init__(self, main_logger):
        """Routing initial function.
        Args:
            main_logger: Pointer to main logger class.
        """
        self.main_logger = main_logger
        # self.iproute = IPRoute()
        # self.interface = self.iproute.link_lookup(ifname='wlan0')[0]
        # nexthop_table = [{dest, nexthop}]
        self.nexthop_table = []



    def set_route(self, destination, nexthop):
        self.main_logger.info("start setting route to "+str(destination)+" via "+str(nexthop))
        if destination == nexthop:
            self.main_logger.info("destination and nexthop are the same, no need for setting route")
        else:
            for record in self.nexthop_table:
                if record['dest'] == destination:
                    if record['nexthop'] == nexthop:
                        self.main_logger.info("this route is already set")
                        return
                    else:
                        self.del_nexthop_from_rt(destination=destination, nexthop=record['nexthop'])
                        self.add_nexthop_to_rt(destination=destination, nexthop=nexthop)
                        record['nexthop'] = nexthop
                        self.main_logger.info("this route is now set")
                        return
            self.add_nexthop_to_rt(destination=destination, nexthop=nexthop)
            self.nexthop_table.append({'dest':destination, 'nexthop':nexthop})
            self.main_logger.info("this route is now set")
            return

    def del_route(self, destination, nexthop):
        self.main_logger.info("start delleting route to "+str(destination)+" via "+str(nexthop))
        if destination == nexthop:
            self.main_logger.info("destination and nexthop are the same, no need for selleting route")
        else:
            for record in self.nexthop_table:
                if record['dest'] == destination:
                    if record['nexthop'] == nexthop:
                        self.del_nexthop_from_rt(destination=destination, nexthop=nexthop)
                        self.main_logger.info("route was deleted")
                        return
        self.main_logger.info("no route to delete")
        return


    def add_nexthop_to_rt(self, destination, nexthop):
        """Add nexthop to routingtable."""
        self.main_logger.info("adding route to "+str(destination)+" via "+str(nexthop))
        try:
            cmd_set_net = "sudo ip route add "+str(destination)+" via "+str(nexthop)+" dev wlan0"
            subprocess.Popen(cmd_set_net, shell=True, stdout=subprocess.PIPE)
        except Exception as e:
            self.main_logger.error("error occure while adding route to "+str(destination)+" via "+str(nexthop)+", exeption: "+str(e))
        else:
            self.main_logger.info("route to "+str(destination)+" via "+str(nexthop) +" was added to routing table")


    def del_nexthop_from_rt(self, destination, nexthop):
        """Delete nexthop from routingtable."""
        self.main_logger.info("deleteing route to "+str(destination)+" via "+str(nexthop))
        try:
            cmd_set_net = "sudo ip route del "+str(destination)+" via "+str(nexthop)+" dev wlan0"
            subprocess.Popen(cmd_set_net, shell=True, stdout=subprocess.PIPE)
        except Exception as e:
            self.main_logger.error("error occure while delleting route to "+str(destination)+" via "+str(nexthop)+", exeption: "+str(e))
        else:
            self.main_logger.info("route to "+str(destination)+" via "+str(nexthop) +" was deleted from routing table")
   
