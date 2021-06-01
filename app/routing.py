import logger
import logging
import subprocess

class Routing:

    def __init__(self, main_logger, interface):
        """Routing initial function.
        Args:
            main_logger: Pointer to main logger class.
        """
        self.main_logger = main_logger
        self.INTERFACE = interface
        self.nexthop_table = []
        # {'dest_ipv6':destination_ipv6, 'nexthop_ipv6':nexthop_ipv6, 'dest_ipv4':destination_ipv4, 'nexthop_ipv4':nexthop_ipv4}

    def set_route(self, destination_ipv6, nexthop_ipv6, destination_ipv4, nexthop_ipv4):
        self.main_logger.info("start setting route to "+str(destination_ipv6)+"("+str(destination_ipv4)+") via "+str(nexthop_ipv6)+"("+str(nexthop_ipv4)+")")
        if destination_ipv6 == nexthop_ipv6:
            self.main_logger.info("destination and nexthop are the same, no need for setting route")
        else:
            for record in self.nexthop_table:
                if record['dest_ipv6'] == destination_ipv6:
                    if record['nexthop_ipv6'] == nexthop_ipv6:
                        self.main_logger.info("this route is already set")
                        return
                    else:
                        self.main_logger.warning("wrong nexthop was set")
                        self.del_nexthop_from_rt(destination=destination_ipv6, nexthop=record['nexthop_ipv6'])
                        self.del_nexthop_from_rt(destination=destination_ipv4, nexthop=record['nexthop_ipv4'])
                        self.add_nexthop_to_rt(destination=destination_ipv6, nexthop=nexthop_ipv6)
                        self.add_nexthop_to_rt(destination=destination_ipv4, nexthop=nexthop_ipv4)
                        record['nexthop_ipv6'] = nexthop_ipv6
                        self.main_logger.info("fixed to proper ipv4 and ipv6 nexthop")
                        return
            self.add_nexthop_to_rt(destination=destination_ipv6, nexthop=nexthop_ipv6)
            self.main_logger.info("this route ipv6 is now set")
            self.add_nexthop_to_rt(destination=destination_ipv4, nexthop=nexthop_ipv4)
            self.main_logger.info("this route ipv4 is now set")
            self.nexthop_table.append({'dest_ipv6':destination_ipv6, 'nexthop_ipv6':nexthop_ipv6, 'dest_ipv4':destination_ipv4, 'nexthop_ipv4':nexthop_ipv4})
            return


    def del_route(self, destination_ipv6, nexthop_ipv6, destination_ipv4, nexthop_ipv4):
        self.main_logger.info("start delleting route to "+str(destination_ipv6)+"("+str(destination_ipv4)+") via "+str(nexthop_ipv6)+"("+str(nexthop_ipv4)+")")
        if destination_ipv6 == nexthop_ipv6:
            self.main_logger.info("destination and nexthop are the same, no need for selleting route")
        else:
            for record in self.nexthop_table:
                if record['dest_ipv6'] == destination_ipv6:
                    if record['nexthop_ipv6'] == nexthop_ipv6:
                        self.del_nexthop_from_rt(destination=destination_ipv6, nexthop=nexthop_ipv6)
                        self.main_logger.info("route ipv6 was deleted")
                        self.del_nexthop_from_rt(destination=destination_ipv4, nexthop=nexthop_ipv4)
                        self.main_logger.info("route ipv4 was deleted")
                        return
        self.main_logger.info("no route to delete")
        return


    def add_nexthop_to_rt(self, destination, nexthop):
        """Add nexthop to routingtable."""
        self.main_logger.info("adding route to "+str(destination)+" via "+str(nexthop))
        try:
            cmd_set_net = "sudo ip route add "+str(destination)+" via "+str(nexthop)+" dev "+str(self.INTERFACE)
            proc = subprocess.Popen(cmd_set_net, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error = proc.stderr.read().decode()
            if error != "":
                self.main_logger.error('Error occure while adding route to routing table, error: '+str(error))
            else:
                self.main_logger.info("route to "+str(destination)+" via "+str(nexthop) +" was added to routing table")
        except Exception as e:
            self.main_logger.error("Exception occure while adding route to "+str(destination)+" via "+str(nexthop)+", exeption: "+str(e))


    def del_nexthop_from_rt(self, destination, nexthop):
        """Delete nexthop from routingtable."""
        self.main_logger.info("deleteing route to "+str(destination)+" via "+str(nexthop))
        try:
            cmd_set_net = "sudo ip route del "+str(destination)+" via "+str(nexthop)+" dev "+str(self.INTERFACE)
            subprocess.Popen(cmd_set_net, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            error = proc.stderr.read().decode()
            if error != "":
                self.main_logger.error('Error occure while deleting route from routing table, error: '+str(error))
            else:
                self.main_logger.info("route to "+str(destination)+" via "+str(nexthop) +" was deleted from routing table")
        except Exception as e:
            self.main_logger.error("error occure while delleting route to "+str(destination)+" via "+str(nexthop)+", exeption: "+str(e))


    def cleanup_rt(self):
        """Cleanup routing table - rollback all changes"""
        self.main_logger.info("start process of cleaning up routing table")
        for record in self.nexthop_table:
            self.del_nexthop_from_rt(destination=record['dest_ipv6'], nexthop=record['nexthop_ipv6'])
            self.main_logger.info("route ipv6 was deleted")
            self.del_nexthop_from_rt(destination=record['dest_ipv4'], nexthop=record['nexthop_ipv4'])
            self.main_logger.info("route ipv4 was deleted")
        self.main_logger.info("all changes to routing table were rollback")
        
