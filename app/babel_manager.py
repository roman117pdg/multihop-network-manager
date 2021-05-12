import peer_udp_connection
import adhoc_init
import threading
import time
import logger
import logging
import uuid
import random
from pyroute2 import IPRoute
import messages
import math 
from tables import *
import routing
import json




class BabelManager:

    def __init__(self, mac, ip_v6, ip_v4, iface_idx, sn, ah_i, main_logger):       
        """BabelManager initial function.

        Args:
            mac: String value of MAC addres.
            ip_v6: String value of IPv6 address.
            iface_idx: Integer value of interface index.
            main_logger: Pointer to main logger class.
        """
        self.MY_IPV6 = ip_v6
        self.MY_IPV4 = ip_v4
        self.MAC = mac
        self.TIME_FOR_RESPONSE = {'ROUTE_CHANGE':0.3, 'REQ_TO_EST_RT':2.0, 'RES_TO_EST_IP':0.2, 'REQ_IP_ADDR':0.5, 'ROUTE_INFO':1.0}
        # RFC 6126 Apenix B Constants
        # Intervals are cecified in centiseconds RFC 6126 4.1.1
        self.HELLO_MSG_INTERVAL = 40
        self.IHU_MSG_INTERVAL = 3*self.HELLO_MSG_INTERVAL
        self.UPDATE_MSG_INTERVAL = 4*self.HELLO_MSG_INTERVAL
        self.IHU_HOLD_TIME = int(3.5 * self.IHU_MSG_INTERVAL)
        self.ROUTE_EXPIRY_TIME =  int(3.5 * self.UPDATE_MSG_INTERVAL)
        self.GC = 1800 # 3 minutes - garbage collection timer (source table)

        self.PLEN = 64 # in bits
        self.HOPCOUNT = 16
        self.ACK_REQ_INTERVAL = 5

        self.IFACE_IDX = iface_idx
        self.MSG_TYPE = {'Pad1':0, 'PadN':1, 'AckReq':2, 'Ack':3, 'Hello':4, 'IHU':5,  
        'RouterID':6, 'NextHop':7, 'Update':8, 'RouteReq':9, 'SeqnoReq':10, 'RTReq':11, 'RTInfo':12}
        # arr = ip_v6.split(':')
        self.MY_RID = int(sn,16)%int(0xFFFFFFFF)
        # self.MY_RID = 0
        self.main_logger = main_logger
        self.iproute = IPRoute()
        self.routing = routing.Routing(main_logger)
        self.seqno = 0
        self.interface = self.iproute.link_lookup(ifname='wlan0')[0]
        self.ah_i = ah_i

        self.interface_table = []
        self.neigh_table = []
        self.source_table = []
        self.route_table = []
        # self.pend_req_table = []
        self.other_nodes_rts = []
        self.ipv6_to_ipv4 = [[self.MY_IPV6], [self.MY_IPV4]]


    def get_neigh_table(self):
        neighbours = []
        for neigh in self.neigh_table:
            json_acceptable_string = str(neigh).replace("'", "\"").replace("True", "\"True\"").replace("False", "\"False\"")
            neighbours.append(json.loads(json_acceptable_string))
        return neighbours

    def get_source_table(self):
        sources = []
        for source in self.source_table:
            json_acceptable_string = str(source).replace("'", "\"").replace("True", "\"True\"").replace("False", "\"False\"")
            sources.append(json.loads(json_acceptable_string))
        return sources

    def get_route_table(self):
        routes = []
        for route in self.route_table:
            json_acceptable_string = str(route).replace("'", "\"").replace("True", "\"True\"").replace("False", "\"False\"")
            routes.append(json.loads(json_acceptable_string))
        return routes

    def get_seqno(self):
        return self.seqno

    def get_other_nodes_rts(self):
        self.main_logger.info("other_nodes_rts: "+str(self.other_nodes_rts))
        tmp_array = self.other_nodes_rts[:]
        self.main_logger.info("clearing other_nodes_rts table and sending new RTReq_msgs")
        self.other_nodes_rts = []
        for source in self.source_table:
            self.send_RTReq_msg(destination=source.prefix) 
        return tmp_array   
            

    def get_ipv4_from_ipv6(self, ipv6):
        if ipv6 in self.ipv6_to_ipv4[0]:
            index = self.ipv6_to_ipv4[0].index(ipv6)
            return self.ipv6_to_ipv4[1][index]
        else:
            self.ipv6_to_ipv4[0].append(ipv6)
            ipv4 = self.ah_i.get_ipv4_from_ipv6(ipv6)
            self.ipv6_to_ipv4[1].append(ipv4)
            return(ipv4)


    def check_neighb_table(self):
        """Check periodically if neighbours table have outdated records (without IHU updates).
        If it is outdated then cost is set to 0xFFFF (infinity)."""
        while len(self.neigh_table) == 0:
            time.sleep(1.5)
        while True:
            time.sleep(self.IHU_HOLD_TIME/10)
            self.main_logger.info("checking neigh_table for outdated records (without IHU updates)")
            for record in self.neigh_table:
                if (time.time() - record.IHU_hist) > (self.IHU_HOLD_TIME/10) and record.IHU_hist != 0.0:
                    self.main_logger.info("record ["+str(record)+"] was outdated, txcost set to 0xFFFF")
                    record.txcost = int(0xFFFF)


    def check_route_exp_timers(self):
        """Check periodically if routing table have outdated records."""
        while len(self.route_table) == 0:
            time.sleep(1.5)
        while True:
            time.sleep(self.ROUTE_EXPIRY_TIME/20)
            self.main_logger.info("checking route_table for outdated records")
            for i in range(len(self.route_table)-1, -1, -1):
                route = self.route_table[i]
                self.main_logger.info("checking route: "+str(route)+", time"+str(time.time()))
                if (time.time() - route.route_expire_timer) > (self.ROUTE_EXPIRY_TIME/10):
                    if route.metric < int(0xFFFF):
                        self.main_logger.info("record ["+str(route)+"] is outdated, metric set to 0xFFFF")
                        route.metric = int(0xFFFF)
                        # 3.8.2.1.
                        self.main_logger.info("sendding Seqno Request message for that prefix")
                        self.send_SeqnoReq_msg(addr="MULTICAST", ae=3, plen=self.PLEN, seqno=route.seqno+1, hopcount=self.HOPCOUNT, routerid=route.router_id, prefix=route.prefix)
                        # self.main_logger.info("creating new element in pend_req_table")
                        # self.pend_req_table.append(PendReqRecord(prefix=route.prefix, plen=route.plen, router_id=route.router_id, seqno=route.seqno, nexthop="MULTICAST", resent_count=self.HOPCOUNT))

                    else:
                        self.main_logger.info("sendding Seqno Request message for that prefix")
                        self.send_SeqnoReq_msg(addr="MULTICAST", ae=3, plen=self.PLEN, seqno=route.seqno+1, hopcount=self.HOPCOUNT, routerid=route.router_id, prefix=route.prefix)
                        if route.use_flag == True:
                            self.routing.del_route(destination_ipv6=route.prefix, nexthop_ipv6=route.nexthop, destination_ipv4=route.prefix_ipv4, nexthop_ipv4=route.nexthop_ipv4)
                            self.main_logger.info("record ["+str(route)+"] is outdated, deleting route from OS routing table")
                        self.main_logger.info("record ["+str(route)+"] is outdated, removing it from routing table")
                        self.route_table.remove(route)
            self.route_selection()

            self.main_logger.info("checking source_table for outdated records")
            for i in range(len(self.source_table)-1, -1, -1):
                source = self.source_table[i]
                self.main_logger.info("checking source: "+str(source)+", time"+str(time.time()))
                if (time.time() - source.garb_col_timer) > (self.GC/10):
                    self.main_logger.info("source is outdated, it will be removed")
                    self.source_table.remove(source)


    

    def compute_rxcost(self, addr):
        for record in self.neigh_table:            
            if record.neigh_addr == addr:
                avg_interval = 0.0
                for i in range(4):
                    avg_interval += math.fabs(record.hello_hist[i+1] - record.hello_hist[i])
                avg_interval /= 4
                self.main_logger.info("avg:"+str(avg_interval))
                rxcost = math.ceil((avg_interval/(self.HELLO_MSG_INTERVAL/10))**16.0) # reason for using 'to the power of 16' is to make bigger rxcost values
                if rxcost >= int(0xFFFF): 
                    return int(0xFFFF)
                else:
                    return rxcost
        return int(0xFFFF) # if not return inf


    def compute_cost(self, addr):
        """Described in RFC 6126 Section 3.4.3 and Appendix A.2.2"""
        self.main_logger.info("running compute cost for addr: "+str(addr))
        for record in self.neigh_table:            
            if record.neigh_addr == addr:
                rxcost = record.rxcost
                txcost = record.txcost
                cost = math.ceil((max(txcost, 256)*rxcost)/256)
                if rxcost >= int(0xFFFF) or txcost >= int(0xFFFF) or cost >= int(0xFFFF):
                    return int(0xFFFF)
                else:
                    return cost
        return int(0xFFFF)

    def compute_metric(self, prefix, nexthop):
        """Described in RFC 6126 Section 3.5.2 and Appendix A.3.1"""
        self.main_logger.info("running compute metric for prefix: "+str(prefix)+", nexthop: "+str(nexthop))
        neigh_cost = self.compute_cost(nexthop)
        if nexthop == prefix:
            if neigh_cost < int(0xFFFF):
                return neigh_cost
            else:
                return int(0xFFFF)
        else:
            for route in self.route_table:
                if route.prefix == prefix:
                    if (route.metric + neigh_cost) < int(0xFFFF):
                        return route.metric + neigh_cost   
                    else:
                        return int(0xFFFF) 
        return int(0xFFFF)


    def update_neightable_Hello(self, addr, message):
        for record in self.neigh_table:
            if record.neigh_addr == addr:
                self.main_logger.info("updating neighbour record in neigh_table (addr:"+str(addr)+", msg:"+str(message)+")")
                seqno_dif =  message['SEQNO'] - record.expect_seqno
                record.hello_hist.pop(0)
                record.hello_hist.append(time.time())
                record.expect_seqno = (message['SEQNO']+1)%int(0xFFFF)
                record.Hello_interval = message['INTERVAL']
                return True
        self.main_logger.info("adding new neighbour record to neigh_table (addr:"+str(addr)+", msg:"+str(message)+")")
        self.neigh_table.append(NeighbourTableRecord(interface_id=self.IFACE_IDX, neigh_addr=addr, hello_hist=[0,0,0,0,time.time()], 
        IHU_hist=0.0, rxcost=int(0xFFFF), txcost=int(0xFFFF), expect_seqno=message['SEQNO']+1, Hello_interval=message['INTERVAL'], IHU_interval=self.IHU_MSG_INTERVAL))

        self.main_logger.info("sending 5 trigerred Hello messages")
        for i in range(5):
            self.send_Hello_msg()
        return False


    def update_neightable_IHU(self, addr, message):
        for record in self.neigh_table:
            if record.neigh_addr == addr:
                self.main_logger.info("updating neighbour record in neigh_table (addr:"+str(addr)+", msg:"+str(message)+")")
                record.txcost = message['RXCOST']
                record.IHU_interval = message['INTERVAL']
                record.IHU_hist = time.time()
                return True
        return False


    def feasible(self, prefix, seqno, metric):
        """Condition runned on reciving Update message.
        Compares the metric in the recived update with the metric of the updates received erlier (in source table?)
        Full description in RFC 6126, chapter 3.5.1."""
        self.main_logger.info("running feasibility confition")
        if metric >= int(0xFFF):
            self.main_logger.info("metric to "+str(prefix)+" was accepted (reason: metric is inf - retraction)")
            return True
        for record in self.source_table:
            if record.prefix == prefix:
                if (record.seqno)%int(0xFFFF) < (seqno)%int(0xFFFF):
                    self.main_logger.info("metric to "+str(prefix)+" was accepted (reason: seqno is new)")
                    return True
                elif record.seqno == seqno and record.metric > metric:
                    self.main_logger.info("metric to "+str(prefix)+" was accepted (reason: metric is better)")
                    return True
                else:
                    self.main_logger.info("metric to "+str(prefix)+" wasn't accepted (reason: seqno is not new and metric is not better)")
                    return False
        self.main_logger.info("metric to "+str(prefix)+" was accepted (reason: no record)")
        return True

    def feasible_update(self):
        """Process of maintaining feasibility distances, runned before sending Update message.
        Updates feasibility distance maintained in source table, by comparing the to reouting table records.
        Full description in RFC 6126, chapter 3.7.3."""
        self.main_logger.info("maintaining feasibility distances before sending update") 
        for route in self.route_table:
            route_in_source_table = False
            for source in self.source_table:
                if source.prefix == route.prefix:
                    route_in_source_table = True
                    if source.seqno < route.seqno and route.use_flag == True:
                        source.seqno = route.seqno
                        source.metric = route.metric
                        source.garb_col_timer = time.time()
                        self.main_logger.info("source updated, (reason: seqno) source:"+str(source)+", route: "+str(route))
                    elif source.seqno == route.seqno and source.metric > route.metric and route.use_flag == True:
                        source.metric = route.metric
                        source.garb_col_timer = time.time()
                        self.main_logger.info("source updated, (reason: metric) source:"+str(source)+", route: "+str(route))
                    else:
                        self.main_logger.info("source NOT updated, source:"+str(source)+", route: "+str(route))
                    break
            if route_in_source_table == False:
                self.source_table.append(SourceTableRecord(prefix=route.prefix, plen=route.plen, router_id=route.router_id, seqno=route.seqno, metric=route.metric, garb_col_timer=time.time()))
                self.main_logger.info("new record to source table was added, route: "+str(route))   


    def route_acquisition(self, prefix, seqno, metric, neigh_addr):
        """Runned after receiving Update message.
        Full description in RFC 6126, chapter 3.5.4."""
        self.main_logger.info("route acqusition beggins")
        for record in self.route_table:
            if record.prefix == prefix and record.nexthop == neigh_addr:
                record.metric = metric
                record.seqno = seqno
                record.route_expire_timer = time.time()
                self.main_logger.info("route ("+str(record)+") was updated")
                return

        if metric < int(0xFFFF):
            prefix_ipv4 = self.get_ipv4_from_ipv6(prefix)
            nexthop_ipv4 = self.get_ipv4_from_ipv6(neigh_addr)
            self.route_table.append(RouteTableRecord(prefix=prefix, prefix_ipv4=prefix_ipv4, plen=self.PLEN, router_id=self.MY_RID, metric=metric, seqno=seqno, nexthop=neigh_addr, nexthop_ipv4=nexthop_ipv4, use_flag=False, route_expire_timer=time.time()))
            self.main_logger.info("route ("+str(self.route_table[len(self.route_table)-1])+") was added")


    def route_selection(self):
        """Process of selecting best route for every "prefix in source table"-my change, to be used for forwarding packets.
        Full description in RFC 6126, chapter 3.6."""
        for source in self.source_table:
            self.main_logger.info("running process of route selection for prefix: "+str(source.prefix))
            best_route = None
            old_route = None
            for route in self.route_table:
                if route.prefix == source.prefix and route.use_flag == True:
                    old_route = route
                    self.main_logger.info("found old route: "+str(old_route))
            for route in self.route_table:
                # check if route for given prefix is feasible, and then if it is better than selected route
                if route.prefix == source.prefix and (route.metric <= source.metric or route.seqno > source.seqno):
                    if best_route == None:
                        if route.metric != int(0xFFFF):
                            best_route = route
                    elif route.metric < best_route.metric and route.seqno >= best_route.seqno:
                        best_route = route
                    elif route.metric <= best_route.metric and route.seqno > best_route.seqno:
                        best_route = route
                    elif old_route != None and route.metric == old_route.metric:
                        best_route = old_route
                
            if best_route == None:
                self.main_logger.info("couldn't find any route to: "+str(source.prefix))
            else:
                self.main_logger.info("best route to "+str(source.prefix)+" is: "+str(best_route))
                if best_route != old_route:
                    self.main_logger.info("setting new route (prefix: "+str(best_route.prefix)+",nexthop: "+str(best_route.nexthop)+")")
                    self.routing.set_route(destination_ipv6=best_route.prefix, nexthop_ipv6=best_route.nexthop, destination_ipv4=best_route.prefix_ipv4, nexthop_ipv4=best_route.nexthop_ipv4)
                    best_route.use_flag = True
                    if old_route != None:
                        old_route.use_flag = False
                    self.send_Update_msg(record_prefix=source.prefix)
                    self.send_RouteReq_msg(ae=0, addr='MULTICAST', prefix=source.prefix)
                else:
                    self.main_logger.info("old route to "+str(source.prefix)+" is already best route")

    def send_AckReq_msg(self, destination):
        """Send unicast AckReq message. """
        self.main_logger.info("adding unicast AckReq message to output queue")
        nonce = random.randint(0,int(0xFFFF))
        self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['AckReq'], destination=destination, body={'nonce':nonce, 'interval': self.ACK_REQ_INTERVAL})
                

    def handle_AckReq_msg(self, addr, message):
        """Handle the received AckReq message."""
        self.main_logger.info("message AckReq handling beggins (addr:"+str(addr)+",msg:"+str(message)+")")
        self.main_logger.info("sending responde Ack to received AckReq")
        self.send_Ack_msg(destination=addr, nonce=message['NONCE'])


    def send_Ack_msg(self, destination, nonce):
        """Send unicast Ack message. """
        self.main_logger.info("adding unicast Ack message to output queue")
        self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['Ack'], destination=destination, body={'nonce':nonce})
                

    def handle_Ack_msg(self, addr, message):
        """Handle the received Ack message."""
        self.main_logger.info("message Ack handling beggins (addr:"+str(addr)+",msg:"+str(message)+")")
        # TODO


    def send_Hello_msg(self):
        """Periodically sending Hello messages every given period HELLO_MSG_INTERVAL. """
        for record in self.interface_table:
            if record.interface_id == self.IFACE_IDX:
                self.main_logger.info("adding multicast Hello message to output queue")
                self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['Hello'], destination='MULTICAST', body={'seqno':record.hello_seqno, 'interval':self.HELLO_MSG_INTERVAL})
                record.hello_seqno = (record.hello_seqno+1)%int(0xFFFF) 


    def handle_Hello_msg(self, addr, message):
        """Handle the received HELLO message."""
        self.main_logger.info("message Hello handling beggins (addr:"+str(addr)+",msg:"+str(message)+")")
        self.update_neightable_Hello(addr, message)


    def send_IHU_msg(self):
        """Periodically sending IHU messages every given period IHU_MSG_INTERVAL."""
        self.main_logger.info("adding unicast IHU message to output queue")
        for record in self.neigh_table:
            ae = 3
            rxcost = self.compute_rxcost(record.neigh_addr)
            record.rxcost = rxcost
            interval = self.IHU_MSG_INTERVAL
            address = self.MY_IPV6
            self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['IHU'], 
            destination=record.neigh_addr, body={'ae':ae, 'rxcost':rxcost, 'interval':interval, 'address':address})


    def handle_IHU_msg(self, addr, message):
        """Handle the received IHU message."""
        self.main_logger.info("message IHU handling beggins (addr:"+str(addr)+",msg:"+str(message)+")")
        self.update_neightable_IHU(addr, message)
        self.route_selection()


    def send_RouterID_msg(self, destination="MULTICAST"):
        """Send unicast RouterID message. """
        self.main_logger.info("adding unicast RouterID message to output queue")
        self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['RouterID'], destination=destination, body={'routerid':self.MY_RID})
                

    def handle_RouterID_msg(self, addr, message):
        """Handle the received RouterID message."""
        self.main_logger.info("message RouterID handling beggins (addr:"+str(addr)+",msg:"+str(message)+")")
        for route in self.route_table:
            if route.prefix == addr:
                route.router_id = message['ROUTERID']


    def send_NextHop_msg(self, destination="MULTICAST"):
        """Send unicast NextHop message. """
        self.main_logger.info("adding unicast NextHop message to output queue")
        self.main_logger.info("NextHop message with ipv4 address")
        self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['NextHop'], destination=destination, body={'ae':1, 'nexthop':''})
                

    def handle_NextHop_msg(self, addr, message):
        """Handle the received NextHop message."""
        self.main_logger.info("message NextHop handling beggins (addr:"+str(addr)+",msg:"+str(message)+")")
        # for route in self.route_table:
        #     if route.prefix == addr:
        #         route.prefix_ipv4 = message['NEXTHOP']


    def send_Update_msg(self, addr='MULTICAST', record_prefix=''):
        """Periodically sending Update messages every given period UPDATE_MSG_INTERVAL 
        and sending them by trigger (received Route request or rapid changes).
        
        Args:
            addr: Specify where to send this message or messages.
            record_prefix: Specify what record (by addr) have to be send.
        """
        self.main_logger.info("start process of sending Update message")
        # ae for ipv6 link local is 3
        ae = 3
        flags = 0
        omitted = 0
        plen = self.PLEN # ipv6 linklocal constant
        interval = self.UPDATE_MSG_INTERVAL
        self.feasible_update()
        if record_prefix == '':
            for record in self.source_table:
                metric = record.metric
                seqno = record.seqno
                prefix = record.prefix
                self.main_logger.info("adding multicast Update message to output queue (from source table)")
                self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['Update'], destination=addr, 
                body={'ae':ae, 'flags':flags, 'plen':plen, 'omitted':omitted, 'interval':interval, 'seqno':seqno, 'metric':metric, 'prefix':prefix})
            
            self.main_logger.info("adding multicast Update message to output queue (own prefix)")
            self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['Update'], destination=addr, 
            body={'ae':ae, 'flags':flags, 'plen':plen, 'omitted':omitted, 'interval':interval, 'seqno':self.seqno, 'metric':0, 'prefix':self.MY_IPV6})
            self.send_RouterID_msg(destination=addr)
        else:
            for record in self.source_table:
                if record.prefix == record_prefix:
                    seqno = record.seqno
                    metric = record.metric
                    self.main_logger.info("adding unicast Update message for given prefix to output queue")
                    self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['Update'], destination=addr, 
                    body={'ae':ae, 'flags':flags, 'plen':plen, 'omitted':omitted, 'interval':interval, 'seqno':seqno, 'metric':metric, 'prefix':record_prefix})
                    self.send_RouterID_msg(destination=addr)
                    return
            if record_prefix == self.MY_IPV6:
                self.main_logger.info("adding multicast Update message to output queue (own prefix)")
                self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['Update'], destination=addr, 
                body={'ae':ae, 'flags':flags, 'plen':plen, 'omitted':omitted, 'interval':interval, 'seqno':self.seqno, 'metric':0, 'prefix':self.MY_IPV6})
                self.send_RouterID_msg(destination=addr)
            else:
                self.main_logger.info("adding unicast Update retraction message (no info about prefix) to output queue")
                self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['Update'], destination=addr, 
                body={'ae':3, 'flags':0, 'plen':64, 'omitted':0, 'interval':0, 'seqno':0, 'metric':int(0xFFFF), 'prefix':record_prefix})
                self.send_RouterID_msg(destination=addr)


    def handle_Update_msg(self, addr, message):
        """Handle the received Update message."""
        self.main_logger.info("message Update handling beggins (addr:"+str(addr)+",msg:"+str(message)+")")
        new_metric = message['METRIC'] + self.compute_cost(addr)
        if new_metric > int(0xFFFF):
            new_metric = int(0xFFFF)
        if message['PREFIX'] == self.MY_IPV6:
            self.main_logger.info("prefix in update message is this node prefix, silently ignoring this message")
        elif self.feasible(message['PREFIX'], message['SEQNO'], new_metric) == True:
            self.main_logger.info("feasibility condition was fulfilled")
            self.route_acquisition(prefix=message['PREFIX'], seqno=message['SEQNO'], metric=new_metric, neigh_addr=addr)
            self.route_selection()
        else:
            self.main_logger.info("feasibility condition was NOT fulfilled")


    def send_RouteReq_msg(self, ae, addr, prefix):
        """Send Route Request message."""
        self.main_logger.info("adding multicast Route Request messages to output queue")
        if ae == 0:
            self.main_logger.info("with ae value equal 0")
            self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['RouteReq'], destination=addr, body={'ae':ae, 'plen':self.PLEN, 'prefix':prefix})
        elif ae == 3:
            self.main_logger.info("with ae value equal 3")
            self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['RouteReq'], destination=addr, body={'ae':ae, 'plen':self.PLEN, 'prefix':prefix})
        else:
            self.main_logger.warning("wrong ae value, silently ignoring this tlv")


    def handle_RouteReq_msg(self, addr, message):
        """Handle the received Route Request message.
        Full description in RFC 6126, chapter 3.8.1.1."""
        self.main_logger.info("message Route Request handling beggins (addr:"+str(addr)+",msg:"+str(message)+")")
        ae = message['AE'] 
        if ae == 0:
            self.main_logger.info("sending unicast messages with all neigh table")
            self.send_Update_msg(addr=addr)
        elif ae == 3:
            prefix = message['PREFIX']
            self.main_logger.info("sending unicast messages with one record from neigh table")
            self.send_Update_msg(addr=addr, record_prefix=prefix)
        else:
            self.main_logger.warning("wrong ae value, silently ignoring this tlv")
    

    def send_SeqnoReq_msg(self, addr, ae, plen, seqno, hopcount, routerid, prefix):
        """Send Seqno Request message."""
        self.main_logger.info("adding multicast Seqno Request messages to output queue")
        self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['SeqnoReq'], destination=addr, 
        body={'ae':ae, 'plen':plen, 'seqno':seqno, 'hopcount':hopcount, 'routerid':routerid, 'prefix':prefix})


    def handle_SeqnoReq_msg(self, addr, message):
        """Handle the received Seqno Request message.
        Full description in RFC 6126, chapter 3.8.1.2"""
        self.main_logger.info("message Seqno Request handling beggins (addr:"+str(addr)+",msg:"+str(message)+")")
        for route in self.route_table:
            if route.prefix == message['PREFIX']:
                if route.metric >= int(0xFFFF):
                    self.main_logger.info("silently ignoring message Seqno Request (reason: inf metric in rt table)")
                    return
                elif route.router_id != message['ROUTERID'] or (route.router_id == message['ROUTERID'] and route.seqno >= message['SEQNO']):
                    self.send_Update_msg(record_prefix=message['PREFIX'])
                    self.main_logger.info("sending Update message for given prefix: "+str(message['PREFIX']))
                    return
                elif route.router_id == message['ROUTERID'] and route.seqno < message['SEQNO']:
                    if message['ROUTERID'] == self.MY_RID:
                        self.seqno += 1
                        self.send_Update_msg()
                        self.main_logger.info("increasing seqno and sending Update messages")
                        return
                    elif message['HOPCOUNT'] >= 2:
                        for route in self.route_table:
                            if route.prefix == message['PREFIX'] and route.use_flag == True:
                                if route.metric >= int(0xFFFF):
                                    self.send_SeqnoReq_msg(addr="MULTICAST", ae=message['AE'], plen=message['PLEN'], seqno=message['SEQNO'], 
                                    hopcount=message['HOPCOUNT'] - 1, routerid=message['ROUTERID'], prefix=message['PREFIX'])
                                    self.main_logger.info("forwarding Seqno req message with decreased HOPCOUNT value: "+str(message['HOPCOUNT'] - 1))
                        
                                else:
                                    self.send_SeqnoReq_msg(addr=message['PREFIX'], ae=message['AE'], plen=message['PLEN'], seqno=message['SEQNO'], 
                                    hopcount=message['HOPCOUNT'] - 1, routerid=message['ROUTERID'], prefix=message['PREFIX'])
                                    self.main_logger.info("forwarding Seqno req message with decreased HOPCOUNT value: "+str(message['HOPCOUNT'] - 1))
                        return
        if message['ROUTERID'] == self.MY_RID:
            self.main_logger.info("given routerid is equal to this node routerid")
            if message['SEQNO'] > self.seqno:
                self.seqno += 1
                self.send_Update_msg()
                self.main_logger.info("increasing seqno and sending Update messages")
                return
            else:
                self.main_logger.info("sending Update messages")
                self.send_Update_msg()
        else:
            self.main_logger.info("silently ignoring message Seqno Request (reason: no record in rt table)")



    
    def send_RTReq_msg(self, destination):
        """Send unicast RTReq message. """
        self.main_logger.info("adding unicast RTReq message to output queue")
        self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['RTReq'], destination=destination, body={})
                

    def handle_RTReq_msg(self, addr, message):
        """Handle the received RTReq message."""
        self.main_logger.info("message RTReq handling beggins (addr:"+str(addr)+",msg:"+str(message)+")")
        prefixes = []
        nexthops = []
        for route in self.route_table:
            if route.use_flag == True:
                prefixes.append(route.prefix)
                nexthops.append(route.nexthop)
        self.send_RTInfo_msg(destination=addr, plen=self.PLEN, pnum=len(prefixes), prefixes=prefixes, nexthops=nexthops)
    
    def send_RTInfo_msg(self, destination, plen, pnum, prefixes, nexthops):
        """Send unicast RTInfo message. """
        self.main_logger.info("adding unicast RTInfo message to output queue")
        self.ipv6_connection.add_msg_to_out_que(msgtype=self.MSG_TYPE['RTInfo'], destination=destination, body={'plen':plen, 'pnum':pnum, 'prefixes':prefixes, 'nexthops':nexthops})
                

    def handle_RTInfo_msg(self, addr, message):
        """Handle the received RTInfo message."""
        self.main_logger.info("message RTInfo handling beggins (addr:"+str(addr)+",msg:"+str(message)+")")
        node = {'addr':addr, 'prefixes':message['PREFIXES'], 'nexthops':message['NEXTHOPS']}
        self.other_nodes_rts.append(node)
            
                  

    def receive_ipv6_msgs(self, receive_ipv6_message_event):
        """Receive IPv6 messages when receive_ipv6_message_event is True.
        Then call suitable handle function.
        If received response, take it from response_table."""
        while True:
            receive_ipv6_message_event.wait()
            addr, message = self.ipv6_connection.take_msg_off_in_que()
            self.main_logger.info("taking message off input queue: "+str(message)+" from "+str(addr))
            if message["TYPE"] == self.MSG_TYPE['AckReq']:
                self.handle_AckReq_msg(addr[0], message) 
            elif message["TYPE"] == self.MSG_TYPE['Ack']:
                self.handle_Ack_msg(addr[0], message) 
            elif message["TYPE"] == self.MSG_TYPE['Hello']:
                self.handle_Hello_msg(addr[0], message) 
            elif message["TYPE"] == self.MSG_TYPE['IHU']:
                self.handle_IHU_msg(addr[0], message) 
            elif message["TYPE"] == self.MSG_TYPE['RouterID']:
                self.handle_RouterID_msg(addr[0], message) 
            elif message["TYPE"] == self.MSG_TYPE['NextHop']:
                self.handle_NextHop_msg(addr[0], message) 
            elif message["TYPE"] == self.MSG_TYPE['Update']:
                self.handle_Update_msg(addr[0], message) 
            elif message["TYPE"] == self.MSG_TYPE['RouteReq']:
                self.handle_RouteReq_msg(addr[0], message) 
            elif message["TYPE"] == self.MSG_TYPE['SeqnoReq']:
                self.handle_SeqnoReq_msg(addr[0], message) 
            elif message["TYPE"] == self.MSG_TYPE['RTReq']:
                self.handle_RTReq_msg(addr[0], message) 
            elif message["TYPE"] == self.MSG_TYPE['RTInfo']:
                self.handle_RTInfo_msg(addr[0], message) 
            else:
                self.main_logger.info("cannot handle message addr:"+str(addr)+" ["+str(message)+"]")
            receive_ipv6_message_event.clear()


    def run(self):
        self.ipv6_connection = peer_udp_connection.PeerUDPConnection(my_ip=self.MY_IPV6, ip_ver=6, interface_idx=self.IFACE_IDX, main_logger=self.main_logger)
        receive_ipv6_message_event = threading.Event()
        self.interface_table.append(InterfaceTableRecord(interface_id=self.IFACE_IDX, hello_seqno=0))

        connection_ipv6_thread = threading.Thread(name="ipv6_conn", target=self.ipv6_connection.run, args=(receive_ipv6_message_event, ), daemon=True)
        connection_ipv6_thread.start()

        receive_ipv6_msgs_thread = threading.Thread(name="ipv6_recv", target=self.receive_ipv6_msgs, args=(receive_ipv6_message_event, ), daemon=True)
        receive_ipv6_msgs_thread.start()

        check_neig_tab_thread = threading.Thread(name="check_neigh", target=self.check_neighb_table, args=( ), daemon=True)
        check_neig_tab_thread.start()

        check_route_exp_tim_thread = threading.Thread(name="check_rout_exp", target=self.check_route_exp_timers, args=( ), daemon=True)
        check_route_exp_tim_thread.start()


        Hello_per_IHU = int(self.IHU_MSG_INTERVAL/self.HELLO_MSG_INTERVAL)
        Hello_per_Update = int(self.UPDATE_MSG_INTERVAL/self.HELLO_MSG_INTERVAL)
        iterator = 0
        while True:
            time.sleep(self.HELLO_MSG_INTERVAL/10)
            self.send_Hello_msg()
            iterator += 1
            if (iterator%Hello_per_IHU) == 0:
                self.send_IHU_msg()
            if (iterator%Hello_per_Update) == 0:
                self.send_Update_msg()
            print('--------------------------------------- neigh_table ----------------------------------------')
            for record in self.neigh_table:
                print(str(record))
            print('--------------------------------------- source_table ---------------------------------------')
            for record in self.source_table:
                print(str(record))
            print('--------------------------------------- route_table ----------------------------------------')
            for record in self.route_table:
                print(str(record))
            print('--------------------------------------- seq_number ----------------------------------------')
            print(str(self.seqno))
