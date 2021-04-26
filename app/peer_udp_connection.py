import socket
import struct
import selectors
import time
import random
import threading
import logger
import messages

class PeerUDPConnection:

    def __init__(self, my_ip, ip_ver, interface_idx, main_logger):  
        """PeerUDPConnection initial function.

        Args:
            my_ip: String value of IP address.
            ip_ver: Integer value of IP version (4 or 6).
            interface_idx: Integer value of interface index.
        """
        self.IP_VER = ip_ver
        self.MY_IP = my_ip
        self.HOST = ''
        self.MULTICAST = 'ff02::1:6' # 'ff02::1' # 
        self.BROADCAST = '192.168.2.255'
        self.LOCALHOST_IPV6 = '::1'
        self.LOCALHOST_IPV4 = '127.0.0.1'
        self.PORT_IPV6 = 6696
        self.PORT_IPV4 = 6696 
        self.BUFFER_SIZE = 2048
        self.INTERFACE_INDEX = interface_idx
        self.main_logger = main_logger
        

        if self.IP_VER == 4: 
            self.ADDR = (self.HOST, self.PORT_IPV4)  
            self.BROADCAST_ADDR = (self.BROADCAST, self.PORT_IPV4) 
            self.LOCALHOST = self.LOCALHOST_IPV4
            self.PORT = self.PORT_IPV4
        elif self.IP_VER == 6:
            self.ADDR = (self.HOST, self.PORT_IPV6,0,self.INTERFACE_INDEX)  
            self.MULTICAST_ADDR = (self.MULTICAST, self.PORT_IPV6,0,self.INTERFACE_INDEX) 
            self.LOCALHOST = self.LOCALHOST_IPV6
            self.PORT = self.PORT_IPV6

        self.my_selector = selectors.DefaultSelector()
        self.msg = messages.Messages(self.main_logger)
        # record in output_queue = msg
        self.output_queue = []
        # record in input_queue = msg
        self.input_queue = []

    

    def add_msg_to_out_que(self, msgtype, destination, body):
        """Add the message to the output queue.
        
        Args:
            msgtype: Integer value of message id which is added to output que.
            destination: String value of unicast destination IP address or "MULTICAST"/"BROADCAST".
            body: String value of name of body (i.e. ACK_TO_EST_IP)
            data: Tuple object with content of message (every message have difrent content).
        """
        if self.IP_VER == 4: 
            if destination == "BROADCAST":
                tlv = (self.create_msg(msgtype, destination, body), self.BROADCAST_ADDR)
                self.output_queue.append(tlv)
            else:
                tlv = (self.create_msg(msgtype, destination, body), (destination, self.PORT))
                self.output_queue.append(tlv)
        elif self.IP_VER == 6:
            if destination == "MULTICAST":
                tlv = (self.create_msg(msgtype, destination, body), self.MULTICAST_ADDR)
                self.output_queue.append(tlv)
            else:
                tlv = (self.create_msg(msgtype, destination, body), (destination, self.PORT,0,self.INTERFACE_INDEX))
                self.output_queue.append(tlv)
    

    def take_msg_off_in_que(self):
        """Take the message off the input queue."""
        return self.input_queue.pop(0)


    def create_msg(self, msgtype, destination, body):
        """Create message.
        
        Args:
            msgtype: Integer value of message id which is added to output que.
            destination: String value of unicast destination IP address or "MULTICAST"/"BROADCAST".
            body: String value of name of body (i.e. ACK_TO_EST_IP)
            data: Tuple object with content of message (every message have difrent content).
        """
        return self.msg.createTLV(type=msgtype, body=body)

    def decode_msg(self, message):
        """Decode message."""
        tlvs = self.msg.decodePacket(message)
        decoded_tlvs = []
        for tlv in tlvs:
            decoded_tlvs.append(self.msg.decodeTLV(tlv))
        return decoded_tlvs

    def jitter(self):
        """Wait random time (between 0 to 20 centiseconds) to avoid colisions.
        RFC 6126 Apenix B Constants"""
        jitter_time = random.uniform(0,0.2)
        self.main_logger.info('jitter: '+str(jitter_time))
        time.sleep(jitter_time)


    def start_listening(self):
        """Start listening. Set socket and register it in selector."""
        self.main_logger.info('start binding socket to port '+str(self.PORT))
        if self.IP_VER == 4:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            # peer_socket.setsockopt(socket.SOL_SOCKET, 25, "wlan0"+'\0')
            peer_socket.setblocking(False)
            peer_socket.bind(self.ADDR)
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
            self.my_selector.register(peer_socket, events, self.handle_IO_event)
            self.main_logger.info('binding socket(ipv4) to port '+str(self.PORT)+' ended with sucess')
        elif self.IP_VER == 6:
            peer_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            
            req = struct.pack("=16si", socket.inet_pton(socket.AF_INET6, self.MULTICAST), self.INTERFACE_INDEX)
            peer_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, req)
            peer_socket.setblocking(False)
            # peer_socket.bind('', self.PORT_IPV6)
            peer_socket.bind(self.ADDR)
            events = selectors.EVENT_READ | selectors.EVENT_WRITE
            self.my_selector.register(peer_socket, events, self.handle_IO_event)
            self.main_logger.info('binding socket(ipv6) to port '+str(self.PORT)+' ended with sucess')
        

    def handle_IO_event(self, key, mask):
        """Handle Input or Output event. 

        Args:
            key: Variable passing message data.
            mask: Bit mask, describing what kind of event it is (READ/WRITE/BOTH).
        """
        sock = key.fileobj
        data = key.data
        if mask & selectors.EVENT_READ and self.receive_message_event.is_set() == False:
            data, msg_addr = sock.recvfrom(self.BUFFER_SIZE)
            self.main_logger.info("starting read event (data:"+str(data)+",addr:"+str(msg_addr)+")")
            if data and (msg_addr[0] != self.MY_IP) and (msg_addr[0] != self.LOCALHOST):
                data = self.decode_msg(data)
                for tlv in data:
                    self.main_logger.info('received ' + str(tlv) +' from '+str(msg_addr[0]))
                    if tlv != None:
                        self.input_queue.append((msg_addr, tlv))
                        self.receive_message_event.set()
                        while self.receive_message_event.is_set() != False:
                            time.sleep(0.01)

            elif not data:
                self.main_logger.info('closing connection to')
                sock.close()

        if mask & selectors.EVENT_WRITE:
            #self.main_logger.info("starting write event")
            if not self.output_queue:
                #self.main_logger.info('no messages to send')
                time.sleep(0.05)
            else:
                tlv, msg_addr = self.output_queue.pop(0)
                tlvs = [tlv]
                for i in range(len(self.output_queue)-1, -1, -1):
                    if self.output_queue[i][1] == msg_addr:
                        tlvs.append(self.output_queue[i][0])
                        self.output_queue.pop(i)
                packet = self.msg.createPacket(tlvs)
                self.main_logger.info('sending '+str(packet)+' to '+str(msg_addr))
                self.jitter()
                sock.sendto(packet, msg_addr)
                # msg, msg_addr = self.output_queue.pop(0)
                # self.main_logger.info('sending '+str(msg)+' to '+str(msg_addr))
                # self.jitter()
                # sock.sendto(msg, msg_addr)


    def run(self, receive_message_event):
        """Start main selector loop.

        Args:
            receive_message_event: Thread event which communicate that new message has been received.
        """
        self.receive_message_event = receive_message_event
        self.start_listening()

        while True:
            events = self.my_selector.select(timeout=1)
            if len(events) > 0:
                for key, mask in events:
                    #self.main_logger.info("new event, mask ("+str(bin(mask))+")")
                    try :
                        self.handle_IO_event(key, mask)
                    except Exception as e:
                        self.main_logger.warning("exception occure while calling IO event: "+str(e))
            else:
                self.main_logger.info("no IO event, timeout")
