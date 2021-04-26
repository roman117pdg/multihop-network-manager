import logger
import logging
import math
import ipaddress

class Messages:
    """Basic message class."""
    
    def __init__(self, main_logger):       
        """Massages initial function."""
        self.CODING_STANDARD = 'utf-8'
        self.BYTEORDER = 'big'

        self.PACKET = {'MAGIC':42, 'VERSION':2, 'MAGIC_LENGTH':1, 'VERSION_LENGTH':1,
         'BODYLENGTH_LENGTH':2}
        self.TLV = {'TYPE_LENGTH':1, 'LENGTH_LENGTH':1}
        self.Pad1 = {'TYPE':0}
        self.PadN = {'TYPE':1, 'MBZ_LENGTH':1}
        self.AckReq = {'TYPE':2, 'RESERVED_LENGTH':2, 'NONCE_LENGTH':2, 'INTERVAL_LENGTH':2}
        self.Ack = {'TYPE':3, 'NONCE_LENGTH':2}
        self.Hello = {'TYPE':4, 'RESERVED_LENGTH':2, 'SEQNO_LENGTH':2, 'INTERVAL_LENGTH':2}
        self.IHU = {'TYPE':5,'AE_LENGTH':1, 'RESERVED_LENGTH':1, 'RXCOST_LENGTH':2, 
        'INTERVAL_LENGTH':2, 'ADDRESS_LENGTH':8}
        self.RouterID = {'TYPE':6, 'RESERVED_LENGTH':2, 'ROUTERID_LENGTH':8}
        self.NextHop = {'TYPE':7, 'AE_LENGTH':1, 'RESERVED_LENGTH':1, 'NEXTHOP_LENGTH':8}
        self.Update = {'TYPE':8,'AE_LENGTH':1, 'FLAGS_LENGTH':1, 'PLEN_LENGTH':1, 
        'OMITTED_LENGTH':1, 'INTERVAL_LENGTH':2, 'SEQNO_LENGTH':2, 'METRIC_LENGTH':2}
        self.RouteReq = {'TYPE':9, 'AE_LENGTH':2, 'PLEN_LENGTH':1}
        self.SeqnoReq = {'TYPE':10,'AE_LENGTH':1, 'PLEN_LENGTH':1, 'SEQNO_LENGTH':2, 
        'HOPCOUNT_LENGTH':1, 'RESERVED_LENGTH':1, 'ROUTERID_LENGTH':8}
        self.RTReq = {'TYPE':11}
        self.RTInfo = {'TYPE':12, 'PLEN_LENGTH':1, 'PNUM_LENGTH':1}

        self.main_logger = main_logger


    def str2bytes(self, str_val, length):
        """Convert string to bytes.

        Args:
            string: String value that will be encoded.
            length: Integer value which describes length of output bytes (in octets).
        Return:
            Fixed size bytes object.        
        """
        array = bytes(str_val, encoding=self.CODING_STANDARD)
        if len(array) > length:
            print("error [wrong length] array:" +str(array) + ", expected length:"+str(length)+", true length: "+str(len(array)))
        while len(array) < length:
            array += b'\x00'
        return array

    def bytes2str(self, bytes_val):
        """Convert bytes to string."""
        if type(bytes_val) == str:
            return bytes_val
        else:
            return bytes_val.decode(self.CODING_STANDARD)


    def ip2bytes(self, ll_ip_val, length):
        """Convert link local IPv6 (string) to bytes."""
        [link_loc, address] = ll_ip_val.split('::')
        blocks = address.split(':')
        byte_addr = b''
        for block in blocks:
            byte_addr += int(block, 16).to_bytes(length=2, byteorder='big')
        return byte_addr

    def bytes2ip(self, bytes_val):
        """Convert bytes to IPv6."""
        str_addr = 'fe80:'
        for i in range(4):
            string = str(hex(int.from_bytes(bytes_val[0+2*i:2+2*i], byteorder='big')))
            length = len(string)
            str_addr += ':'+'0'*(6-length) + string[2:length]
        return str_addr


    def int2bytes(self, int_val, length):
        """Convert integer object to bytes.

        Args:
            integer: Integer value that will be encoded.
            length: Integer value which describes length of output bytes (in octets).
        Return:
            Fixed size bytes object.        
        """
        return int_val.to_bytes(length=length, byteorder=self.BYTEORDER)
        
    def bytes2int(self, bytes_val):
        """Convert bytes to integer."""
        if type(bytes_val) == int:
            return bytes_val
        else:
            return int.from_bytes(bytes_val, byteorder=self.BYTEORDER)
    

    def createPacket(self, tlv_messages):
        """Create Packet.
        Packets are used for aggregating TLV messages.

        Args:
            tlv_messages: Array of encoded tlv messages.
        """
        self.main_logger.info("creating packet, tlvS: "+str(tlv_messages))
        msg_magic = self.int2bytes(self.PACKET['MAGIC'], self.PACKET['MAGIC_LENGTH'])
        msg_version = self.int2bytes(self.PACKET['VERSION'], self.PACKET['VERSION_LENGTH'])
        body = self.str2bytes("", 0)
        for message in tlv_messages:
            body += message
        bodylength = len(body)
        msg_bodylength = self.int2bytes(bodylength, self.PACKET['BODYLENGTH_LENGTH'])
        msg_packetbody = body
        return bytes(msg_magic + msg_version + msg_bodylength + msg_packetbody)

    def decodePacket(self, packet):
        """Decode Packet."""
        packet_magic = packet[0]
        packet_version = packet[1]
        packet_bodylength = self.bytes2int(packet[2:4])
        self.main_logger.info("decoding packet, magic: "+str(packet_magic)+", version: "+str(packet_version)+", bodylen: "+str(packet_bodylength))
        if packet_magic != 42 or packet_version != 2:
            self.main_logger.warning("wrong magic or version, packet is silently ignored")
            return None
        else:
            body = packet[4:4+packet_bodylength]
            tlvs = []
            iterator = 0
            while iterator < packet_bodylength:
                value_len = body[iterator+1]
                tlvs.append(body[iterator:iterator+value_len+2])
                iterator += value_len+2
            self.main_logger.info("encoded tlvs: "+str(tlvs))
            dict_tlvs = []
            for tlv in tlvs:
                dict_tlv = self.decodeTLV(tlv)
                if dict_tlv != None:
                    dict_tlvs.append(dict_tlv)
            self.main_logger.info("decoded tlvs: "+str(dict_tlvs))
            return tlvs


    def createTLV(self, type, body=""):
        """Create TLV (TYPE, LENGTH, VALUE(body)) message. 
        Length describes only size of body (value), exclusive of Type and Length.
        Full description in RFC 6126, chapter 4.3.

        Args:
            type: Intrger value which describes type of TLV.
            body: body of message saved as dictionary.
        """
        self.main_logger.info("creating TLV, type: "+str(type)+", body: "+str(body))
        if type == 0:
            return self.int2bytes(type, self.TLV['TYPE_LENGTH'])
        else:
            if type == 1:
                tlv_body = self.createPadN(body['mbz'])
            elif type == 2:
                tlv_body = self.createAckReq(body['nonce'], body['interval'])
            elif type == 3:
                tlv_body = self.createAck(body['nonce'])
            elif type == 4:
                tlv_body = self.createHello(body['seqno'], body['interval'])
            elif type == 5:
                tlv_body = self.createIHU(body['ae'], body['rxcost'], body['interval'], body['address'])
            elif type == 6:
                tlv_body = self.createRouterID(body['routerid'])
            elif type == 7:
                tlv_body = self.createNextHop(body['ae'], body['nexthop'])
            elif type == 8:
                tlv_body = self.createUpdate(body['ae'], body['flags'], body['plen'], body['omitted'], body['interval'], body['seqno'], body['metric'], body['prefix'])
            elif type == 9:
                tlv_body = self.createRouteReq(body['ae'], body['plen'], body['prefix'])
            elif type == 10:
                tlv_body = self.createSeqnoReq(body['ae'], body['plen'], body['seqno'], body['hopcount'], body['routerid'], body['prefix'])
            elif type == 11:
                tlv_body = self.createRTReq()
            elif type == 12:
                tlv_body = self.createRTInfo(body['plen'], body['pnum'], body['prefixes'], body['nexthops'])

            tlv_type = self.int2bytes(type, self.TLV['TYPE_LENGTH'])
            tlv_length = self.int2bytes(len(tlv_body), self.TLV['LENGTH_LENGTH'])
            tlv_value = tlv_body
            return tlv_type + tlv_length + tlv_value
    
    def decodeTLV(self, tlv_msg):
        """Decode TLV message."""
        tlv_type = tlv_msg[0]
        self.main_logger.info("decoding TLV, type: "+str(tlv_type))
        if tlv_type == 0:
            return self.decodePad1(tlv_msg)
        elif tlv_type == 1:
            return self.decodePadN(tlv_msg)
        elif tlv_type == 2:
            return self.decodeAckReq(tlv_msg)
        elif tlv_type == 3:
            return self.decodeAck(tlv_msg)
        elif tlv_type == 4:
            return self.decodeHello(tlv_msg)
        elif tlv_type == 5:
            return self.decodeIHU(tlv_msg)
        elif tlv_type == 6:
            return self.decodeRouterID(tlv_msg)
        elif tlv_type == 7:
            return self.decodeNextHop(tlv_msg)
        elif tlv_type == 8:
            return self.decodeUpdate(tlv_msg)
        elif tlv_type == 9:
            return self.decodeRouteReq(tlv_msg)
        elif tlv_type == 10:
            return self.decodeSeqnoReq(tlv_msg)
        elif tlv_type == 11:
            return self.decodeRTReq(tlv_msg)
        elif tlv_type == 12:
            return self.decodeRTInfo(tlv_msg)


    def createPad1(self):
        """create Pad1 message.
        Full description in RFC 6126, chapter 4.4.1."""
        self.main_logger.info("creating Pad1 message")
        return None

    def decodePad1(self, msg):
        """This TLV is silently ignored on reception"""
        self.main_logger.info("decoding Pad1 message")
        return None


    def createPadN(self, mbz):
        """create PadN message.
        Full description in RFC 6126, chapter 4.4.2."""
        self.main_logger.info("creating PadN message")
        msg_mbz = self.int2bytes(mbz, self.PadN['MBZ_LENGTH'])
        return msg_mbz

    def decodePadN(self, msg):
        """This TLV is silently ignored on reception"""
        self.main_logger.info("creating Pad1 message")
        return None


    def createAckReq(self, nonce, interval):
        """create Acknowledgement Request message.
        Full description in RFC 6126, chapter 4.4.3."""
        self.main_logger.info("creating AckReq message")
        msg_reserved = self.int2bytes(0, self.AckReq['RESERVED_LENGTH'])
        msg_nonce = self.int2bytes(nonce, self.AckReq['NONCE_LENGTH'])
        msg_interval = self.int2bytes(interval, self.AckReq['INTERVAL_LENGTH'])
        return msg_reserved + msg_nonce + msg_interval

    def decodeAckReq(self, msg):
        self.main_logger.info("decoding AckReq message")
        # reserved value is ignored on reception
        i = 2 + self.AckReq['RESERVED_LENGTH']
        msg_nonce = self.bytes2int(msg[i:i+self.AckReq['NONCE_LENGTH']])
        i += self.AckReq['NONCE_LENGTH']
        msg_interval = self.bytes2int(msg[i:i+self.AckReq['INTERVAL_LENGTH]']])
        return {'TYPE':self.AckReq['TYPE'],'NONCE':msg_nonce, 'INTERVAL':msg_interval}


    def createAck(self, nonce):
        """create Acknowledgement message.
        Full description in RFC 6126, chapter 4.4.4."""
        self.main_logger.info("creating Ack message")
        msg_nonce = self.int2bytes(nonce, self.Ack['NONCE_LENGTH'])
        return msg_nonce

    def decodeAck(self, msg):
        self.main_logger.info("decoding Ack message")
        i = 2 
        msg_nonce = self.bytes2int(msg[i:i+self.Ack['NONCE_LENGTH']])
        return {'TYPE':self.Ack['TYPE'],'NONCE':msg_nonce}


    def createHello(self, seqno, interval):
        """create Hello message.
        Full description in RFC 6126, chapter 4.4.5."""
        self.main_logger.info("creating Hello message")
        msg_reserved = self.int2bytes(0, self.Hello['RESERVED_LENGTH'])
        msg_seqno = self.int2bytes(seqno, self.Hello['SEQNO_LENGTH'])
        msg_interval = self.int2bytes(interval, self.Hello['INTERVAL_LENGTH'])
        return msg_reserved + msg_seqno + msg_interval

    def decodeHello(self, msg):
        self.main_logger.info("decoding Hello message")
        # reserved value is ignored on reception
        i = 2 + self.Hello['RESERVED_LENGTH']
        msg_seqno = self.bytes2int(msg[i:i+self.Hello['SEQNO_LENGTH']])
        i += self.Hello['SEQNO_LENGTH']
        msg_interval = self.bytes2int(msg[i:i+self.Hello['INTERVAL_LENGTH']])
        return {'TYPE':self.Hello['TYPE'], 'SEQNO':msg_seqno, 'INTERVAL':msg_interval}



    def createIHU(self, ae, rxcost, interval, address):
        """create I Hear You (IHU) message.
        Full description in RFC 6126, chapter 4.4.6."""
        self.main_logger.info("creating IHU message")
        msg_ae = self.int2bytes(ae, self.IHU['AE_LENGTH'])
        msg_reserved = self.int2bytes(0, self.IHU['RESERVED_LENGTH'])
        msg_rxcost = self.int2bytes(rxcost, self.IHU['RXCOST_LENGTH'])
        msg_interval = self.int2bytes(interval, self.IHU['INTERVAL_LENGTH'])
        msg_address = self.ip2bytes(address, self.IHU['ADDRESS_LENGTH']) 
        return msg_ae + msg_reserved + msg_rxcost + msg_interval + msg_address

    def decodeIHU(self, msg):
        self.main_logger.info("decoding IHU message")
        i = 2
        msg_ae = self.bytes2int(msg[i:i+self.IHU['AE_LENGTH']])
        # reserved value is ignored on reception
        i += self.IHU['AE_LENGTH'] + self.IHU['RESERVED_LENGTH'] 
        msg_rxcost = self.bytes2int(msg[i:i+self.IHU['RXCOST_LENGTH']])
        i += self.IHU['RXCOST_LENGTH']
        msg_interval = self.bytes2int(msg[i:i+self.IHU['INTERVAL_LENGTH']])
        i += self.IHU['INTERVAL_LENGTH']
        msg_address = self.bytes2ip(msg[i:i+self.IHU['ADDRESS_LENGTH']])
        return {'TYPE':self.IHU['TYPE'], 'AE':msg_ae, 'RXCOST':msg_rxcost, 'INTERVAL':msg_interval,
         'ADDRESS':msg_address}

        
    def createRouterID(self, routerid):
        """create RouterID message.
        Full description in RFC 6126, chapter 4.4.7."""
        self.main_logger.info("creating RouterID message")
        msg_reserved = self.int2bytes(0, self.RouterID['RESERVED_LENGTH'])
        msg_routerid = self.int2bytes(routerid, self.RouterID['ROUTERID_LENGTH'])
        return msg_reserved + msg_routerid

    def decodeRouterID(self, msg):
        self.main_logger.info("decoding RouterID message")
        # reserved value is ignored on reception
        i = 2 + self.RouterID['RESERVED_LENGTH']
        msg_routerid = self.bytes2int(msg[i:i+self.RouterID['ROUTERID_LENGTH']])
        return {'TYPE':self.RouterID['TYPE'], 'ROUTERID':msg_routerid}

        
    def createNextHop(self, ae, nexthop):
        """create Next Hop message.
        Full description in RFC 6126, chapter 4.4.8."""
        self.main_logger.info("creating NextHop message")
        msg_ae = self.int2bytes(ae, self.NextHop['AE_LENGTH'])
        msg_reserved = self.int2bytes(0, self.NextHop['RESERVED_LENGTH'])
        msg_nexthop = self.int2bytes(nexthop, self.NextHop['NEXTHOP_LENGTH'])
        return msg_ae + msg_reserved + msg_nexthop

    def decodeNextHop(self, msg):
        self.main_logger.info("decoding NextHop message")
        i = 2
        msg_ae = self.bytes2int(msg[i:i+self.NextHop['AE_LENGTH']])
        # reserved value is ignored on reception
        i += self.NextHop['AE_LENGTH'] + self.NextHop['RESERVED_LENGTH'] 
        msg_nexthop = self.bytes2int(msg[i:i+self.NextHop['NEXTHOP_LENGTH']])
        return {'TYPE':self.NextHop['TYPE'], 'AE':msg_ae, 'NEXTHOP':msg_nexthop}


    def createUpdate(self, ae, flags, plen, omitted, interval, seqno, metric, prefix):
        """create Update message.
        Full description in RFC 6126, chapter 4.4.9."""
        self.main_logger.info("creating Update message")
        msg_ae = self.int2bytes(ae, self.Update['AE_LENGTH'])
        msg_flags = self.int2bytes(flags, self.Update['FLAGS_LENGTH'])
        msg_plen = self.int2bytes(plen, self.Update['PLEN_LENGTH'])
        msg_omitted = self.int2bytes(omitted, self.Update['OMITTED_LENGTH'])
        msg_interval = self.int2bytes(interval, self.Update['INTERVAL_LENGTH'])
        msg_seqno = self.int2bytes(seqno, self.Update['SEQNO_LENGTH'])
        msg_metric = self.int2bytes(metric, self.Update['METRIC_LENGTH'])
        PREFIX_LENGTH = math.ceil(plen/8 - omitted) # round up
        msg_prefix = self.ip2bytes(prefix, PREFIX_LENGTH)

        return msg_ae + msg_flags + msg_plen + msg_omitted + msg_interval + msg_seqno + msg_metric + msg_prefix

    def decodeUpdate(self, msg):
        self.main_logger.info("decoding Update message")
        i = 2
        msg_ae = self.bytes2int(msg[i:i+self.Update['AE_LENGTH']])
        i += self.Update['AE_LENGTH']
        msg_flags = self.bytes2int(msg[i:i+self.Update['FLAGS_LENGTH']])
        i += self.Update['FLAGS_LENGTH']
        msg_plen = self.bytes2int(msg[i:i+self.Update['PLEN_LENGTH']])
        i += self.Update['PLEN_LENGTH']
        msg_omitted = self.bytes2int(msg[i:i+self.Update['OMITTED_LENGTH']])
        i += self.Update['OMITTED_LENGTH']
        msg_interval = self.bytes2int(msg[i:i+self.Update['INTERVAL_LENGTH']])
        i += self.Update['INTERVAL_LENGTH']
        msg_seqno = self.bytes2int(msg[i:i+self.Update['SEQNO_LENGTH']])
        i += self.Update['SEQNO_LENGTH']
        msg_metric = self.bytes2int(msg[i:i+self.Update['METRIC_LENGTH']])
        i += self.Update['METRIC_LENGTH']
        PREFIX_LENGTH = math.ceil(msg_plen/8 - msg_omitted) # round up
        msg_prefix = self.bytes2ip(msg[i:i+PREFIX_LENGTH])
        return {'TYPE':self.Update['TYPE'], 'AE':msg_ae, 'FLAGS':msg_flags, 'PLEN':msg_plen,
         'OMITTED':msg_omitted, 'INTERVAL':msg_interval, 'SEQNO':msg_seqno, 'METRIC':msg_metric, 
         'PREFIX':msg_prefix}


        
    def createRouteReq(self, ae, plen, prefix):
        """create Route Request message.
        Full description in RFC 6126, chapter 4.4.10."""
        self.main_logger.info("creating RouteReq message")
        msg_ae = self.int2bytes(ae, self.RouteReq['AE_LENGTH'])
        msg_plen = self.int2bytes(plen, self.RouteReq['PLEN_LENGTH'])
        PREFIX_LENGTH = math.ceil(plen/8)
        msg_prefix = self.ip2bytes(prefix, self.RouteReq['PREFIX_LENGTH'])
        return msg_ae + msg_plen + msg_prefix

    def decodeRouteReq(self, msg):
        self.main_logger.info("decoding RouteReq message")
        i = 2
        msg_ae = self.bytes2int(msg[i:i+self.RouteReq['AE_LENGTH']])
        i += self.RouteReq['AE_LENGTH']
        msg_plen = self.bytes2int(msg[i:i+self.RouteReq['PLEN_LENGTH']])
        i += self.RouteReq['PLEN_LENGTH']
        PREFIX_LENGTH = math.ceil(msg_plen/8)
        msg_prefix = self.bytes2ip(msg[i:i+PREFIX_LENGTH])
        return {'TYPE':self.RouteReq['TYPE'], 'AE':msg_ae, 'PLEN':msg_plen, 'PREFIX':msg_prefix}

        
    def createSeqnoReq(self, ae, plen, seqno, hopcount, routerid, prefix):
        self.main_logger.info("creating SeqnoReq message")
        """create Seqno Request message.
        Full description in RFC 6126, chapter 4.4.11."""
        msg_ae = self.int2bytes(ae, self.SeqnoReq['AE_LENGTH'])
        msg_plen = self.int2bytes(plen, self.SeqnoReq['PLEN_LENGTH'])
        msg_seqno = self.int2bytes(seqno, self.SeqnoReq['SEQNO_LENGTH'])
        msg_hopcount = self.int2bytes(hopcount, self.SeqnoReq['HOPCOUNT_LENGTH'])
        msg_reserved = self.int2bytes(0, self.SeqnoReq['RESERVED_LENGTH'])
        msg_routerid = self.int2bytes(routerid, self.SeqnoReq['ROUTERID_LENGTH'])
        PREFIX_LENGTH = math.ceil(plen/8)
        msg_prefix = self.ip2bytes(prefix, PREFIX_LENGTH)
        return msg_ae + msg_plen + msg_seqno + msg_hopcount + msg_reserved + msg_routerid + msg_prefix

    def decodeSeqnoReq(self, msg):
        self.main_logger.info("decoding SeqnoReq message")
        i = 2
        msg_ae = self.bytes2int(msg[i:i+self.SeqnoReq['AE_LENGTH']])
        i += self.SeqnoReq['AE_LENGTH']
        msg_plen = self.bytes2int(msg[i:i+self.SeqnoReq['PLEN_LENGTH']])
        i += self.SeqnoReq['PLEN_LENGTH']
        msg_seqno = self.bytes2int(msg[i:i+self.SeqnoReq['SEQNO_LENGTH']])
        i += self.SeqnoReq['SEQNO_LENGTH']
        msg_hopcount = self.bytes2int(msg[i:i+self.SeqnoReq['HOPCOUNT_LENGTH']])
        i += self.SeqnoReq['HOPCOUNT_LENGTH'] + self.SeqnoReq['RESERVED_LENGTH']
        # reserved value is ignored on reception
        msg_routerid = self.bytes2int(msg[i:i+self.SeqnoReq['ROUTERID_LENGTH']])
        i += self.SeqnoReq['ROUTERID_LENGTH']
        PREFIX_LENGTH = math.ceil(msg_plen/8)
        msg_prefix = self.bytes2ip(msg[i:i+PREFIX_LENGTH])
        return {'TYPE':self.SeqnoReq['TYPE'], 'AE':msg_ae, 'PLEN':msg_plen, 'SEQNO':msg_seqno, 
         'HOPCOUNT':msg_hopcount, 'ROUTERID':msg_routerid, 'PREFIX':msg_prefix}


    def createRTReq(self):
        """create Acknowledgement message.
        Used for creating network topology in Flask API."""
        self.main_logger.info("creating RTReq message")
        return b''

    def decodeRTReq(self, msg):
        self.main_logger.info("decoding RTReq message")
        return {'TYPE':self.RTReq['TYPE']}


    def createRTInfo(self, plen, pnum, prefixes, nexthops):
        """create Acknowledgement message.
        Used for creating network topology in Flask API."""
        self.main_logger.info("creating RTInfo message")
        msg_plen = self.int2bytes(plen, self.RTInfo['PLEN_LENGTH'])
        msg_pnum = self.int2bytes(pnum, self.RTInfo['PNUM_LENGTH'])
        PREFIX_LENGTH = math.ceil(plen/8)
        msg_prefixes = b''
        for prefix in prefixes:
            msg_prefixes += self.ip2bytes(prefix, PREFIX_LENGTH)
        msg_nexthops = b''
        for nexthop in nexthops:
            msg_nexthops += self.ip2bytes(nexthop, PREFIX_LENGTH)
        return msg_plen + msg_pnum + msg_prefixes + msg_nexthops

    def decodeRTInfo(self, msg):
        self.main_logger.info("decoding RTInfo message")
        i = 2 
        msg_plen = self.bytes2int(msg[i:i+self.RTInfo['PLEN_LENGTH']])
        PREFIX_LENGTH = math.ceil(msg_plen/8)
        i += self.RTInfo['PLEN_LENGTH']
        msg_pnum = self.bytes2int(msg[i:i+self.RTInfo['PNUM_LENGTH']])
        i += self.RTInfo['PNUM_LENGTH']
        msg_prefixes = []
        for j in range(i, i+msg_pnum):
            msg_prefixes.append(self.bytes2ip(msg[i:i+PREFIX_LENGTH]))
        i += self.RTInfo['PNUM_LENGTH']*PREFIX_LENGTH
        msg_nexthops = []
        for j in range(i, i+msg_pnum):
            msg_nexthops.append(self.bytes2ip(msg[i:i+PREFIX_LENGTH]))            
        return {'TYPE':self.RTInfo['TYPE'],'PLEN':msg_plen,'PNUM':msg_pnum,'PREFIXES':msg_prefixes,'NEXTHOPS':msg_nexthops}
