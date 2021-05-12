
class InterfaceTableRecord:
    """Struct like object of Interface Table Record.
    Full descirption in RFC 6126, chapter 3.2.2."""
    def __init__(self, interface_id, hello_seqno):
        self.interface_id = interface_id
        self.hello_seqno = hello_seqno
    def __str__(self):
        return str(self.__dict__)

class NeighbourTableRecord:
    """Struct like object of Neighbbour Table Record.
    hello_hist - 5 last hello messages receive time (in float) i.e. [123,183,243,302,364]
    IHU_hist - last IHU message receive time
    Full descirption in RFC 6126, chapter 3.2.3."""
    def __init__(self, interface_id, neigh_addr, hello_hist, IHU_hist, rxcost, txcost, expect_seqno, Hello_interval, IHU_interval):
        self.interface_id = interface_id
        self.neigh_addr = neigh_addr
        self.hello_hist = hello_hist
        self.IHU_hist = IHU_hist
        self.rxcost = rxcost
        self.txcost = txcost
        self.expect_seqno = expect_seqno
        self.Hello_interval = Hello_interval
        self.IHU_interval = IHU_interval
    def __str__(self):
        return str(self.__dict__)

class SourceTableRecord:
    """Struct like object of Source Table Record.
    Full descirption in RFC 6126, chapter 3.2.4."""
    def __init__(self, prefix, plen, router_id, seqno, metric, garb_col_timer):
        self.prefix = prefix
        self.plen = plen
        self.router_id = router_id
        self.seqno = seqno
        self.metric = metric
        self.garb_col_timer = garb_col_timer
    def __str__(self):
        return str(self.__dict__)


class RouteTableRecord:
    """Struct like object of Route Table Record.
    I am not using neighbour field, beacouse I don't understand the purpose of it. Maybe it was needed when babel was working in second ISO layer.
    So for this implementation neighbour field is equal nexthop field.
    Full descirption in RFC 6126, chapter 3.2.5."""
    def __init__(self, prefix, prefix_ipv4, plen, router_id,  metric, seqno, nexthop, nexthop_ipv4, use_flag, route_expire_timer):
        self.prefix = prefix
        self.prefix_ipv4 = prefix_ipv4
        self.plen = plen
        self.router_id = router_id
        self.metric = metric
        self.seqno = seqno
        self.nexthop = nexthop
        self.nexthop_ipv4 = nexthop_ipv4
        self.use_flag = use_flag
        self.route_expire_timer = route_expire_timer
    def __str__(self):
        return str(self.__dict__)


class PendReqRecord:
    """Struct like object of Pending Request Table Record.
    Full descirption in RFC 6126, chapter 3.2.6."""
    def __init__(self, prefix, plen, router_id, seqno, nexthop, resent_count):
        self.prefix = prefix
        self.plen = plen
        self.router_id = router_id
        self.seqno = seqno
        self.nexthop = nexthop
        self.resent_count = resent_count
    def __str__(self):
        return str(self.__dict__)
