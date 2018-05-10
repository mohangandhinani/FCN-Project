from pox.core import core
import pox.openflow.libopenflow_01 as of
from mininet.log import setLogLevel, info
from pox.lib.revent import *
from pox.lib.addresses import EthAddr

rules = [['00:00:00:00:00:01', '00:00:00:00:00:02']]


class SDNFirewall(EventMixin):

    def __init__(self):
        print("***********************in init ****************\n")
        self.listenTo(core.openflow)

    def dpid_to_mac(self,dpid):
        return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

    def _handle_ConnectionUp(self, event):
        print("********************AMG******************************\n")
        print("connection values ",core.openflow.connections)
        for k in core.openflow.connections:
            print ("k-v",self.dpid_to_mac(k.dpid))
        for rule in rules:
            block = of.ofp_match()
            block.dl_src = EthAddr(rule[0])
            block.dl_dst = EthAddr(rule[1])
            flow_mod = of.ofp_flow_mod()
            flow_mod.match = block
            event.connection.send(flow_mod)


def launch():
    print("***********************in launch ****************\n")
    core.registerNew(SDNFirewall)