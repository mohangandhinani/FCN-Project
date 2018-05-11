from pox.core import core

from pox.lib.addresses import IPAddr

from pox.lib.addresses import EthAddr

import pox.openflow.libopenflow_01 as of

from pox.lib.util import dpid_to_str, str_to_bool

from pox.lib.packet.arp import arp

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST

log = core.getLogger()

# flow1:

switch3f = 0000000000000003

flow3fmsg = of.ofp_flow_mod()

flow3fmsg.cookie = 0

flow3fmsg.match.in_port = 1

flow3fmsg.match.dl_type = 0x0800

flow3fmsg.match.nw_src = IPAddr("192.168.1.10")

# ACTIONS---------------------------------

flow3fout = of.ofp_action_output(port=2)

flow3fsrcIP = of.ofp_action_nw_addr.set_src(IPAddr("10.0.0.2"))

flow3fsrcMAC = of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:05"))

flow3fdstMAC = of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:06"))
flow3fvlanid = of.ofp_action_vlan_vid(vlan_vid=123)

flow3fmsg.actions = [flow3fsrcIP, flow3fsrcMAC, flow3fdstMAC, flow3fvlanid, flow3fout]



# flow3b:

switch3b = 0000000000000003

flow3bmsg = of.ofp_flow_mod()

flow3bmsg.cookie = 0

flow3bmsg.match.in_port = 2

flow3bmsg.match.dl_type = 0x0800

flow3bmsg.match.nw_dst = IPAddr("10.0.0.2")

# ACTIONS---------------------------------

flow3bout = of.ofp_action_output(port=1)

flow3bdstIP = of.ofp_action_nw_addr.set_dst(IPAddr("192.168.1.10"))

flow3bsrcMAC = of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:04"))

flow3bdstMAC = of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:02"))
flow3bvlanid = of.ofp_action_vlan_vid()

flow3bmsg.actions = [flow3bdstIP, flow3bsrcMAC, flow3bdstMAC, flow3bvlanid, flow3bout]

# flow1:

switch4f = 0000000000000004

flow4fmsg = of.ofp_flow_mod()

flow4fmsg.cookie = 0

flow4fmsg.match.in_port = 1

flow4fmsg.match.dl_type = 0x0800

#flow4fmsg.match.nw_src = IPAddr("10.0.0.2")

# ACTIONS---------------------------------

flow4fout = of.ofp_action_output(port=2)

#flow4fsrcIP = of.ofp_action_nw_addr.set_src(IPAddr("10.0.0.2"))

flow4fsrcMAC = of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:03"))

flow4fdstMAC = of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:01"))
flow4fvlanid = of.ofp_action_vlan_vid(vlan_vid=0)

flow4fmsg.actions = [flow4fsrcMAC, flow4fdstMAC, flow4fvlanid, flow4fout]

# flow1:

switch4b = 0000000000000004

flow4bmsg = of.ofp_flow_mod()

flow4bmsg.cookie = 0

flow4bmsg.match.in_port = 2

flow4bmsg.match.dl_type = 0x0800

#flow4bmsg.match.nw_src = IPAddr("10.0.0.2")

# ACTIONS---------------------------------

flow4bout = of.ofp_action_output(port=1)

#flow4bsrcIP = of.ofp_action_nw_addr.set_src(IPAddr("10.0.0.2"))

flow4bsrcMAC = of.ofp_action_dl_addr.set_src(EthAddr("00:00:00:00:00:06"))

flow4bdstMAC = of.ofp_action_dl_addr.set_dst(EthAddr("00:00:00:00:00:05"))
flow4bvlanid = of.ofp_action_vlan_vid()

flow4bmsg.actions = [flow4bsrcMAC, flow4bdstMAC, flow4bvlanid, flow4bout]



def install_flows(event):
    log.info("    *** Installing static flows... ***")

    # Push flows to switches

    if event.dpid == 3:
        core.openflow.sendToDPID(switch3f, flow3fmsg)
        core.openflow.sendToDPID(switch3b, flow3bmsg)
    elif event.dpid == 4:
        core.openflow.sendToDPID(switch4f, flow4fmsg)
        core.openflow.sendToDPID(switch4b, flow4bmsg)
    else:
        log.info(" INVALID CASE OF installing flows")
    log.info("    *** Static flows installed. ***")


def _handle_ConnectionUp(event):
    log.info("*** install flows *** {0}".format(str(event.dpid)))

    install_flows(event)


def _handle_PacketIn(event):
    log.info("*** _handle_PacketIn... ***{0}, {1}".format(str(event.dpid), event.port))

    dpid = event.connection.dpid

    inport = event.port

    packet = event.parsed

    if not packet.parsed:
        log.warning("%i %i ignoring unparsed packet", dpid, inport)

        return

    a = packet.find('arp')

    if not a: return

    log.info("%s ARP %s %s => %s", dpid_to_str(dpid),

             {arp.REQUEST: "request", arp.REPLY: "reply"}.get(a.opcode,

                                                              'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))

    if a.prototype == arp.PROTO_TYPE_IP:

        if a.hwtype == arp.HW_TYPE_ETHERNET:

            if a.opcode == arp.REQUEST:

                if str(a.protodst) == "192.168.1.1":
                    r = arp()

                    r.hwtype = a.hwtype

                    r.prototype = a.prototype

                    r.hwlen = a.hwlen

                    r.protolen = a.protolen

                    r.opcode = arp.REPLY

                    r.hwdst = a.hwsrc

                    r.protodst = a.protosrc

                    r.protosrc = a.protodst

                    r.hwsrc = EthAddr("00:00:00:00:00:03")

                    e = ethernet(type=packet.type, src=r.hwsrc,

                                 dst=a.hwsrc)

                    e.payload = r

                    log.info("%s answering ARP for %s" % (dpid_to_str(dpid),

                                                          str(r.protosrc)))

                    msg = of.ofp_packet_out()

                    msg.data = e.pack()

                    msg.actions.append(of.ofp_action_output(port=

                                                            of.OFPP_IN_PORT))

                    msg.in_port = inport

                    event.connection.send(msg)

                if str(a.protodst) == "10.0.0.2":
                    r = arp()

                    r.hwtype = a.hwtype

                    r.prototype = a.prototype

                    r.hwlen = a.hwlen

                    r.protolen = a.protolen

                    r.opcode = arp.REPLY

                    r.hwdst = a.hwsrc

                    r.protodst = a.protosrc

                    r.protosrc = a.protodst

                    r.hwsrc = EthAddr("00:00:00:00:00:04")

                    e = ethernet(type=packet.type, src=r.hwsrc,

                                 dst=a.hwsrc)

                    e.payload = r

                    log.info("%s answering ARP for %s" % (dpid_to_str(dpid),

                                                          str(r.protosrc)))

                    msg = of.ofp_packet_out()

                    msg.data = e.pack()

                    msg.actions.append(of.ofp_action_output(port=

                                                            of.OFPP_IN_PORT))

                    msg.in_port = inport

                    event.connection.send(msg)


def launch():
    log.info("*** Starting... ***")

    log.info("*** Waiting for switches to connect.. ***")

    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)

    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
