from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import Controller
from mininet.node import RemoteController


class Topo(object):
    def __init__(self):
        self.net = Mininet(controller=RemoteController )
        self.add_host_link()
        self.start_network()

    def add_host_link(self):
        info('*** Adding controller\n')
        self.net.addController('c0')
        info('*** Adding hosts\n')
        h1 = self.net.addHost('h1', ip='1.2.3.4',mac="00:00:00:00:00:00")
        h2 = self.net.addHost('h2', ip='1.2.3.5',mac="00:00:00:00:00:01")
        h3 = self.net.addHost('h3', ip='1.2.3.6',mac="00:00:00:00:00:02")
        info('*** Adding switch\n')
        s1 = self.net.addSwitch('s1')
        s2 = self.net.addSwitch('s2')
        info('*** Creating links\n')
        self.net.addLink(h1, s2, intfName1="h1-eth0", intfName2="s2-eth0")
        self.net.addLink(h2, s2, intfName1="h2-eth0", intfName2="s2-eth1")
        self.net.addLink(s1, s2, intfName1="s1-eth0", intfName2="s2-eth2")
        self.net.addLink(s1, h3, intfName1="s1-eth1", intfName2="h3-eth0")

    def start_network(self):
        info('*** Starting network\n')
        self.net.start()
        info('*** Running CLI\n')
        CLI(self.net)
        info('*** Stopping network')
        self.net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    t = Topo()
