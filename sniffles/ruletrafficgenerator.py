import re
import random
import struct
import socket
import sys
import copy
from os import listdir
from os.path import isfile, join
from sniffles.rulereader import *
from sniffles.nfa import *
from sniffles.vendor_mac_list import VENDOR_MAC_OUI

ETHERNET_HDR_GEN_RANDOM = 0
ETHERNET_HDR_GEN_DISTRIBUTION = 1
MAC_IP_MAP = dict()
OPEN_PORT_CHANCE = 20
VENDOR_MAC_DIST_DOMAIN = {}
VENDOR_MAC_DIST = {}
HOME_IP_PREFIXES = []
HOME_IP_PREFIXESv6 = []
FIN = 0x01
SYN = 0x02
ACK = 0x10
MORE_FRAGMENTS = 0x2000
SUPPORTED_PROTOCOLS = {'icmp': 1, 'tcp': 6, 'udp': 17}

# Scan attack types
SYN_SCAN = 0
CONNECTION_SCAN = 1

HTTP_CONTENT = ['http_client_body', 'http_cookie',
                'http_raw_cookie', 'http_header', 'http_raw_header',
                'http_method', 'http_uri', 'http_raw_uri', 'http_stat_code',
                'http_stat_msg', 'http_encode']

# Snort Possible Port lists for variables such as $HTTP_PORTS
HTTP_PORTS = [80, 311, 591, 593, 901, 1220, 1414, 1830, 2301, 2381,
              2809, 3128, 3702, 5250, 7001, 7777, 7779, 8000, 8008,
              8028, 8080, 8088, 8118, 8123, 8180, 8243, 8280, 8888,
              9090, 9091, 9443, 9999, 11371]
FILE_PORTS = [80, 81, 311, 591, 593, 901, 1220, 1414, 1741, 1830,
              2301, 2381, 2809, 3128, 3702, 4343, 4848, 5250, 7001,
              7145, 7510, 7777, 7779, 8000, 8008, 8014, 8028, 8080,
              8088, 8090, 8118, 8123, 8180, 8181, 8243, 8280, 8800,
              8888, 8899, 9080, 9090, 9091, 9443, 9999, 11371, 55555,
              100, 143]
FTP_PORTS = [21, 2100, 3535]
MAIL_PORTS = [25, 143, 465, 691]
POP_PORTS = [110, 109]
SMB_PORTS = [139, 445]
NBT_PORTS = [135, 137, 138]
NNTP_PORTS = [119]
DNS_PORTS = [53]
ORACLE_PORTS = [1024]


def set_ipv4_home(list):
    """
        Set the list of IPv4 prefixes for home addresses.
        This list will ensure that all 'Home' IP addrs will
        match the prefix of one prefix in the list.  If
        not provided, then no prefixes will be used for home addresses
    """
    global HOME_IP_PREFIXES
    HOME_IP_PREFIXES = list


def set_ipv6_home(list):
    """
        Set the list of IPv6 prefixes for home addresses.
        This list will ensure that all 'Home' IP addrs will
        match the prefix of one prefix in the list.  If
        not provided, then no prefixes will be used for home addresses
    """
    global HOME_IP_PREFIXESv6
    HOME_IP_PREFIXESv6 = list


def get_all_subclasses(myCls):
    all_subclasses = []

    for subclass in myCls.__subclasses__():
        all_subclasses.append(subclass)
        all_subclasses.extend(get_all_subclasses(subclass))

    return all_subclasses


class Conversation(object):
    """
        Dictates rules for a particular communication or series of
        communications.
    """

    def __init__(self, con, sconf):

        subclasses = get_all_subclasses(globals()["TrafficStream"])

        self.ts = []
        self.ts_active = []
        self.started = False

        if con:
            tsrules = con.getTS()
        else:
            tsrules = [None]

        while tsrules:

            synch = False

            myrule = tsrules.pop(0)
            mypkts = [RulePkt()]

            if myrule:
                synch = myrule.getSynch()

            if myrule and myrule.getTypeTS() is not None:
                useSubclass = False
                for subclass in subclasses:
                    subInstance = subclass()
                    if subInstance.testTypeTS(myrule.getTypeTS()):
                        myts = subclass(myrule, sconf)
                        useSubclass = True
                        break

                if not useSubclass:
                    myts = TrafficStream(myrule, sconf)
            else:
                myts = TrafficStream(myrule, sconf)

            if synch:
                if len(self.ts_active) == 0:
                    self.ts_active.append(myts)
                else:
                    self.ts.append(myts)
            else:
                if len(self.ts) == 0:
                    self.ts_active.append(myts)
                else:
                    self.ts.append(myts)

    def getNextPkts(self):
        pkts = []
        if self.has_packets():
            self.started = True
            for ts in self.ts_active:
                pkts.extend(ts.getNextPacket())
        self.updateStreams()
        return pkts

    def getNextTS(self):
        if self.ts_active:
            myts = self.ts_active.pop(0)
            self.updateStreams()
            return myts
        return None

    def getNumberOfStreams(self):
        num_ts = (len(self.ts_active) if self.ts_active else 0) + \
                 (len(self.ts) if self.ts else 0)
        return num_ts

    def has_packets(self):
        if (self.ts_active and len(self.ts_active) > 0) or \
           (self.ts and len(self.ts) > 0):
            return True
        else:
            return False

    def has_started(self):
        return self.started

    def updateStreams(self):
        if self.ts_active is not None:
            self.ts_active[:] = [
                s for s in self.ts_active if not s.isFinished()]
        if len(self.ts_active) < 1:
            if self.ts is not None and len(self.ts) > 0:
                self.ts_active = []
                ts = self.ts.pop(0)
                while ts:
                    self.ts_active.append(ts)
                    if ts.getSynch():
                        break
                    if self.ts:
                        ts = self.ts.pop(0)
                    else:
                        ts = None
            else:
                self.ts_active = None


class TrafficStream(object):
    """
        Basic definition of a traffic stream.  Packets will be created
        dependent on the values provided to this object.  Extend this
        class to add new traffic functionality.

        API:
          getNextPacket() will return the next packet for this stream or
          None if there are no more packets for this stream.

          has_packets() returns true if the stream has packets to send, or
          false otherwise.

          is_finished() returns true if the stream has no packets, or false
          otherwise (deprecated).
    """

    def __init__(self, rule=None, sconf=None):
        # local
        flow_opts = None
        handshake = False
        ipv6_percent = 0
        teardown = False

        # member
        self.stream_ooo = False
        self.synch = False
        self.myp = None
        self.pkt_len = -1
        self.packets_in_stream = 1
        self.mac_def_file = None
        self.flow_ack = False
        self.rand = False
        self.full_eval = False
        self.full_match = False
        self.bi = False
        self.rule = rule
        self.ack_dir = "to client"
        self.advance_pkt = False
        self.content_string = None
        self.fragments = []
        self.split = []
        self.frag_id = 0
        self.footer = 0
        self.header = 0
        self.ip_type = 4
        self.lost_pkt_string = None
        self.last_off = 0
        self.mac_gen = ETHERNET_HDR_GEN_RANDOM
        self.next_is_ack = False
        self.p_count = 0
        self.window = 0
        self.order = None
        self.dropped = False
        self.frag_con_size = 0
        self.rand = False

        self.tcp_overlap = False
        self.shift_seq = False

        if sconf:
            handshake = sconf.getTCPHandshake()
            teardown = sconf.getTCPTeardown()
            self.pkt_len = sconf.getPktLength()
            self.mac_def_file = sconf.getMacAddrDef()
            if sconf.getPktsPerStream() > 1:
                self.packets_in_stream = sconf.getPktsPerStream()
            self.flow_ack = sconf.getTCPACK()
            self.rand = sconf.getRandom()
            self.full_eval = sconf.getFullEval()
            self.full_match = sconf.getFullMatch()
            self.bi = sconf.getBi()
            if self.mac_def_file:
                self.mac_gen = ETHERNET_HDR_GEN_DISTRIBUTION

        if rule:
            if not handshake and rule.getHandshake():
                handshake = True
            if not teardown and rule.getTeardown():
                teardown = True
            if rule.getLength() >= 0:
                self.pkt_len = rule.getLength()
            self.tcp_overlap = rule.getTCPOverlap()
            self.stream_ooo = rule.getOutOfOrder()
            self.synch = rule.getSynch()
            self.myp = rule.getPkts()
            self.packets_in_stream = len(rule.getPkts())
            flow_opts = rule.getFlowOptions()
            if rule.getIPV() == 6:
                ipv6_percent = 100
            self.proto = rule.getProto()
            if self.proto.lower() not in SUPPORTED_PROTOCOLS:
                pick = random.randint(0, len(SUPPORTED_PROTOCOLS)-1)
                protos = list(SUPPORTED_PROTOCOLS.keys())
                self.proto = protos[pick]
            self.sport = Port(rule.getSport())
            self.dport = Port(rule.getDport())
        else:
            pick = random.randint(0, len(SUPPORTED_PROTOCOLS)-1)
            protos = list(SUPPORTED_PROTOCOLS.keys())
            self.proto = protos[pick]
            self.rand = True

        if sconf is None and rule is None:
            self.rand = True

        if handshake:
            self.header = 3
        if teardown:
            self.footer = 4
        if self.proto == 'tcp':
            self.current_seq_a_to_b = random.randint(0, 4000000000)
            self.current_ack_a_to_b = 0
            self.current_seq_b_to_a = random.randint(0, 4000000000)
            self.current_ack_b_to_a = 0

        if ipv6_percent > 0 and ipv6_percent <= 100:
            pick = random.randint(0, 99) + 1
            if pick > (100 - ipv6_percent):
                self.ip_type = 6

        if rule:
            self.sip = self.calculateIP(rule.getSrcIp(), True)
            self.dip = self.calculateIP(rule.getDstIp(), False)

        if self.rand:
            self.sip = self.calculateIP('any', True)
            self.dip = self.calculateIP('any', False)
            self.sport = Port('any')
            self.dport = Port('any')

        # Always orient flow from client
        if flow_opts:
            change_dir = re.compile("/(to[_\\s]?client|from[_\\s]?server)/i")
            if change_dir.match(flow_opts):
                temp = self.dip
                self.dip = self.sip
                self.sip = temp
                temp = self.dport
                self.dport = self.sport
                self.sport = temp

    def testTypeTS(self, value):
        return True

    def __str__(self):
        mystr = "Traffic Stream\n"
        mystr += "  PROTO: " + self.proto + "\n"
        mystr += "  SIP: " + self.sip + "\n"
        mystr += "  DIP: " + self.dip + "\n"
        mystr += "  SPORT: " + str(self.sport) + "\n"
        mystr += "  DPORT: " + str(self.dport) + "\n"
        mystr += "  #Pkt Rules: " + str(self.packets_in_stream) + "\n"
        mystr += "  Len: " + str(self.pkt_len) + "\n"
        return mystr

    def buildFragPkt(self, dir="to server", frag=None, offset=0, mf=False):
        sip = self.sip
        dip = self.dip
        if dir == "to client":
            sip = self.dip
            dip = self.sip
        pkt = Packet(self.proto, sip, dip, self.ip_type, self.sport,
                     self.dport, 0, 0, 0, self.mac_gen, self.mac_def_file,
                     frag, self.frag_id, offset, mf)
        return pkt

    def buildPkt(self, dir="to server", flags=ACK, content=None, seq=None,
                 ack=None):
        sip = self.sip
        dip = self.dip
        sport = self.sport
        dport = self.dport
        seq_no = seq
        ack_no = ack
        if dir == "to client":
            sip = self.dip
            dip = self.sip
            sport = self.dport
            dport = self.sport
        if self.proto == 'tcp':
            if seq_no is None and dir == "to client":
                seq_no = self.current_seq_b_to_a
            elif seq_no is None and dir == "to server":
                seq_no = self.current_seq_a_to_b
            if ack_no is None and dir == "to client":
                ack_no = self.current_ack_b_to_a
            elif ack_no is None and dir == "to server":
                ack_no = self.current_ack_a_to_b

        # if we turn on tcp_overlap and we need
        # to shift the sequence number
        # and direction is to server
        # content is not None
        if self.tcp_overlap and self.shift_seq and \
           content is not None and dir=="to server":
            seq_no -= 1
            newContent = [48]
            newContent.extend(content.data)
            content = Content(newContent, len(content.data) + 1)

        pkt = Packet(self.proto, sip, dip, self.ip_type, sport, dport, flags,
                     seq_no, ack_no, self.mac_gen, self.mac_def_file, content)
        if self.proto == 'tcp' or self.proto == 'udp':
            pkt.transport_hdr.set_checksum(pkt.network_hdr.get_sip(),
                                           pkt.network_hdr.get_dip(),
                                           SUPPORTED_PROTOCOLS[self.proto],
                                           pkt.transport_hdr.get_size() +
                                           pkt.content.get_size(),
                                           pkt.content.get_data())
        return pkt

    def calculateIP(self, ip="", home=True):
        ip_generator = None
        if self.ip_type == 6:
            ip_generator = IPV6()
        else:
            ip_generator = IPV4()
        if (ip.lower() == 'any' or ip == '*'):
            return ip_generator.gen_ip(home)
        elif ip.find('/') > 0:
            ip = ip[:ip.find('/')]
            mynewip = ""
            splitter = '.'
            if self.ip_type == 6:
                splitter = ':'
            vals = ip.split(splitter)
            spcounter = 0
            while vals:
                v = vals.pop(0)
                if int(v) > 0:
                    if spcounter > 0:
                        mynewip += splitter
                    mynewip += v
                else:
                    break
                spcounter += 1
            return ip_generator.gen_ip(home, mynewip)
        elif ip.lower() == '$HOME_NET':
            return ip_generator.gen_ip(True)
        elif ip.lower() == '$EXTERNAL_NET':
            return ip_generator.gen_ip(False)
        elif ',' in ip:
            mychoices = ip.split(',')
            target = random.choice(mychoices)
            return ip_generator.gen_ip(home, target)
        elif '.' in ip and self.ip_type == 4:
            return ip_generator.gen_ip(True, ip)
        elif ':' in ip and self.ip_type == 6:
            return ip_generator.gen_ip(True, ip)
        else:
            return ip_generator.gen_ip(home)

    def createFragments(self, dir="to server", content=None, myfrags=1,
                        ttlexpiry=0):
        self.frag_id = random.randint(1, 65000)
        myoffset = 0
        myindex = 0
        mf = True
        whole_pkt = self.buildPkt(dir, ACK, content)
        data = whole_pkt.get_packet()
        frag_content = Content(data[34:], len(data[34:]), False, True)
        possible_frags = frag_content.get_size() / 8
        if not possible_frags.is_integer():
            possible_frags = int(possible_frags) + 1
        else:
            possible_frags = int(possible_frags)
        if myfrags > possible_frags:
            myfrags = possible_frags
        frag_size = int(possible_frags / myfrags)
        if frag_size <= 0:
            frag_size = 1
        for i in range(0, myfrags):
            myend = myindex + (frag_size * 8)
            if i == (myfrags - 1):
                myend = frag_content.get_size()
                mf = False
            self.last_off = myoffset

            self.fragments.append(
                (myoffset,
                 frag_content.get_fragment(myindex, myend),
                 False)
                )

            # if this is not the last fragment and ttlexpiry is nonzero
            if i != (myfrags - 1) and ttlexpiry != 0:
                self.fragments.append(
                    (myoffset,
                     ContentGenerator(None, myend - myindex)
                     .get_next_published_content(),
                     True)
                )

            myindex += (frag_size * 8)
            myoffset = int(myindex/8)

    def createNormalPacket(self, dir="to server", ack_only=False, myrule=None,
                           seq=None, ack=None):
        if myrule is None:
            myrule = self.rule
        pkt = None
        con = None
        if not ack_only:
            cg = ContentGenerator(myrule, self.pkt_len, self.rand,
                                  self.full_match, self.full_eval)
            con = cg.get_next_published_content()
            if self.full_eval:
                pkt = []
                while con:
                    pkt.append(self.buildPkt(dir, ACK, con))
                    con = cg.get_next_published_content()
                return pkt

        pkt = self.buildPkt(dir, ACK, con, seq, ack)
        return pkt

    def getNextContentPacket(self):
        pkt = None
        isMalicious = False
        # Handle complex rules such as fragments, out-of-order, etc.
        if self.myp:
            p = self.myp[0]
            if p.getDir() == "to server":
                self.ack_dir = "to client"
            else:
                self.ack_dir = "to server"
            if self.p_count == 0:
                self.p_count = p.getTimes()

            # Handle acked packets
            if self.next_is_ack:
                pkt = self.buildPkt(self.ack_dir, ACK)
                if self.advance_pkt:
                    self.p_count -= 1
                    self.advance_pkt = False
                self.next_is_ack = False

            elif p.getSplit() > 0:
                pkt = self.handleSplitPacket(p)

            # handle fragmented packets
            elif p.getFragment() > 0:
                pkt, isMalicious = self.handleFragPacket(p)

            # Out of order packet-level
            elif ((
                p.getOutOfOrder() or self.stream_ooo) and self.proto == 'tcp'
            ):
                pkt = self.handleOOOPacket(p)

            elif self.rule and self.rule.getPacketLoss() > 0:
                pkt = self.handleLostPacket(p)

            # Just a normal packet
            else:
                pkt = self.createNormalPacket(p.getDir(), False, p)
                if type(pkt) is list:
                    self.packets_in_stream = 0
                    self.header = 0
                    self.footer = 0
                else:
                        self.updateSequence(p.getDir(), pkt.content.get_size())
                        self.p_count -= 1

            # Update TTL value getting from the rule (ignored if 256)
            # only if that packet is not malicious
            # In other words, isMalicious is none or false
            if p.getTTL() != 256 and not isMalicious:
                pkt.set_ttl(p.getTTL())

            # If p_count is zero, then we have finished with this pkt rule.
            if self.p_count <= 0:
                self.packets_in_stream -= 1
                if len(self.myp) > 0:
                    self.myp.pop(0)
                if self.content_string is not None:
                    self.content_string = None

        # Handle basic and random rules here.
        else:
            if self.next_is_ack:
                if self.bi:
                    pkt = self.createNormalPacket("to client")
                    self.updateSequence("to client", pkt.content.get_size())
                else:
                    pkt = self.createNormalPacket("to client", True)
                self.next_is_ack = False
                self.packets_in_stream -= 1
            else:
                pkt = self.createNormalPacket("to server")
                if not self.full_eval:
                    self.updateSequence("to server", pkt.content.get_size())
                if self.flow_ack:
                    self.next_is_ack = True
                    self.advance_pkt = True
                else:
                    self.packets_in_stream -= 1
        return pkt

    def getNextHandshakePacket(self):
        pkt = None
        if self.header == 3:
            pkt = self.buildPkt("to server", SYN)
            self.updateSequence("to server", 1)
        elif self.header == 2:
            pkt = self.buildPkt("to client", SYN+ACK)
            self.updateSequence("to client", 1)
        elif self.header == 1:
            if self.myp is None or (self.myp and
               self.myp[0].getDir() == "to server"):
                pkt = self.getNextContentPacket()
            else:
                pkt = self.buildPkt("to server", ACK)
        self.header -= 1
        return pkt

    def getNextPacket(self):
        pkt = None
        if self.header > 0:
            pkt = self.getNextHandshakePacket()
            self.shift_seq = False
        elif self.packets_in_stream > 0:
            pkt = self.getNextContentPacket()
            if not self.shift_seq and self.tcp_overlap:
                self.shift_seq = True
        elif self.footer > 0:
            self.shift_seq = False
            pkt = self.getNextTeardownPacket()
        else:
            pass
            # Nothing left.
        if type(pkt) is not list:
            return [pkt]
        else:
            return pkt

    def getNextTeardownPacket(self):
        pkt = None
        if self.footer == 4:
            pkt = self.buildPkt("to server", FIN + ACK)
            self.updateSequence("to server", 1)
        elif self.footer == 3:
            pkt = self.buildPkt("to client", ACK)
        elif self.footer == 2:
            pkt = self.buildPkt("to client", FIN + ACK)
            self.updateSequence("to client", 1)
        elif self.footer == 1:
            pkt = self.buildPkt("to server", ACK)
        else:
            pass  # Finished, this stream should be done
        self.footer -= 1
        return pkt

    def getSynch(self):
        return self.synch

    def handleFragPacket(self, p=None):
        pkt = None

        if not self.fragments or len(self.fragments) <= 0:
            cg = ContentGenerator(p, self.pkt_len, self.rand,
                                  self.full_match, self.full_eval)
            mycontent = cg.get_next_published_content()
            self.frag_con_size = mycontent.get_size()
            self.createFragments(p.getDir(), mycontent, p.getFragment(),
                                 p.getTTLExpiry())

        # If a fragment is lost just consume the next frag.
        if self.rule and self.rule.getPacketLoss() > 0:
            pick = random.randint(0, 100)
            if pick < self.rule.getPacketLoss():
                off, frag, ttlexpi = self.fragments.pop(0)
                self.dropped = True

        if len(self.fragments) > 0:

            # out of order fragments
            if (self.stream_ooo or p.getOutOfOrder()) \
               and len(self.fragments) > 1:
                off, frag, ttlexpi = self.fragments.pop(
                    random.randint(0, len(self.fragments) - 1))
            else:
                off, frag, ttlexpi = self.fragments.pop(0)
            mf = True

            # check if this is last fragment and ttl expiry == 0
            if off == self.last_off and p.getTTLExpiry() == 0:
                mf = False

            pkt = self.buildFragPkt(p.getDir(), frag, off, mf)

            # If ttl_expiry is set, then change the ttl to match
            # the value that should expire prior to reaching the
            # destination.
            if ttlexpi:
                pkt.network_hdr.set_ttl(p.getTTLExpiry())
            if self.fragments is None or len(self.fragments) < 1:
                if not self.dropped:
                    self.updateSequence(p.getDir(), self.frag_con_size)
                    self.advance_pkt = True
                else:
                    self.dropped = False
                    self.frag_con_size = 0
                if self.flow_ack or p.ackThis():
                    self.next_is_ack = True
                else:
                    self.p_count -= 1
        return pkt, ttlexpi

    def handleLostPacket(self, p=None):
        pkt = None
        if self.lost_pkt_string is not None and self.proto == 'tcp':
            pick = random.randint(0, 100)
            if pick <= self.rule.getPacketLoss():
                pkt = self.buildPkt(p.getDir(), self.lost_pkt_string)
                self.lost_packet_string = None
                self.updateSequence(p.getDir(), pkt.content.get_size())
                if self.flow_ack or p.ackThis():
                    self.advance_pkt = True
        else:
            pick = random.randint(0, 100)
            if self.proto == 'tcp' and pick <= self.rule.getPacketLoss():
                cg = ContentGenerator(p, self.pkt_len, self.rand,
                                      self.full_match, self.full_eval)
                self.lost_packet_string = cg.get_next_published_content()
                seq = 0
                if p.getDir() == "to server":
                    seq = self.current_seq_a_to_b
                else:
                    seq = self.current_seq_b_to_a
                if self.p_count > 0:
                    seq += self.lost_packet_string.get_size()
                pkt = self.buildPkt(p.getDir(), ACK, self.lost_packet_string,
                                    seq)
                if self.p_count <= 0:
                    self.advance_pkt = True
                    self.updateSequence(p.getDir(), pkt.content.get_size())
                    self.lost_packet_string = None

            elif self.proto != 'tcp' and pick <= self.rule.getPacketLoss():
                self.p_count -= 1
                if self.p_count > 0:
                    pkt = self.getNextContentPacket()
            else:
                pkt = self.createNormalPacket(p.getDir(), False, p)
                self.updateSequence(p.getDir(), pkt.content.get_size())
                if self.flow_ack or p.ackThis():
                    self.advance_pkt = True
        if self.flow_ack or p.ackThis():
            self.next_is_ack = True
        else:
            self.p_count -= 1
        return pkt

    def handleOOOPacket(self, p=None):
        pkt = None
        max_window = 3
        if not self.flow_ack and not p.ackThis():
            max_window = self.p_count
        if self.content_string is None:
            cg = ContentGenerator(p, self.pkt_len, self.rand,
                                  self.full_match, self.full_eval)
            self.content_string = cg.get_next_published_content()
        if p.getDir() == "to server":
            seq = self.current_seq_a_to_b
        else:
            seq = self.current_seq_b_to_a
        self.window += 1
        if self.order is None:
            self.order = []
            self.order_sent = []
            temp = []
            for i in range(0, max_window):
                pick = random.randint(0, 100)
                if pick < self.rule.getOOOProb():
                    temp.append(i)
                else:
                    self.order.append(i)
            while temp:
                self.order.append(temp.pop(random.randint(0, len(temp) - 1)))
        next = self.order.pop(0)
        self.order_sent.append(next)
        seq += next * self.content_string.get_size()
        pkt = self.buildPkt(p.getDir(), ACK, self.content_string,
                            seq)
        if self.window >= max_window or ((self.p_count - self.window) <= 0
           and self.p_count > 1):
            pkts_acked = 0
            try:
                first = self.order_sent.index(0)
                index = 1
                pkts_acked = 1
                while (first + index) < len(self.order_sent):
                    if index == self.order_sent[(first + index)]:
                        pkts_acked += 1
                        index += 1
                    else:
                        break
            except ValueError:
                pass  # ooo does not contain first so dont worry
            self.order = None
            self.order_sent = None
            self.window = 0
            self.updateSequence(p.getDir(), pkts_acked *
                                self.content_string.get_size())
            if self.flow_ack or p.ackThis():
                self.next_is_ack = True
                if pkts_acked > 0:
                    self.advance_pkt = True
                if pkts_acked > 1:
                    self.p_count -= (pkts_acked - 1)
            else:
                self.p_count = 0
        elif self.p_count == 1:
            self.window = 0
            self.order = None
            self.updateSequence(p.getDir(), self.content_string.get_size())
            if self.flow_ack or p.ackThis():
                self.next_is_ack = True
                self.advance_pkt = True
            else:
                self.p_count -= 1
        return pkt

    def handleSplitPacket(self, p=None):
        pkt = None
        base_seq = self.current_seq_a_to_b
        if p.getDir() == "to client":
            base_seq = self.current_seq_b_to_a
        if not self.split or len(self.split) < 1:
            cg = ContentGenerator(p, self.pkt_len, self.rand,
                                  self.full_match, self.full_eval)
            cs = cg.get_next_published_content()
            mysplit = p.getSplit()
            if mysplit > cs.get_size():
                mysplit = cs.get_size()
            split_len = int(cs.get_size() / mysplit)
            temp_seq = 0
            index = 0
            for i in range(0, mysplit):
                splitp = None
                if i == mysplit - 1:
                    splitp = cs.get_fragment(index, cs.get_size())
                else:
                    splitp = cs.get_fragment(index, index+split_len)
                self.split.append(((base_seq + temp_seq), splitp))
                temp_seq += splitp.get_size()
                index += splitp.get_size()
        seq = 0
        next = None
        if (p.getOutOfOrder() or self.stream_ooo) and self.proto == 'tcp':
            pick = random.randint(0, 100)
            if pick < self.rule.getOOOProb() and len(self.split) > 1:
                seq, next = self.split.pop(1)
            else:
                seq, next = self.split.pop(0)
                self.updateSequence(p.getDir(), next.get_size())
            pkt = self. buildPkt(p.getDir(), ACK, next, seq)

        # Normal split packet
        else:
            seq, next = self.split.pop(0)
            pkt = self.buildPkt(p.getDir(), ACK, next)
            self.updateSequence(p.getDir(), next.get_size())

        if len(self.split) > 0:
            if self.flow_ack or p.ackThis():
                self.next_is_ack = True
        else:
            if self.flow_ack or p.ackThis():
                self.next_is_ack = True
                self.advance_pkt = True
            else:
                self.p_count -= 1
        return pkt

    def has_packets(self):
        if (self.header + self.packets_in_stream + self.footer) > 0:
            return True
        else:
            return False

    def isFinished(self):
        if not self.has_packets():
            return True
        else:
            return False

    def updateSequence(self, dir="to server", data_len=1):
        if self.tcp_overlap and self.shift_seq and \
           data_len > 0:
            data_len -= 1
        if self.proto == 'tcp':
            if dir == "to server":
                self.current_seq_a_to_b += data_len
                self.current_ack_b_to_a = self.current_seq_a_to_b
            else:
                self.current_seq_b_to_a += data_len
                self.current_ack_a_to_b = self.current_seq_b_to_a


class ScanAttack(TrafficStream):
    """
        Creates the traffic for a specific scanning attack.  Works the same as
        a normal traffic stream, only packets returned are part of a scan.
    """

    def __init__(self, rule=None, sconf=None):

        src_ip = None
        base_port = None
        self.scan_type = SYN_SCAN
        self.targets = None
        self.t_ports = None
        self.ip_type = 4
        self.proto = 'tcp'
        self.mac_gen = ETHERNET_HDR_GEN_RANDOM
        self.mac_def_file = None
        self.intensity = 5
        self.duration = 1
        self.last_sent = 0.0
        self.offset = 0.0
        self.reply_chance = OPEN_PORT_CHANCE
        self.num_packets = self.intensity * self.duration
        self.next_is_ack = False
        self.finish_handshake = False

        self.shift_seq = False
        self.tcp_overlap = False

        if sconf:
            self.scan_type = sconf.getScanType()
            self.t_ports = sconf.getTargetPorts()
            if sconf.getMacAddrDef():
                self.mac_gen = ETHERNET_HDR_GEN_DISTRIBUTION
                self.mac_def_file = sconf.getMacAddrDef()
            self.intensity = sconf.getIntensity()
            self.duration = sconf.getScanDuration()
            self.num_packets = self.intensity * self.duration

        if rule:
            base_port = rule.getBasePort()
            src_ip = rule.getSrcIp()
            self.scan_type = rule.getScanType()
            self.targets = rule.getTarget()
            if rule.getTargetPorts():
                self.t_ports = rule.getTargetPorts()
            if rule.getIntensity() != 5:
                self.intensity = rule.getIntensity()
            if rule.getDuration() != 1:
                self.duration = rule.getDuration()
            self.offset = rule.getOffset()
            self.reply_chance = rule.getReplyChance()
            self.num_packets = self.intensity * self.duration

        if not self.t_ports:
            self.t_ports = [str(random.randint(1, 65535))]

        if src_ip is None:
            self.sip = self.calculateIP('any', False)
        else:
            self.sip = self.calculateIP(src_ip, False)

        if self.targets is not None:
            self.dip = self.calculateIP(self.targets, False)
        else:
            self.sip = self.calculateIP('any', False)

        if base_port is None:
            self.sport = Port('any')
        else:
            self.sport = Port(base_port)

    def testTypeTS(self, value):
        if value == "ScanAttack":
            return True
        return False

    def get_duration(self):
        return self.duration

    def get_last_sent(self):
        return self.last_sent

    def getNextPacket(self):
        pkt = None
        if self.num_packets > 0:
            if self.next_is_ack:
                pkt = self.buildPkt("to client", SYN+ACK)
                self.updateSequence("to client", 1)
                self.next_is_ack = False
                if self.scan_type is SYN_SCAN:
                    self.num_packets -= 1
                if self.scan_type is CONNECTION_SCAN:
                    self.finish_handshake = True
            elif self.finish_handshake:
                pkt = self.buildPkt("to server", ACK)
                self.updateSequence("to server", 1)
                self.num_packets -= 1
                self.finish_handshake = False
            else:
                next_port = self.get_next_port(self.t_ports)
                pkt = self.scan_packet(self.dip, next_port, self.mac_gen,
                                       self.mac_def_file)
                pick = random.randint(0, 100)
                if pick <= self.reply_chance:
                    self.next_is_ack = True
                else:
                    self.num_packets -= 1
        return [pkt]

    def get_next_port(self, target_ports=None):
        next_port = 'any'
        if len(target_ports) > 1:
            next_port = target_ports.pop(0)
            target_ports.append(next_port)
        elif len(target_ports) == 1:
            next_port = target_ports.pop(0)
            next_port_int = int(next_port)
            next_port_int = (next_port_int+1) % 65536
            target_ports.append(str(next_port_int))
        else:
            print("nothing")
        return next_port

    def get_number_of_packets(self):
        return self.num_packets

    def get_offset(self):
        return self.offset

    def get_pkt_interval(self):
        return float((1/self.intensity) * 1000000)

    def has_packets(self):
        if self.num_packets > 0:
            return True
        else:
            return False

    def set_last_sent(self, last=0.0):
        self.last_sent = last

    def scan_packet(self, dip=None, dport=None,
                    mac_gen=ETHERNET_HDR_GEN_RANDOM, dist_file=None):
        if dip is None or dport is None:
            print("Can't get any work done!")
            return None
        self.dip = dip
        self.dport = dport
        self.current_seq_a_to_b = random.randint(0, 4000000000)
        self.current_ack_a_to_b = 0
        self.current_seq_b_to_a = random.randint(0, 4000000000)
        self.current_ack_b_to_a = 0
        pkt = self.buildPkt("to server", SYN)
        self.updateSequence("to server", 1)
        return pkt


class Packet(object):
    """
        Container and generator for packets.  Will build headers and content
        for a given packet.  Once built, use get_packet() to pullout the
        generated packet.
    """
    def __init__(self, proto='tcp', sip=None, dip=None,
                 ipv=4, sport=None, dport=None, flags=None, seq=0,
                 ack=0, mac_gen=ETHERNET_HDR_GEN_RANDOM,
                 dist_file=None, content=None, frag_id=0,
                 offset=0, mf=False, ttl=None):
        self.transport_hdr = None
        self.proto = proto
        if ipv == 6:
            self.network_hdr = IPV6(sip, dip, ttl)
        else:
            self.network_hdr = IPV4(sip, dip, ttl)
        self.datalink_hdr = EthernetFrame(self.network_hdr.get_sip(),
                                          self.network_hdr.get_dip(),
                                          mac_gen, dist_file, ipv)

        if content is not None:
            self.content = content
        else:
            self.content = Content(None, 0)
        if frag_id == 0:
            self.prepare_headers(proto, sport, dport, flags, seq, ack)
        else:
            self.network_hdr.set_frag(frag_id, offset, mf)
            self.network_hdr.set_length(self.network_hdr.get_size() +
                                        self.content.get_size())
            self.network_hdr.set_prototcol(SUPPORTED_PROTOCOLS[proto])

    def __str__(self):
        pkt_str = ''
        pkt = self.get_packet()
        for i in range(0, int(len(pkt) / 16) * 16, 16):
            pkt_str += '\t0x%04x' % i + ': '
            for j in range(i, i + 16, 2):
                pkt_str += ' %02x%02x' % (pkt[j], pkt[j+1])
            pkt_str += '\n'
        if len(pkt) % 16 > 0:
            pkt_str += '\t0x%04x' % (int(len(pkt) / 16) * 16) + ': '
            for j in range(int(len(pkt) / 16) * 16, int(len(pkt) / 2) * 2, 2):
                pkt_str += ' %02x%02x' % (pkt[j], pkt[j+1])
            if len(pkt) % 2 > 0:
                pkt_str += ' %02x' % pkt[-1]
            pkt_str += '\n'
        return pkt_str

    def get_content(self):
        return self.content

    def get_packet(self):
        packet = self.datalink_hdr.get_ethernet_header() + \
            self.network_hdr.get_ip_header()
        if self.transport_hdr:
            packet += self.transport_hdr.get_transport_header()
        if self.content and self.content.get_size() > 0:
            packet += self.content.get_data()
        return packet

    def get_size(self):
        size = self.network_hdr.get_size() + self.content.get_size() + \
            self.datalink_hdr.get_datalink_hdr_size()
        if self.transport_hdr:
            size += self.transport_hdr.get_size()
        return size

    def get_proto(self):
        return self.proto

    def get_src_ip(self):
        return self.network_hdr.get_sip()

    def get_dst_ip(self):
        return self.network_hdr.get_dip()

    def get_content_length(self):
        if self.content is not None:
            return self.content.get_size()
        else:
            return 0

    def get_ttl(self):
        return self.network_hdr.get_ttl()

    def prepare_headers(self, proto='tcp', sport=None, dport=None,
                        flags=0, seq=0, ack=0):
        if proto.lower() == 'icmp':
            self.transport_hdr = ICMP(1, 0)
            self.network_hdr.set_prototcol(SUPPORTED_PROTOCOLS['icmp'])
        elif proto.lower() == 'udp':
            self.transport_hdr = UDP(sport, dport)
            self.network_hdr.set_prototcol(SUPPORTED_PROTOCOLS['udp'])
            self.transport_hdr.set_length(self.transport_hdr.get_size() +
                                          self.content.get_size())
        else:
            self.transport_hdr = TCP(sport, dport)
            self.transport_hdr.set_flags(flags)
            self.set_seq_num(seq)
            self.set_ack_num(ack)
            self.network_hdr.set_prototcol(SUPPORTED_PROTOCOLS['tcp'])
        self.network_hdr.set_length(self.network_hdr.get_size() +
                                    self.transport_hdr.get_size() +
                                    self.content.get_size())

    def set_ack_num(self, ack=0):
        self.transport_hdr.set_ack_num(ack)

    def set_seq_num(self, seq=0):
        self.transport_hdr.set_seq_num(seq)

    def set_content(self, content=None):
        self.content = content

    def set_ttl(self, ttl):
        self.network_hdr.set_ttl(ttl)

    def get_seq_num(self):
        return self.transport_hdr.get_seq_num()

    def get_ack_num(self):
        return self.transport_hdr.get_ack_num()

    def get_data_len(self):
        return self.content

class Content(object):
    """
        Container for holding generated content.  Used so that the
        content can be manipulated to fit the constraints placed on
        it by the traffic stream.
    """
    def __init__(self, data=None, length=0, full_match=False, frag=False,
                 rand=False):
        self.length = length
        self.full_match = full_match
        self.frag = frag
        self.rand = rand
        self.data = []
        if data:
            self.set_data(data)

    def __str__(self):
        data_str = '-'.join(['%02x' % byte for byte in self.data])
        return data_str

    def get_data(self):
        if self.data and self.length > 0:
            pack_string = "!" + str(self.length) + "s"
            packed_data = struct.pack(pack_string, bytearray(self.data))
            return packed_data
        else:
            return None

    def get_fragment(self, start=0, end=1):
        if start >= 0 and end <= self.length and start < end:
            myfrag = Content(self.data[start:end], end-start, False, True)
            return myfrag
        return None

    def get_size(self):
        return self.length

    def adjust_length(self):
        if self.length > 0 and not self.frag:
            # If we aren't full matching, then clip the last char from
            # the match string as that should prevent a match but still
            # cause a lot of burden.

            if not self.rand and not self.full_match and len(self.data) > 2:
                self.data = self.data[0:-1]

            if len(self.data) > self.length:
                self.data = self.data[0:self.length]
            if self.length > len(self.data):
                temp_data = []
                if self.full_match and len(self.data) > 1:
                    remainder = self.length - len(self.data)
                    data_len = len(self.data)
                    while remainder > 0:
                        if int(data_len/2) > remainder:
                            temp_data.extend(self.data[0:remainder])
                            remainder = 0
                        else:
                            temp_data.extend(self.data[0:int(data_len/2)])
                            remainder = remainder - int(data_len/2)
                    temp_data.extend(self.data)
                else:
                    cgen = ContentGenerator(None, self.length - len(self.data),
                                            True)
                    temp_data.extend(self.data)
                    temp_data.extend(
                        cgen.get_next_published_content().get_data())
                self.data = temp_data

    def set_data(self, data=None):
        self.data = data
        if self.length > 0:
            self.adjust_length()

    def set_length(self, length):
        self.length = length
        self.adjust_length


class ContentGenerator:
    """
        Class for generating content.  Will build content derived from a rule,
        if provided, or generate completely random content if no rule is
        provided.  If a length is provided, will return content to fit that
        length.  If full_match is not set to true, it will clip content
        generated from a rule so that it should not match the rule.
    """
    def __init__(self, rule=None, length=-1, rand=False, full_match=False,
                 full_eval=False):
        self.published = []
        self.index = 0
        if rand or rule is None:
            if length < 0:
                length = random.randint(0, 1400)+10
            self.published.append(Content(self.generate_random_data(length),
                                          length, False, False))
        elif full_eval:
            self.generate_full_eval(rule)
        else:
            generated = self.generate_nfa_data(rule)
            if length < 0:
                if rule and rule.getLength() > 0:
                    length = rule.getLength()
                else:
                    length = len(generated)
            self.published.append(
                Content(generated, length, full_match, False))

    def __str__(self):
        cg_str = ""
        for content in self.published:
            cg_str += str(content)
            cg_str += "\n"
        return cg_str

    def get_number_of_published_content(self):
        return len(self.published)

    def get_next_published_content(self):
        if self.published:
            return self.published.pop(0)
        else:
            return None

    def get_transitions(self, state=None):
        tran_map = {}
        if state is None:
            return tran_map
        for sym in range(0, NSYMBOLS + 1):
            for next_state in state.tx[sym]:
                if next_state in tran_map:
                    if sym not in tran_map[next_state]:
                        tran_map[next_state].append(sym)
                else:
                    tran_map[next_state] = [sym]
        return tran_map

    """
        This function will recursively enumerate a regular expression and
        create a packet for each enumeration.  The enumeration should cover
        all branches within the nfa generated from the regular expression.
        However, it will not exhaustively enumerate all possibilities.
        The only guarantee (loose use of the word) is that each branch
        will be followed at least once.  The purpose of this function
        is to create test packets that will examine all possible paths
        for a regular expression.  This allows verification
        of zero false negatives.
    """
    def follow_all_branches(self, nfa=None, state=None, path=[], visited=[],
                            self_visit=[]):

        new_visited = visited[:]
        new_path = path[:]
        while state is not None and state != nfa.accept:
            t_map = self.get_transitions(state)
            if state not in new_visited:
                new_visited.append(state)
            t_count = len(t_map)
            if t_count == 0:
                break
            for t in t_map:
                t_count -= 1
                possible = t_map[t]
                tx = E
                if len(possible) > 1:
                    tx = possible[random.randint(0, len(possible)-1)]
                elif len(possible) == 1:
                    tx = possible[0]
                if len(t_map) > 1:
                    if t == state:
                        if t != nfa.accept and t not in self_visit:
                            self_visit.append(t)
                            self.follow_all_branches(nfa, t,
                                                     new_path if tx == E
                                                     else new_path + [tx],
                                                     new_visited, self_visit)
                    else:
                        if t == nfa.accept:
                            state = t
                            break
                        if t not in new_visited:
                            self.follow_all_branches(nfa, t,
                                                     new_path if tx == E
                                                     else new_path + [tx],
                                                     new_visited, self_visit)
                    if t_count == 0:
                        state = None
                else:
                    if t != state and t not in new_visited:
                        if tx != E:
                            new_path.append(tx)
                        state = t
                    else:
                        state = None
            if state == nfa.accept:
                if len(new_path) > 0:
                    self.published.append(Content(new_path, len(new_path),
                                                  True, False))
                state = None

    def generate_random_data(self, length=0):
        i = 0
        data = []
        while i < length:
            data.append(random.randint(0, 255))
            i += 1
        return data

    def generate_full_eval(self, rule=None):
        if rule:
            content_options = rule.getContent()
            for con in content_options:
                if con.getType() == 'pcre':
                    nfa = pcre2nfa(con.getContentString(), True)
                    nfa.calculate_depth()
                    path = []
                    self.follow_all_branches(nfa, nfa.start, path)

    def generate_nfa_data(self, rule=None):
        if rule:
            data = []
            http_content = []
            content_options = rule.getContent()
            for con in content_options:
                generated = []
                if con.getName() == 'Snort Rule Content' and \
                   con.isHTTP():
                    http_content.append(con)
                else:
                    if con.getType() == 'content':
                        generated = self.generate_from_content_strings(
                            con.getContentString())
                    elif con.getType() == 'pcre':
                        generated = self.generate_from_regex(
                            con.getContentString())
                        if len(generated) < 1:
                            print(
                                "did not generate from: ",
                                con.getContentString())
                            sys.exit(0)
                    else:
                        print("Cannot generate NFA Data from: ", con)
                        print("\n")

                if generated:
                    inter_char = 0
                    if con.getName() == 'Snort Rule Content':
                        # handle tag modifiers like depth, within, etc.
                        if con.getDepth() is not None:
                            inter_char = int(con.getDepth())
                        if con.getDistance() is not None:
                            inter_char = int(con.getDistance())
                        if con.getOffset() is not None:
                            if len(data) > 0:
                                if con.getOffset() > (
                                   len(data) + len(generated)):
                                    inter_char = int(
                                        int(con.getOffset()) -
                                        (len(data) + len(generated))
                                    )
                            else:
                                inter_char = int(con.getOffset())
                    while (inter_char > 0):
                        data.append(random.randint(0, 255))
                        inter_char -= 1
                    while generated:
                        data.append(generated.pop(0))
            if http_content:
                http_con = self.generate_http_content(http_content)
                http_con.extend(data)
                data = http_con
            return data

    def generate_http_content(self, rules):
        http_directive_map = {}
        # HTTP/1.1
        http_text = [72, 84, 84, 80, 47, 49, 46, 49]
        # GET
        http_method = [71, 69, 84]
        # /
        http_uri = [47]
        # Content-type: text-html
        http_header = [99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112,
                       101, 58, 32, 116, 101, 120, 116, 45, 104, 116, 109,
                       108]
        # Cookie:
        http_cookie = []
        # Stat Code:
        http_stat_code = []
        # Stat Msg:
        http_stat_msg = []
        http_body = []
        generated = []
        cr_lf = [13, 10]
        space = [32]
        for rule in rules:
            if rule.getName() == 'Snort Rule Content':
                if rule.getHttpMethod():
                    if rule.getType() == 'content':
                        http_method = self.generate_from_content_strings(
                            rule.getContentString()
                        )
                    else:
                        http_method = self.generate_from_regex(
                            rule.getContentString())
                elif rule.getHttpStatCode():
                    if rule.getType() == 'content':
                        http_stat_code = self.generate_from_content_strings(
                            rule.getContentString()
                        )
                    else:
                        http_stat_code = self.generate_from_regex(
                            rule.getContentString())
                elif rule.getHttpStatMsg():
                    if rule.getType() == 'content':
                        http_stat_msg = self.generate_from_content_strings(
                            rule.getContentString()
                        )
                    else:
                        http_stat_msg = self.generate_from_regex(
                            rule.getContentString())
                elif rule.getHttpUri() or rule.getHttpRawUri():
                    if rule.getType() == 'content':
                        http_uri = self.generate_from_content_strings(
                            rule.getContentString()
                        )
                    else:
                        http_uri = self.generate_from_regex(
                            rule.getContentString())
                elif rule.getHttpCookie() or rule.getHttpRawCookie():
                    if rule.getType() == 'content':
                        http_cookie = self.generate_from_content_strings(
                            rule.getContentString()
                        )
                    else:
                        http_cookie = self.generate_from_regex(
                            rule.getContentString())
                elif rule.getHttpHeader() or rule.getHttpRawHeader():
                    if rule.getType() == 'content':
                        http_header = self.generate_from_content_strings(
                            rule.getContentString()
                        )
                    else:
                        http_header = self.generate_from_regex(
                            rule.getContentString())
                elif rule.getHttpClientBody():
                    body = ""
                    if rule.getType() == 'content':
                        body = self.generate_from_content_strings(
                            rule.getContentString()
                        )
                    else:
                        body = self.generate_from_regex(
                            rule.getContentString())
                    if http_body is None:
                        http_body = body
                    else:
                        http_body += body

        request_line = []
        request_line.extend(http_method)
        request_line.extend(space)
        request_line.extend(http_uri)
        request_line.extend(space)
        request_line.extend(http_text)

        if http_stat_code:
            request_line.extend(space)
            request_line.extend(http_stat_code)

        if http_stat_msg:
            request_line.extend(space)
            request_line.extend(http_stat_msg)

        request_line.extend(cr_lf)

        for c in request_line:
            generated.append(c)

        if http_cookie:
            http_header.extend(cr_lf)
            http_header.extend(http_cookie)

        http_header.extend(cr_lf)
        http_header.extend(cr_lf)
        for c in http_header:
            generated.append(c)

        if http_body:
            for c in http_body:
                generated.append(c)

        return generated

    """
      This Function will build an NFA of a given regular expression.
      It will then take a random walk of said NFA building a string
      as it goes.  When it reaches the final state, it will return
      the string that was built.  Thus, said string should match to
      the regular expression.  Note, there is a problem if multiple
      NFA with anchors are used together.  Essentially, this
      works with any single regular expression, but may fail with
      compound regular expressions especially if those regex contain
      the ^ anchor.
    """
    def generate_from_regex(self, pcre=None):
        generated = []
        if pcre:
            nfa = pcre2nfa(pcre, True)
            nfa.calculate_depth()
            state = nfa.start
            visited = []
            while state != nfa.accept:
                visited.append(state)
                possible_symbols = []
                depth = state.get_depth()
                next_states = []
                for sym in range(0, NSYMBOLS):
                    for next_state in state.tx[sym]:
                        if next_state == nfa.accept:
                            generated.append(sym)
                            next_states = [next_state]
                            break
                        if next_state != state and sym not in possible_symbols:
                            possible_symbols.append(sym)
                if possible_symbols and not next_states:
                    searching = True
                    while searching and len(possible_symbols) > 0:
                        next_symbol = possible_symbols.pop(
                            random.randint(0, len(possible_symbols)-1))
                        for next_state in state.tx[next_symbol]:
                            if next_state != state and \
                               next_state not in visited:
                                next_states.append(next_state)
                                generated.append(next_symbol)
                                searching = False
                else:
                    for next_state in state.tx[E]:
                        if next_state == nfa.accept:
                            next_states = [next_state]
                            break
                        if next_state != state and next_state not in visited:
                            next_states.append(next_state)

                if next_states:
                    state = next_states.pop(random.randrange(len(next_states)))

                # something broke--just bail for now.
                else:
                    break
        if len(generated) < 1:
            for i in range(0, 10):
                generated = self.generate_from_regex(pcre)
                if len(generated) > 0:
                    break
        if len(generated) < 1:
            print("No content generated!")
        return generated

    """
        Assumes Snort content tags.
    """
    def generate_from_content_strings(self, content_string=None):
        if content_string:
            generated = []
            i = 0
            hex = False
            while i < len(content_string):
                if content_string[i] == '|':
                    hex = not hex
                    i += 1
                if hex:
                    if content_string[i] == ' ':
                        i += 1
                    if content_string[i] == '|':
                        hex = not hex
                        i += 1
                        continue
                    num = content_string[i:i+2]
                    generated.append(int(num, 16))
                    i += 1
                else:
                    if i < len(content_string):
                        generated.append(ord(content_string[i]))
                i += 1
            return generated

    def test_for_http(self, list=None):
        if list:
            for item in list:
                if item.lower() in HTTP_CONTENT:
                    return True
        return False


class EthernetFrame:
    """Defines the methods for creating randomized ethernet headers.  All
    Ethernet headers are mapped to distinct IP addressses and stored
    in a global data structure accessible to all EthernetFrame
    objects.  There are two methods of Ethernet address creation:
    Random, or by distribution.  The random method randomly selects a
    vendor OUI from the OUI list "vendor_mac_list.dat".  The first
    three bytes are taken from the MAC OUI list, and the remaining
    bytes are randomly determined.  Obviously, if the OUI list is
    missing, this will fail.  You may edit the OUI list to produce
    different results.  However, rather than that, providing a
    mac_definition_file and generating by distribution is a better
    idea.

        The MAC definition file defines the MAC prefixes and the probability
        to use them.  For example:
            0x00 0x80 0x12 = 10
        Would designate using 008012 as the first three bytes of 10% of all
        MAC addresses generated (assuming a domain of 100).  It is possible to
        fix up to all six bytes in the MAC address.  Any bytes not fixed will
        be random generated.  Further, it is possible to use a domain larger
        than 100 (1000 for example) or smaller.  Just note that the prefix = n
        will set a probability for that prefix of n/domain.  If you do set a
        domain it should be the first value set in the file.  Finally,
        prefixes can be writen as hex values, or just a straight string
        (like 008012).  However, they cannot be written as string values
        separated by spaces (i.e. 00 80 12).  If spaces are used, hex notation
        must also be used (i.e. 0x00 0x80 0x12).  Please look at the
        vendor_mac_definition.txt for an example.
    """

    def __init__(self, sip=None, dip=None, type=ETHERNET_HDR_GEN_RANDOM,
                 dist_file=None, ipv=4):
        self.d_mac = []
        self.s_mac = []

        if ipv == 6:
            self.e_type = 0x86dd
        else:
            self.e_type = 0x0800

        if type == ETHERNET_HDR_GEN_DISTRIBUTION and dist_file is not None:
            self.gen_mac_addr_from_distribution(sip, dip, dist_file)
        elif type == ETHERNET_HDR_GEN_RANDOM:
            self.gen_random_mac_addrs(sip, dip)
        else:
            pass

    def __str__(self):
        e_header = self.d_mac + self.s_mac + [((self.e_type &
                                                0xff00) >> 8),
                                              (self.e_type & 0xff)]
        e_header_str = '-'.join(['%02x' % octet for octet in e_header])
        return e_header_str

    def clear_globals(self):
        global MAC_IP_MAP
        global VENDOR_MAC_DIST_DOMAIN
        global VENDOR_MAC_DIST
        MAC_IP_MAP = dict()
        VENDOR_MAC_DIST_DOMAIN = {}
        VENDOR_MAC_DIST = {}

    def create_vendor_mac_dist(self, src=None, dest=None):
        global VENDOR_MAC_DIST_DOMAIN
        global VENDOR_MAC_DIST

        origins = ['src', 'dest']
        for origin in origins:
            if origin == 'src':
                path = src
            elif origin == 'dest':
                path = dest
            if path is not None:
                try:
                    fd = open(path, 'r')
                except:
                    print("Could not open mac definition file: ", path)
                    sys.exit(1)

                VENDOR_MAC_DIST[origin] = {}

                line = fd.readline()
                base_prob = 0
                while line:
                    line = line.strip()
                    if len(line) > 1 and line.find('#') < 0:
                        prefix = line.partition('=')[0].strip().lower()
                        percent = line.partition('=')[2].strip().lower()
                        if prefix == 'domain':
                            VENDOR_MAC_DIST_DOMAIN[origin] = int(percent)
                        else:
                            octets = []

                            # Differentiate between handling hex
                            # or raw digit notation
                            if prefix.find('0x') > -1:
                                str_octets = prefix.split('0x')
                                for o in str_octets:
                                    if o:
                                        octets.append(int(o, 16))
                            else:
                                i = 0
                                while i < len(prefix):
                                    octets.append(int(prefix[i:i+2], 16))
                                    i += 2
                            VENDOR_MAC_DIST[origin][base_prob] = octets
                            base_prob += int(percent)
                            if VENDOR_MAC_DIST_DOMAIN[origin] and \
                               base_prob > VENDOR_MAC_DIST_DOMAIN[origin]:
                                break
                    line = fd.readline()

    def gen_mac_addr_from_distribution(self, sip=None, dip=None,
                                       dist_file=None):

        global VENDOR_MAC_DIST

        if not VENDOR_MAC_DIST:
            paths = dist_file.split(":")
            lenPaths = len(paths)
            source = None
            dest = None
            if lenPaths == 1:
                source = dest = paths[0]
            elif lenPaths == 2:
                if paths[0] != "?" and paths[1] != "?":
                    source = paths[0]
                    dest = paths[1]
                elif paths[0] != "?":
                    source = paths[0]
                elif paths[1] != "?":
                    dest = paths[1]
            else:
                print("Invalid format for mac distribution file: " + dist_file)
                sys.exit(0)

            self.create_vendor_mac_dist(source, dest)

        if 'src' in VENDOR_MAC_DIST and 'dest' in VENDOR_MAC_DIST:
            option = -1
        elif 'src' in VENDOR_MAC_DIST:
            option = 2
        elif 'dest' in VENDOR_MAC_DIST:
            option = 1
        else:
            option = 0

        if option in [0, 1, 2]:
            self.gen_random_mac_addrs(sip, dip, option)

        self.test_mac_addr_exists(sip, dip)
        if not self.s_mac:
            self.s_mac = self.get_random_octets(self.get_dist_mac_oui('src'))
            self.map_mac_addr_to_ip(self.s_mac, sip)
        if not self.d_mac:
            self.d_mac = self.get_random_octets(self.get_dist_mac_oui('dest'))
            self.map_mac_addr_to_ip(self.d_mac, dip)

    def gen_random_mac_addrs(self, sip=None, dip=None, option=0):

        # option 0: change both s_mac and d_mac
        # option 1: change s_mac only
        # option 2: change d_mac only

        global VENDOR_MAC_OUI
        self.test_mac_addr_exists(sip, dip)
        if not self.s_mac and (option == 0 or option == 1):
            self.s_mac = \
                self.get_random_octets(random.choice(VENDOR_MAC_OUI))
            self.map_mac_addr_to_ip(self.s_mac, sip)

        if not self.d_mac and (option == 0 or option == 2):
            self.d_mac = self.get_random_octets(random.choice(VENDOR_MAC_OUI))
            self.map_mac_addr_to_ip(self.d_mac, dip)

    def get_d_mac(self):
        return self.d_mac

    def get_dist_mac_oui(self, origin):
        dist_map = VENDOR_MAC_DIST[origin].keys()
        pick = random.randint(1, VENDOR_MAC_DIST_DOMAIN[origin])
        prefix = []
        last_key = 0

        for i in dist_map:
            if i > pick:
                prefix = VENDOR_MAC_DIST[origin][last_key]
                break
            elif i == pick:
                prefix = VENDOR_MAC_DIST[origin][i]
                break
            else:
                last_key = i

        if not prefix:
            prefix = VENDOR_MAC_DIST[origin][last_key]
        return prefix

    def get_datalink_hdr_size(self):
        return len(self.get_ethernet_header())

    def get_ethernet_header(self):
        """
            This marks the primary function for returning a packed binary
            string representing the Ethernet Header portion of a packet.
        """
        e_header = struct.pack('!6s6sH', bytearray(self.d_mac),
                               bytearray(self.s_mac), self.e_type)
        return e_header

    def get_ether_type(self):
        return self.e_type

    def get_s_mac(self):
        return self.s_mac

    def get_random_octets(self, prefix):
        random_octets = list(prefix)
        start = len(random_octets)
        for o in range(start, 6):
            random_octets.append(random.randint(0, 255))
        return random_octets

    def map_mac_addr_to_ip(self, mac, ip=None):
        global MAC_IP_MAP
        if ip is None:
            print("IP Address is None! Cannot be mapped!")
            return
        if mac is None:
            print("MAC address is None! Cannot be mapped!")
            return
        MAC_IP_MAP[ip] = mac

    def test_mac_addr_exists(self, sip=None, dip=None):
        global MAC_IP_MAP
        if sip is not None:
            if sip in MAC_IP_MAP:
                self.s_mac = MAC_IP_MAP[sip]
        if dip is not None:
            if dip in MAC_IP_MAP:
                self.d_mac = MAC_IP_MAP[dip]


class IP(object):
    """
        Base class for generating IP headers.  Should not be instantiated.
        Provides the shared functionality for IP headers.
    """
    def __init__(self, sip=None, dip=None, ttl=None):
        home_or_not = False
        if random.randint(1, 100) > 60:
            home_or_not = not home_or_not
        if not sip:
            home_or_not = not home_or_not
            self.sip = self.gen_ip(home_or_not)
        else:
            self.sip = sip
        if not dip:
            home_or_not = not home_or_not
            self.dip = self.gen_ip(home_or_not)
        else:
            self.dip = dip
        if not ttl:
            self.ttl = int(random.normalvariate(45, 7))
        else:
            self.ttl = ttl
        self.protocol = 0x00
        self.length = 0x0000
        self.size = 20

    def __str__(self):
        bytes = bytearray(self.get_ip_header())
        ip_hdr_str = '-'.join(['%02x' % byte for byte in bytes])
        return ip_hdr_str

    def clear_hope_ip_prefixes(self):
        global HOME_IP_PREFIXES
        HOME_IP_PREFIXES = []

    def gen_ip(self, home=False, target=None):
        return None

    def get_ip_header(self):
        return None

    def get_ip_header_fields(self):
        return None

    def get_sip(self):
        return self.sip

    def get_dip(self):
        return self.dip

    def get_protocol(self):
        return self.protocol

    def get_version(self):
        return None

    def get_ttl(self):
        return self.ttl

    def set_prototcol(self, protocol=0):
        if protocol == 0:
            print("Cannot set the protocol to zero")
            return
        if protocol not in SUPPORTED_PROTOCOLS.keys() and protocol not \
           in SUPPORTED_PROTOCOLS.values():
            print("Unsupported Protocol")
        self.protocol = protocol

    def set_length(self, length):
        if length < 0:
            print("Incorrect length")
        self.length = length

    def set_home_ip_prefixes(self, ip_prefixes):
        global HOME_IP_PREFIXES
        if not ip_prefixes:
            return
        for prefix in ip_prefixes:
            HOME_IP_PREFIXES.append(prefix)
        self.home_or_not = True

    def get_size(self):
        return self.size

    def set_ttl(self, ttl):
        self.ttl = ttl


class IPV4(IP):
    """
        Build a basic IPv4 header.  If no IP address is provided, will
        randomly generate the IP addresses.  This assumes the
        HOME_IP_PREFIXES data structure contains IP prefixes definining
        the protected network.

        NOTE: currently no effort is made to ensure external addresses do
        not match home addresses.
    """
    def __init__(self, sip=None, dip=None, ttl=None):
        super().__init__(sip, dip, ttl)
        self.vhl = 0x45
        self.tos = 0x00
        self.id = 0x0000
        self.frag = 0x0000
        self.checksum = 0x0000
        self.size = 20

    def calculate_checksum(self):
        sip = socket.inet_pton(socket.AF_INET, self.sip)
        dip = socket.inet_pton(socket.AF_INET, self.dip)
        self.checksum = 0
        ip_hdr_bin = struct.pack('!BBHHHBBH4s4s', self.vhl, self.tos,
                                 self.length, self.id, self.frag, self.ttl,
                                 self.protocol, self.checksum, sip, dip)
        bytes = bytearray(ip_hdr_bin)
        sum = 0
        count = 0
        for b in bytes:
            if count == 0:
                sum += b << 8
            else:
                sum += b
            count = (count + 1) % 2

        while sum >> 16:
            sum = (sum & 0xffff) + (sum >> 16)
        sum = (sum ^ 0xffff)
        self.checksum = sum

    def gen_ip(self, home=False, target=None):
        myip = []
        start = 0
        if home and (HOME_IP_PREFIXES or target):
            prefix = ""
            if target is not None:
                prefix = target
            else:
                prefix = random.choice(HOME_IP_PREFIXES)
            bytes = prefix.split('.')
            for b in bytes:
                if b:
                    myip.append(int(b))
            start = len(myip)
        for i in range(start, 4):
            myip.append(random.randint(0, 255))
        return '.'.join(['%d' % byte for byte in myip])

    def get_ip_header(self):
        self.calculate_checksum()
        sip = socket.inet_pton(socket.AF_INET, self.sip)
        dip = socket.inet_pton(socket.AF_INET, self.dip)
        ip_hdr_bin = struct.pack('!BBHHHBBH4s4s', self.vhl, self.tos,
                                 self.length, self.id, self.frag, self.ttl,
                                 self.protocol, self.checksum, sip, dip)
        return ip_hdr_bin

    def get_version(self):
        return 4

    def get_frag_id(self):
        return self.id

    def get_frag_offset(self):
        return self.frag

    def set_frag(self, id=0, offset=0, more_frags=False):
        self.id = id
        self.frag = offset
        if more_frags:
            self.frag += MORE_FRAGMENTS


class IPV6(IP):
    """
        Class for IPv6 addresses.  Similar in all practical respects to
        IPV4, but creates an IPV6 header instead.  Also assumes the existence
        of HOME_IP_PREFIXESv6 if distinction between home and external networks
        is to be maintained.
    """
    def __init__(self, sip=None, dip=None, ttl=None):
        super().__init__(sip, dip, ttl)
        self.vtc = 0x6000
        self.flow_label = 0
        self.length = 0
        self.protocol = 0
        self.size = 40

    def gen_ip(self, home=False, target=None):
        myip = [0x2001, random.randint(0x0000, 0x01F8) + 0x400]
        start = 2
        if home and (HOME_IP_PREFIXESv6 or target):
            prefix = []
            myip = []
            start = 0
            if target is not None:
                prefix = target
            else:
                prefix = random.choice(HOME_IP_PREFIXESv6)
            bytes = prefix.split(':')
            for b in bytes:
                if b:
                    myip.append(int(b, 16))
            start = len(myip)
        for i in range(start, 8):
            myip.append(random.randint(0, 65535))
        return ':'.join(['%04x' % byte for byte in myip])

    def get_ip_header(self):
        sip = socket.inet_pton(socket.AF_INET6, self.sip)
        dip = socket.inet_pton(socket.AF_INET6, self.dip)
        ip_hdr_bin = struct.pack('!HHHBB16s16s', self.vtc,
                                 self.flow_label, self.length,
                                 self.protocol, self.ttl, sip, dip)
        return ip_hdr_bin

    def get_version(self):
        return 6


class Port:
    """
        Container and Generator for port values.  Will take a Snort
        port value listing, parse it, and randomly select a potential
        option.  Call get_port_value() to get the port value chosen.
        If the constructor is called with no value, will randomly choose
        a port using the 'any' category.
    """
    def __init__(self, snort_port_val=None):
        if snort_port_val is None:
            snort_port_val = 'any'
        snort_port_val = snort_port_val.strip()

        # Strip away brackets
        if snort_port_val[0] == '[':
            snort_port_val = snort_port_val[1:-1]

        # Contains a list
        if snort_port_val.find(',') > -1:
            self.process_list(snort_port_val)
        else:
            self.process_port_val(snort_port_val)

    def __str__(self):
        return str(self.get_port_value())

    def get_port_value(self):
        return self.port_value

    def process_list(self, list):

        values = list.split(',')
        chosen_value = random.choice(values)
        self.process_port_val(chosen_value)

    def process_port_val(self, port_val=None):
        if port_val.find(":") >= 0:
            range = port_val.partition(":")
            if range[0]:
                start = int(range[0])
            else:
                start = 0
            if range[2] and int(range[2]) > start:
                end = int(range[2])
            else:
                end = 65535
            chosen = random.randint(0, end-start)
            self.port_value = chosen + start
        elif port_val.lower().find("http") >= 0:
            self.port_value = random.choice(HTTP_PORTS)
        elif port_val.lower().find("ftp") >= 0:
            self.port_value = random.choice(FTP_PORTS)
        elif port_val.lower().find("mail") >= 0:
            self.port_value = random.choice(MAIL_PORTS)
        elif port_val.lower().find("pop") >= 0:
            self.port_value = random.choice(POP_PORTS)
        elif port_val.lower().find("smb") >= 0:
            self.port_value = random.choice(SMB_PORTS)
        elif port_val.lower().find("nbt") >= 0:
            self.port_value = random.choice(NBT_PORTS)
        elif port_val.lower().find("nntp") >= 0:
            self.port_value = random.choice(NNTP_PORTS)
        elif port_val.lower().find("dns") >= 0:
            self.port_value = random.choice(DNS_PORTS)
        elif port_val.lower().find("file") >= 0:
            self.port_value = random.choice(FILE_PORTS)
        elif port_val.lower().find("oracle") >= 0:
            self.port_value = random.choice(ORACLE_PORTS)
        elif port_val.lower().find("any") >= 0:
            self.port_value = random.randint(0, 65535)
        elif port_val.isdigit():
            self.port_value = int(port_val)
        else:
            print("unknown port value: ", port_val, " returning random value.")
            self.port_value = random.randint(0, 65535)


class TransportLayer(object):
    """
        Base class for transport layer objects.  Defaults transport layer
        objects to TCP.
    """
    def __init__(self, proto=None, sport=None, dport=None):
        if proto is None:
            proto = 'tcp'
        self.proto = proto
        if sport and type(sport) == Port:
            self.sport = sport
        elif sport and type(sport) != Port:
            self.sport = Port(sport)
        else:
            pass
        if dport and type(dport) == Port:
            self.dport = dport
        elif dport and type(dport) != Port:
            self.dport = Port(dport)
        else:
            pass

    def __str__(self):
        bytes = bytearray(self.get_transport_header())
        transport_hdr_str = '-'.join(['%02x' % byte for byte in bytes])
        return transport_hdr_str

    def get_checksum(self):
        return self.checksum

    def get_transport_header(self):
        pass

    def get_size(self):
        return self.size

    def get_proto(self):
        return self.proto

    def set_checksum(self, sip=None, dip=None, proto=None, length=0,
                     data=None):
        self.checksum = 0
        hdr = None

        # build pseudo header
        if sip and dip:
            if sip.find(":") >= 0:
                sip = socket.inet_pton(socket.AF_INET6, sip)
                dip = socket.inet_pton(socket.AF_INET6, dip)
                hdr = struct.pack('!16s16sHH', sip, dip, proto, length)
            else:
                sip = socket.inet_pton(socket.AF_INET, sip)
                dip = socket.inet_pton(socket.AF_INET, dip)
                hdr = struct.pack('!4s4sHH', sip, dip, proto, length)
        else:
            print("Missing IP address in transport pseudo header.")
        hdr += self.get_transport_header()
        if data:
            hdr += data
        bytes = bytearray(hdr)
        sum = 0
        count = 0
        for b in bytes:
            if count == 0:
                sum += b << 8
            else:
                sum += b
            count = (count + 1) % 2
        while sum >> 16:
            sum = (sum & 0xffff) + (sum >> 16)
        sum = (sum ^ 0xffff)
        self.checksum = sum

    def set_src_port(self, sport):
        self.sport = Port(sport)

    def set_dst_port(self, dport):
        self.dport = Port(dport)


class ICMP(TransportLayer):

    def __init__(self, type, code=None):
        self.proto = "icmp"
        self.type = int(type)
        if code:
            self.code = int(code)
        else:
            self.code = 1
        self.checksum = 0
        self.size = 4

    def get_transport_header(self):
        icmp_bin = struct.pack('!BBH', self.type, self.code,
                               self.checksum)
        return icmp_bin


class TCP(TransportLayer):

    def __init__(self, sport=None, dport=None, seq=None, ack=None):
        super().__init__("tcp", sport, dport)
        self.ack = ack
        self.seq = seq
        if self.seq is None:
            self.seq = random.randint(0, 4000000000)
        if self.ack is None:
            self.ack = 0
        self.offset = 5
        self.flags = 0
        self.window = 65000
        self.urg = 0
        self.checksum = 0
        self.size = 20

    def get_transport_header(self):
        flags_n_offset = (self.offset << 12) + self.flags
        tcp_hdr = struct.pack('!HHIIHHHH',
                              self.sport.get_port_value(),
                              self.dport.get_port_value(), self.seq,
                              self.ack, flags_n_offset, self.window,
                              self.checksum, self.urg)
        return tcp_hdr

    def get_flags(self):
        return self.flags

    def get_seq_num(self):
        return self.seq

    def get_ack_num(self):
        return self.ack

    def set_seq_num(self, seq=0):
        self.seq = seq

    def set_ack_num(self, ack=0):
        self.ack = ack

    def set_flags(self, flags=0):
        self.flags = flags

class UDP(TransportLayer):

    def __init__(self, sport=None, dport=None):
        super().__init__("udp", sport, dport)
        self.length = 0
        self.checksum = 0
        self.size = 8

    def get_transport_header(self):
        udp_hdr = struct.pack('!HHHH', self.sport.get_port_value(),
                              self.dport.get_port_value(), self.length,
                              self.checksum)
        return udp_hdr

    def set_length(self, length=0):
        self.length = length
