import re
import xml.etree.ElementTree as ET
import os
import unittest
from sniffles.petabi_rule_writer.petabi_rule_writer import *
from sniffles.rulereader import *

"""Unit tests for petabi_rule_writer.py

The following unit test checks if the format of output rule file follows
the petabi rule format listed in github.com/petabi/sniffles

More importantly, it checks whether an output file is compatible with
sniffles(i.e. checks if output file is formatted in a way that sniffles
can read its attributes).
"""


# Class for testing format functions in petabi_rule_writer.py
class TestPetabiRuleWriter(unittest.TestCase):

    # Check if pkt rule is in correct format
    def test_pkt_format(self):
        # Check each inputs are readable
        regex = "/abc/"
        count = '1'
        fragment = '2'
        flow = 'to client'
        split = '3'
        ttl = '4'
        ttlExpiry = '5'
        pktAck = True
        pktRule = formatPktRule(regex, count, fragment, flow, split, ttl,
                                ttlExpiry, pktAck)
        root = ET.fromstring(pktRule)
        for attribute in root.attrib:
            if attribute == 'content':
                self.assertEqual(root.attrib[attribute], '/abc/')
            elif attribute == 'times':
                self.assertEqual(root.attrib[attribute], '1')
            elif attribute == 'fragment':
                self.assertEqual(root.attrib[attribute], '2')
            elif attribute == 'flow':
                self.assertEqual(root.attrib[attribute], 'to client')
            elif attribute == 'split':
                self.assertEqual(root.attrib[attribute], '3')
            elif attribute == 'ttl':
                self.assertEqual(root.attrib[attribute], '4')
            elif attribute == 'ttl_expiry':
                self.assertEqual(root.attrib[attribute], '5')
            elif attribute == 'pktAck':
                self.assertEqual(root.attrib[attribute], 'true')

        # Check if header and tail is in right format
        pktRule = pktRule.strip()
        pktFormat = pktRule.split(' ')
        self.assertEqual(pktFormat[0], "<pkt")
        self.assertEqual(pktFormat[-1], "/>")

    # Checks if the traffic stream rule is in correct format
    def test_traffic_stream_format(self):
        # Check for input format
        proto = 'tcp'
        src = 'any'
        dst = 'any'
        sport = 'any'
        dport = 'any'
        ack = True
        out_of_order = True
        out_of_order_prob = '50'
        packet_loss = '50'
        tcpOverlap = True
        tsRule = formatTrafficStreamRule(proto, src, dst, dport, sport, ack,
                                         out_of_order, out_of_order_prob,
                                         packet_loss, tcpOverlap)
        # Add ending tag for testing purpsoe
        tsRule += "    </traffic_stream>"
        root = ET.fromstring(tsRule)
        for attribute in root.attrib:
            if attribute == 'proto':
                self.assertEqual(root.attrib[attribute], 'tcp')
            elif attribute == 'src':
                self.assertEqual(root.attrib[attribute], 'any')
            elif attribute == 'dst':
                self.assertEqual(root.attrib[attribute], 'any')
            elif attribute == 'dport':
                self.assertEqual(root.attrib[attribute], 'any')
            elif attribute == 'sport':
                self.assertEqual(root.attrib[attribute], 'any')
            elif attribute == 'ack':
                self.assertEqual(root.attrib[attribute], 'true')
            elif attribute == 'out_of_order':
                self.assertEqual(root.attrib[attribute], 'true')
            elif attribute == 'out_of_order_prob':
                self.assertEqual(root.attrib[attribute], '50')
            elif attribute == 'packet_loss':
                self.assertEqual(root.attrib[attribute], '50')
            elif attribute == 'tcp_overlap':
                self.assertEqual(root.attrib[attribute], 'true')

        # Check if the head and tail is in right format
        tsRule = formatTrafficStreamRule(proto, src, dst, dport, sport, ack,
                                         out_of_order, out_of_order_prob,
                                         packet_loss, tcpOverlap)
        tsRule = tsRule.strip()
        self.assertEqual(tsRule[-1], '>')
        tsFormat = tsRule.split(' ')
        self.assertEqual(tsFormat[0], "<traffic_stream")

    # Checks format of background traffic
    def test_background_rule_format(self):
        background_percentage = '50'
        protocol_dist = ['20', '20', '20', '20', '20']
        background_format = formatBackgroundTrafficRule(background_percentage,
                                                        protocol_dist)
        # Add ending tag for test purpose
        background_format += "    </traffic_stream>"
        root = ET.fromstring(background_format)

        for attribute in root.attrib:
            if attribute == 'typets':
                self.assertEqual(root.attrib[attribute], 'BackgroundTraffic')
            elif attribute == 'percentage':
                self.assertEqual(root.attrib[attribute], '50')

            elif attribute == 'http':
                self.assertEqual(root.attrib[attribute], '20')

            elif attribute == 'ftp':
                self.assertEqual(root.attrib[attribute], '20')

            elif attribute == 'imap':
                self.assertEqual(root.attrib[attribute], '20')

            elif attribute == 'pop':
                self.assertEqual(root.attrib[attribute], '20')

            elif attribute == 'smtp':
                self.assertEqual(root.attrib[attribute], '20')

    # Checks order and number of rule created
    def test_rule_format(self):
        # Check if number or regex matches number of rules
        regexList = ["/abc/", "/def/", "/ghi/"]
        ruleSet = formatRule(regexList)
        self.assertEqual(len(ruleSet), 3)

        # Check the order of rule
        ruleNum = 1
        ruleName = "Rule #"
        for key in ruleSet:
            ruleID = ruleName + str(ruleNum)
            self.assertEqual(key, ruleID)
            ruleNum += 1

    # Checks if output file is compatible with rulereader.py
    def test_print_rule(self):
        filename = "sniffles/test/data_files/test_petabi_rule.xml"
        regexList = ["/abc/", "/def/", "/ghi/"]
        ruleName = None
        percentage = '50'
        proto = 'tcp'
        src = 'any'
        dst = 'any'
        sport = 'any'
        dport = 'any'
        ack = True
        out_of_order = True
        out_of_order_prob = '50'
        packet_loss = '50'
        tcpOverlap = True
        count = '1'
        fragment = '2'
        flow = 'to client'
        split = '3'
        ttl = '4'
        ttlExpiry = '5'
        pktAck = True
        tsAck = True
        bg_traffic_percentage = '50'
        protocol_dist = ['10', '10', '10', '*', '10']

        rule = formatRule(regexList, ruleName, proto, src, dst, dport, sport,
                          out_of_order, out_of_order_prob, packet_loss,
                          tcpOverlap, count, fragment, flow, split, ttl,
                          ttlExpiry, pktAck, tsAck, bg_traffic_percentage,
                          protocol_dist)

        printRule(rule, filename)
        parser = PetabiRuleParser()
        parser.parseRuleFile(filename)
        os.remove(filename)
        test_rule = parser.getRules()

        bg_traffic_rule = parser.getBackgroundTraffic()
        protocol_dist_dictionary = bg_traffic_rule.getDistribution()
        self.assertEqual(int(bg_traffic_percentage),
                         bg_traffic_rule.getBackgroundPercent())
        self.assertEqual(len(protocol_dist) - 1,
                         len(protocol_dist_dictionary))
        self.assertEqual(protocol_dist_dictionary['http'], 10)

        for petabi_rule in test_rule:

            ts_rule = petabi_rule.getTS()
            self.assertEqual(proto, ts_rule[0].getProto())
            self.assertEqual(src, ts_rule[0].getSrcIp())
            self.assertEqual(dst, ts_rule[0].getDstIp())
            self.assertEqual(sport, ts_rule[0].getSport())
            self.assertEqual(dport, ts_rule[0].getDport())
            self.assertEqual(out_of_order, ts_rule[0].getOutOfOrder())
            self.assertEqual(int(out_of_order_prob), ts_rule[0].getOOOProb())
            self.assertEqual(int(packet_loss), ts_rule[0].getPacketLoss())
            self.assertEqual(tcpOverlap, ts_rule[0].getTCPOverlap())

            pkt_rule = ts_rule[0].getPkts()
            pkt_rule = pkt_rule[0]
            self.assertEqual(int(count), pkt_rule.getTimes())
            self.assertEqual(int(fragment), pkt_rule.getFragment())
            self.assertEqual(flow, pkt_rule.getDir())
            self.assertEqual(int(split), pkt_rule.getSplit())
            self.assertEqual(int(ttl), pkt_rule.getTTL())
            self.assertEqual(int(ttlExpiry), pkt_rule.getTTLExpiry())
            self.assertEqual(pktAck, pkt_rule.ackThis())
