import re
import xml.etree.ElementTree as ET
from unittest import *
from sniffles.petabi_rule_writer.petabi_rule_writer import *

"""Unit tests for petabi_rule_writer.py

The following unit test checks if the format of output rule file follows
the petabi rule format listed in github.com/petabi/sniffles

More importantly, it checks whether an output file is compatible with
sniffles(i.e. checks if output file is formatted in a way that sniffles
can read its attributes).
"""


# Class for testing format functions in petabi_rule_writer.py
class TestPetabiRuleWriter(TestCase):

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
