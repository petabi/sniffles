from unittest import *
from sniffles.petabi_rule_writer.petabi_rule_writer import *
import re
import random


class TestPetabiRuleWriter(TestCase):

    # Check if pkt rule is in correct format
    def test_pkt_format(self):
        # Check content
        print("hello")
        regex = "/abc/"
        pktRule = formatPktRule(regex)
        check = re.search("content=\"" + regex + "\"", pktRule)
        self.assertIsNot(check, None)

        # Check each inputs
        count = '1'
        fragment = '2'
        flow = 'to client'
        split = '3'
        ttl = '4'
        ttlExpiry = '5'
        pktAck = True
        pktRule = formatPktRule(regex, count, fragment, flow, split, ttl,
                                ttlExpiry, pktAck)

        check = re.search("times=\"" + count + "\"", pktRule)
        self.assertIsNot(check, None)
        check = re.search("fragment=\"" + fragment + "\"", pktRule)
        self.assertIsNot(check, None)
        check = re.search("dir=\"" + flow + "\"", pktRule)
        self.assertIsNot(check, None)
        check = re.search("split=\"" + split + "\"", pktRule)
        self.assertIsNot(check, None)
        check = re.search("ttl=\"" + ttl + "\"", pktRule)
        self.assertIsNot(check, None)
        check = re.search("ttl_expiry=\"" + ttlExpiry + "\"", pktRule)
        self.assertIsNot(check, None)
        check = re.search("ack=\"true\"", pktRule)
        self.assertIsNot(check, None)

        # Check if header and tail is in right format
        pktRule = pktRule.strip()
        pktFormat = pktRule.split(' ')
        self.assertEqual(pktFormat[0], "<pkt")
        self.assertEqual(pktFormat[-1], "/>")

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

        check = re.search("proto=\"tcp\"", tsRule)
        self.assertIsNot(check, None)
        check = re.search("src=\"any\"", tsRule)
        self.assertIsNot(check, None)
        check = re.search("dst=\"any\"", tsRule)
        self.assertIsNot(check, None)
        check = re.search("sport=\"any\"", tsRule)
        self.assertIsNot(check, None)
        check = re.search("dport=\"any\"", tsRule)
        self.assertIsNot(check, None)
        check = re.search("ack=\"true\"", tsRule)
        self.assertIsNot(check, None)
        check = re.search("out_of_order=\"true\"", tsRule)
        self.assertIsNot(check, None)
        check = re.search("out_of_order_prob=\"50\"", tsRule)
        self.assertIsNot(check, None)
        check = re.search("packet_loss=\"50\"", tsRule)
        self.assertIsNot(check, None)
        check = re.search("tcp_overlap=\"true\"", tsRule)
        self.assertIsNot(check, None)

        # Check if the head and tail is in right format
        tsRule = tsRule.strip()
        self.assertEqual(tsRule[-1], '>')
        tsFormat = tsRule.split(' ')
        self.assertEqual(tsFormat[0], "<traffic_stream")

    def test_rule_format(self):
        # Check if number or regex matches number of rules
        regexList = ["/abc/", "/def/", "/ghi/"]
        ruleSet = formatRule(regexList)
        self.assertEqual(len(ruleSet), 3)

        # Check the order of rule
        ruleNum = 1
        ruleName = "Rule #"
        for key in ruleSet:
            ruleID = ruleName + ruleNum
            self.assertEqual(key, ruleID)
            ruleNum += 1





