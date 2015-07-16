from unittest import *
from sniffles.ruletrafficgenerator import *
from sniffles.snifflesconfig import *

class TestExamples(TestCase):

    def test_udp_stream(self):
        myrpkt = RulePkt("to server", "/my udp1/", 0, 3)
        mytsrule = TrafficStreamRule('udp', '1.2.3.6', '9.8.7.6', '9005',
                                     '105')
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(25)
        myConfig.setIPV6Percent(0)
        myConfig.setFullMatch(True)

        myts = TrafficStream(mytsrule, myConfig)

        mycount = 0
        while myts.has_packets():
            mypkt = myts.getNextPacket()[0]
            self.assertEqual(mypkt.get_size(), 67)
            self.assertEqual(mypkt.get_src_ip(), '1.2.3.6')
            self.assertEqual(mypkt.get_dst_ip(), '9.8.7.6')
            mycount += 1
        self.assertEqual(mycount, 3)

    def test_udp_stream_frags(self):
        myrpkt = RulePkt("to server", "/my udp2/", 3, 2)
        mytsrule = TrafficStreamRule('udp', '1.2.3.6', '9.8.7.6', '9005',
                                     '105')
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(250)
        myConfig.setIPV6Percent(0)
        myConfig.setFullMatch(True)

        myts = TrafficStream(mytsrule, myConfig)

        mycount = 0
        while myts.has_packets():
            mypkt = myts.getNextPacket()[0]
            self.assertIn(mypkt.get_size(), [116, 122])
            self.assertEqual(mypkt.get_src_ip(), '1.2.3.6')
            self.assertEqual(mypkt.get_dst_ip(), '9.8.7.6')
            self.assertIn(mypkt.network_hdr.get_frag_offset(),
                          [8192, 8203, 22])
            mycount += 1
        self.assertEqual(mycount, 6)

    def test_udp_stream_frags_and_ooo(self):
        myrpkt = RulePkt("to server", "/my udp3/", 3, 5, 250)
        mytsrule = TrafficStreamRule('udp', '1.2.3.6', '9.8.7.6', '9005',
                                     '105', -1, 4, False, False, False, True,
                                     75)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(250)
        myConfig.setIPV6Percent(0)
        myConfig.setFullMatch(True)

        myts = TrafficStream(mytsrule, myConfig)

        mycount = 0
        myfragid = 0
        mylastoff = -1
        ooo = False
        while myts.has_packets():
            mypkt = myts.getNextPacket()[0]
            if mypkt.network_hdr.get_frag_id() != myfragid:
                myfragid = mypkt.network_hdr.get_frag_id()
                mylastid = -1
            if mylastoff > -1:
                if abs((mypkt.network_hdr.get_frag_offset() & 0xFF) -
                       mylastoff) > 11:
                    ooo = True
            mylastoff = (mypkt.network_hdr.get_frag_offset() & 0xFF)
            self.assertIn(mypkt.get_size(), [116, 122])
            self.assertEqual(mypkt.get_src_ip(), '1.2.3.6')
            self.assertEqual(mypkt.get_dst_ip(), '9.8.7.6')
            self.assertIn(mypkt.network_hdr.get_frag_offset(),
                          [8192, 8203, 22])
            mycount += 1
        self.assertEqual(mycount, 15)
        self.assertEqual(ooo, True)

    def test_udp_stream_frags_loss(self):
        myrpkt = RulePkt("to server", RuleContent("pcre", "/my udp4/"), 3, 2,
                         250)
        mytsrule = TrafficStreamRule('udp', '1.2.3.6', '9.8.7.6', '9005',
                                     '105', -1, 4, False, False, False, False,
                                     0, 95)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(250)
        myConfig.setIPV6Percent(0)
        myConfig.setFullMatch(True)

        myts = TrafficStream(mytsrule, myConfig)
        
        mycount = 0
        while myts.has_packets():
            mypkt = myts.getNextPacket()[0]
            mycount += 1
        self.assertNotEqual(mycount, 6)

    def test_tcp_stream(self):
        myrpkt = RulePkt("to server", "/my tcp1/", 0, 3)
        mytsrule = TrafficStreamRule('tcp', '1.2.3.4', '9.8.7.5', '9000',
                                     '101', -1, 4, False, True, True)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(100)
        myConfig.setIPV6Percent(0)
        myConfig.setFullMatch(True)

        myts = TrafficStream(mytsrule, myConfig)
        
        mycount = 0
        mypkt = myts.getNextPacket()[0]
        myseq = mypkt.transport_hdr.get_seq_num()
        self.assertEqual(mypkt.transport_hdr.get_flags(), SYN)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), SYN + ACK)
        for i in range(0, 3):
            mypkt = myts.getNextPacket()[0]
            self.assertEqual(mypkt.transport_hdr.get_seq_num(),
                             myseq + (i * 100) + 1)
            self.assertEqual(mypkt.get_src_ip(), '1.2.3.4')
            self.assertEqual(mypkt.get_dst_ip(), '9.8.7.5')

        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), FIN + ACK)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), ACK)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), FIN + ACK)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), ACK)

    def test_tcp_stream_frag(self):
        myrpkt = RulePkt("to server", "/my tcp2/", 4, 3)
        mytsrule = TrafficStreamRule('tcp', '1.2.3.4', '9.8.7.5', '9000',
                                     '101', -1, 4, False, True, True)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(140)
        myConfig.setIPV6Percent(0)

        myts = TrafficStream(mytsrule, myConfig)
        
        mycount = 0
        mypkt = myts.getNextPacket()[0]
        myseq = mypkt.transport_hdr.get_seq_num()
        self.assertEqual(mypkt.transport_hdr.get_flags(), SYN)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), SYN + ACK)
        for i in range(0, 12):
            mypkt = myts.getNextPacket()[0]
            self.assertNotEqual(mypkt.network_hdr.get_frag_id(), 0)
            self.assertIn(mypkt.network_hdr.get_frag_offset(), [8192, 8197,
                          8202, 8207, 15])

        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), FIN + ACK)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), ACK)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), FIN + ACK)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), ACK)

    def test_tcp_stream_frag_ooo(self):
        myrpkt = RulePkt("to server", "/my tcp2/", 4, 3, 140, False, True)
        mytsrule = TrafficStreamRule('tcp', '1.2.3.4', '9.8.7.5', '9000',
                                     '101', -1, 4, False, True, True)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(140)
        myConfig.setIPV6Percent(0)
        myConfig.setFullMatch(True)

        myts = TrafficStream(mytsrule, myConfig)
        
        mypkt = myts.getNextPacket()[0]
        myseq = mypkt.transport_hdr.get_seq_num()
        self.assertEqual(mypkt.transport_hdr.get_flags(), SYN)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), SYN + ACK)
        myfragid = 0
        mylastoff = -1
        ooo = False
        for i in range(0, 12):
            mypkt = myts.getNextPacket()[0]
            self.assertNotEqual(mypkt.network_hdr.get_frag_id(), 0)
            self.assertIn(mypkt.network_hdr.get_frag_offset(), [8192, 8197,
                          8202, 8207, 15])
            if mypkt.network_hdr.get_frag_id() != myfragid:
                myfragid = mypkt.network_hdr.get_frag_id()
                mylastid = -1
            if mylastoff > -1:
                if abs((mypkt.network_hdr.get_frag_offset() & 0xFF) -
                       mylastoff) > 5:
                    ooo = True
            else:
                mylastoff = (mypkt.network_hdr.get_frag_offset() & 0xFF)
        self.assertEqual(ooo, True)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), FIN + ACK)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), ACK)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), FIN + ACK)
        mypkt = myts.getNextPacket()[0]
        self.assertEqual(mypkt.transport_hdr.get_flags(), ACK)

    def test_split(self):
        myrpkt = RulePkt("to server", "/my split message/", 0, 1, -1, False,
                         False,  2)
        mytsrule = TrafficStreamRule('tcp', '1.2.3.6', '9.8.7.6', '9005',
                                     '105')
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(-1)
        myConfig.setIPV6Percent(0)
        myConfig.setFullMatch(True)

        myts = TrafficStream(mytsrule, myConfig)

        mycount = 0
        while myts.has_packets():
            mypkt = myts.getNextPacket()[0]
            self.assertEqual(mypkt.get_size(), 62)
            mycount += 1
        self.assertEqual(mycount, 2)

    def test_ttl_expiry_scenario2(self):
        """
           2)ttl = 115, 2 fragment
           two packet should have ttl is 115
        """
        myrpkt = RulePkt("to server", "/my tcp2/", 2, 1, ttl=115)
        mytsrule = TrafficStreamRule('tcp', '1.2.3.4', '9.8.7.5', '9000',
                                     '101', -1, 4, False, False, False)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(140)
        myConfig.setIPV6Percent(0)
        myConfig.setFullMatch(True)

        myts = TrafficStream(mytsrule, myConfig)

        mycount = 0
        while myts.has_packets():
            mypkt = myts.getNextPacket()[0]
            self.assertEqual(mypkt.get_ttl(), 115)
            mycount += 1
        self.assertEqual(mycount, 2)

    def test_ttl_expiry_scenario1(self):
        """
           1)tll = 110, no fragment
           one packet should have ttl is 110
        """
        myrpkt = RulePkt("to server", "/my tcp2/", 0, 1, ttl=110)
        mytsrule = TrafficStreamRule('tcp', '1.2.3.4', '9.8.7.5', '9000',
                                     '101', -1, 4, False, False, False)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(140)
        myConfig.setIPV6Percent(0)
        myConfig.setFullMatch(True)

        myts = TrafficStream(mytsrule, myConfig)

        mycount = 0
        while myts.has_packets():
            mypkt = myts.getNextPacket()[0]
            self.assertEqual(mypkt.get_ttl(), 110)
            mycount += 1
        self.assertEqual(mycount, 1)

    def test_ttl_expiry_scenario3(self):
        """
           ttl = 110 and ttl_expiry = 6 and fragment is 2
           create two good packet with ttl value is 110
           and malicious packet with ttl value is 6
           the totall is 3 packet
        """
        myrpkt = RulePkt("to server", "/my tcp2/", 2, 1, ttl=110, ttl_expiry=6)
        mytsrule = TrafficStreamRule('tcp', '1.2.3.4', '9.8.7.5', '9000',
                                     '101', -1, 4, False, False, False)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(140)
        myConfig.setIPV6Percent(0)
        myConfig.setFullMatch(True)

        myts = TrafficStream(mytsrule, myConfig)
        
        mycount = 0
        while myts.has_packets():
            mypkt = myts.getNextPacket()[0]
            if mycount % 2 == 0:
                self.assertEqual(mypkt.get_ttl(), 110)
            else:
                self.assertEqual(mypkt.get_ttl(), 6)
            mycount += 1
        self.assertEqual(mycount, 3)

    def test_ttl_expiry_scenario4(self):
        """
           4)ttl = 147 and ttl_expiry = 0 and fragment is 2
           create two packet with ttl value is 147
           since ttl_expiry is 0
        """
        myrpkt = RulePkt("to server", "/my tcp2/", 2, 1, ttl=147, ttl_expiry=0)
        mytsrule = TrafficStreamRule('tcp', '1.2.3.4', '9.8.7.5', '9000',
                                     '101', -1, 4, False, False, False)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(140)
        myConfig.setIPV6Percent(0)
        myConfig.setFullMatch(True)

        myts = TrafficStream(mytsrule, myConfig)

        mycount = 0
        while myts.has_packets():
            mypkt = myts.getNextPacket()[0]
            self.assertEqual(mypkt.get_ttl(), 147)
            mycount += 1
        self.assertEqual(mycount, 2)

    def test_ttl_expiry_scenario5(self):
        """
           5)ttl_expiry = 9 and fragment is 3
           create three good packet with random ttl value
           malicious packet with ttl value is 9
           the totall is 5 packet
        """
        myrpkt = RulePkt("to server", "/abcdefghik/", 3, 1, ttl_expiry=9)
        mytsrule = TrafficStreamRule('tcp', '1.2.3.4', '9.8.7.5', '9000',
                                     '101', -1, 4, False, False, False)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(140)
        myConfig.setIPV6Percent(0)
        myConfig.setFullMatch(True)

        myts = TrafficStream(mytsrule, myConfig)
        
        mycount = 0
        while myts.has_packets():
            mypkt = myts.getNextPacket()[0]
            if mycount % 2 != 0:
                self.assertEqual(mypkt.get_ttl(), 9)
            mycount += 1
        self.assertEqual(mycount, 5)
