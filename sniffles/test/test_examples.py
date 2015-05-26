from unittest import *
from sniffles.ruletrafficgenerator import *
from sniffles.vendor_mac_list import vendor_oui


class TestExamples(TestCase):

    def test_udp_stream(self):
        myrpkt = RulePkt("to server", "/my udp1/", 0, 3)
        mytsrule = TrafficStreamRule('udp', '1.2.3.6', '9.8.7.6', '9005',
                                     '105')
        mytsrule.addPktRule(myrpkt)
        myts = TrafficStream(mytsrule, 25, 0, len(mytsrule.getPkts()), None,
                             False, mytsrule.getHandshake(),
                             mytsrule.getTeardown(), False, True, False, False,
                             mytsrule.getOutOfOrder(), mytsrule.getSynch(),
                             mytsrule.getPkts())
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
        myts = TrafficStream(mytsrule, 250, 0, len(mytsrule.getPkts()),
                             None, False, mytsrule.getHandshake(),
                             mytsrule.getTeardown(), False, True, False, False,
                             mytsrule.getOutOfOrder(), mytsrule.getSynch(),
                             mytsrule.getPkts())
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
        myts = TrafficStream(mytsrule, 250, 0, len(mytsrule.getPkts()),
                             None, False, mytsrule.getHandshake(),
                             mytsrule.getTeardown(), False, True, False, False,
                             mytsrule.getOutOfOrder(), mytsrule.getSynch(),
                             mytsrule.getPkts())
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
        myrpkt = RulePkt("to server", RuleContent("pcre", "/my udp4/"), 3, 2, 250)
        mytsrule = TrafficStreamRule('udp', '1.2.3.6', '9.8.7.6', '9005',
                                     '105', -1, 4, False, False, False, False, 0,
                                     95)
        mytsrule.addPktRule(myrpkt)
        myts = TrafficStream(mytsrule, 250, 0, len(mytsrule.getPkts()),
                             None, False, mytsrule.getHandshake(),
                             mytsrule.getTeardown(), False, True, False, False,
                             mytsrule.getOutOfOrder(), mytsrule.getSynch(),
                             mytsrule.getPkts())
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
        myts = TrafficStream(mytsrule, 100, 0, len(mytsrule.getPkts()),
                             None, False, mytsrule.getHandshake(),
                             mytsrule.getTeardown(), False, True, False, False,
                             mytsrule.getOutOfOrder(), mytsrule.getSynch(),
                             mytsrule.getPkts())
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
        myts = TrafficStream(mytsrule, 140, 0, len(mytsrule.getPkts()),
                             None, False, mytsrule.getHandshake(),
                             mytsrule.getTeardown(), False, True, False, False,
                             mytsrule.getOutOfOrder(), mytsrule.getSynch(),
                             mytsrule.getPkts())
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
        myts = TrafficStream(mytsrule, 140, 0, len(mytsrule.getPkts()),
                             None, False, mytsrule.getHandshake(),
                             mytsrule.getTeardown(), False, True, False,
                             False, mytsrule.getOutOfOrder(),
                             mytsrule.getSynch(), mytsrule.getPkts())
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
        myts = TrafficStream(mytsrule, -1, 0, len(mytsrule.getPkts()),
                             None, False, mytsrule.getHandshake(),
                             mytsrule.getTeardown(), False, True, False, False,
                             mytsrule.getOutOfOrder(), mytsrule.getSynch(),
                             mytsrule.getPkts())
        mycount = 0
        while myts.has_packets():
            mypkt = myts.getNextPacket()[0]
            self.assertEqual(mypkt.get_size(), 62)
            mycount += 1
        self.assertEqual(mycount, 2)
