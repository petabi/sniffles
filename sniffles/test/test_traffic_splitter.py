from unittest import *
import os
from sniffles.traffic_splitter import *


class TestTrafficSplitter(TestCase):

    def test_meta_packet(self):
        myp = MetaPacket()
        self.assertEqual(myp.getRawPacket(), None)
        self.assertEqual(myp.getPktOrderNum(), 0)
        mpkt = struct.pack('!HIII', 0, 0, 0, 0)
        self.assertEqual(myp.getMetaPacket(), mpkt)
        rpkt = struct.pack('!IIII', 1, 2, 3, 4)
        myp = MetaPacket(5, rpkt, 6, 7)
        self.assertEqual(myp.getRawPacket(), rpkt)
        self.assertEqual(myp.getPktOrderNum(), 5)
        mpkt = struct.pack('!HIII16s', 16, 5, 6, 7, rpkt)
        self.assertEqual(myp.getMetaPacket(), mpkt)

    def test_meta_stream(self):
        mys = MetaStream()
        self.assertEqual(mys.getHash(), None)
        self.assertEqual(mys.getReverseHash(), None)
        self.assertEqual(mys.getStartSec(), 1)
        self.assertEqual(mys.getStartUSec(), 0)
        self.assertFalse(mys.hasPackets())
        mys = MetaStream(5, 6, 'abcd', 'dcba')
        self.assertEqual(mys.getHash(), 'abcd')
        self.assertEqual(mys.getReverseHash(), 'dcba')
        self.assertEqual(mys.getStartSec(), 5)
        self.assertEqual(mys.getStartUSec(), 6)
        rpkt1 = struct.pack('!IIII', 1, 2, 3, 4)
        mys.addPacket(rpkt1, 0, 0, 0)
        rpkt2 = struct.pack('!IIII', 5, 6, 7, 8)
        mys.addPacket(rpkt2, 1, 1, 1)
        self.assertTrue(mys.hasPackets())
        myp = mys.getNextPacket()
        self.assertEqual(myp.getMetaPacket(),
                         MetaPacket(0, rpkt1, 0, 0).getMetaPacket())
        myp = mys.getNextPacket()
        self.assertEqual(myp.getMetaPacket(),
                         MetaPacket(1, rpkt2, 1, 1).getMetaPacket())
        self.assertFalse(mys.hasPackets())

    def test_pcap_reader(self):
        myips = [0x01020301, 0x01020302, 0x01020303, 0x01020304, 0x01020305,
                 0x01020306, 0x09080701, 0x09080702, 0x09080703, 0x09080704,
                 0x09080705, 0x09080706]
        myports = [9000, 9001, 9002, 9003, 9004, 9005, 100, 101, 102, 103, 104,
                   105]
        myprotos = [0x06, 0x11]
        mypcaprdr = PcapReader('sniffles/test/pcaps/testall.pcap')
        mypcaprdr.openPcapFile()
        myp = mypcaprdr.getNextPacket()
        self.assertNotEqual(myp, None)
        self.assertEqual(myp.getSecond(), 0)
        self.assertEqual(myp.getUSecond(), 0)

        mycount = 0
        while myp is not None:
            mycount += 1
            myp.getFlowHash()
            self.assertIn(myp.getProto(), myprotos)
            self.assertIn(myp.getSip(), myips)
            self.assertIn(myp.getDip(), myips)
            self.assertIn(myp.getSport(), myports)
            self.assertIn(myp.getDport(), myports)
            self.assertEqual(myp.getFlowHash(),
                             struct.pack('!BIIHH', myp.getProto(),
                                         myp.getSip(), myp.getDip(),
                                         myp.getSport(), myp.getDport()))
            self.assertEqual(myp.getReverseFlowHash(),
                             struct.pack('!BIIHH', myp.getProto(),
                                         myp.getDip(), myp.getSip(),
                                         myp.getDport(), myp.getSport()))
            myp = mypcaprdr.getNextPacket()
        self.assertEqual(mycount, 92)

    def test_traffic_splitter(self):
        myts = TrafficSplitter('sniffles/test/pcaps/testall.pcap')
        myts.readPcap()
        self.assertTrue(os.path.exists('tfilea'))
        if os.path.exists('tfilea'):
            os.remove('tfilea')
        self.assertTrue(os.path.exists('tfileb'))
        if os.path.exists('tfileb'):
            os.remove('tfileb')
