import struct
import random
import sys
from os.path import isfile, join
from sniffles.snifflesconfig import getVersion

"""
    Splits a pcap in two such that traffic from one direction is
    placed in one file and traffic in another direction is placed
    in another file (tfilea and tfileb respectively).
    The traffobot then uses those files to send traffic
    across a network link.  This allows for the possibility
    of more accurately simulating actual traffic.
"""


class MetaPacket:
    def __init__(self, pkt_number=0, raw=None, ts=0, tus=0):
        self.pkt_order_num = pkt_number
        self.raw = raw
        self.ts = ts
        self.tus = tus
        if raw is not None:
            self.len = len(self.raw)
        else:
            self.len = 0

    def __str__(self):
        mystr = "Packet Order Num: "
        mystr += str(self.pkt_order_num)
        mystr += "\nPkt-len: "
        mystr += str(self.len)
        mystr += "\nTS-seconds: "
        mystr += str(self.ts)
        mystr += "\nTS-useconds: "
        mystr += str(self.tus) + "\n"
        mystr += '-'.join(['%02x' % byte for byte in self.raw])
        mystr += "\n"
        return mystr

    def getMetaPacket(self):
        if self.raw is not None:
            myformatstring = '!HIII{0}s'.format(len(self.raw))
            mymetap = struct.pack(myformatstring, self.len, self.pkt_order_num,
                                  self.ts, self.tus, self.raw)
        else:
            mymetap = struct.pack('!HIII', self.len, self.pkt_order_num,
                                  self.ts, self.tus)
        return mymetap

    def getPktOrderNum(self):
        return self.pkt_order_num

    def getRawPacket(self):
        return self.raw


class MetaStream:
    def __init__(self, start_sec=1, start_usec=0, hash=None, rhash=None):
        self.start_sec = start_sec
        self.start_usec = start_usec
        self.hash = hash
        self.rhash = rhash
        self.pkts = []

    def __str__(self):
        mystr = "Meta Stream:\n"
        mystr += "Hash: "
        mystr += str(self.hash)
        mystr += "\nRHash: "
        mystr += str(self.rhash)
        mystr += "Start TS-s: "
        mystr += str(self.start_sec)
        mystr += "\n Start TS-us: "
        mystr += str(self.start_usec)
        mystr += "\n Total Packets: "
        mystr += str(len(self.pkts))
        mystr += "\n"
        for p in self.pkts:
            mystr += str(p)
        return mystr

    def getMetaStream(self):
        myformatstream = '!IIII{0}sI{1}s'.format(len(self.hash),
                                                 len(self.rhash))
        mymetas = struct.pack(myformatstream, self.start_sec, self.start_usec,
                              len(self.pkts), len(self.hash),
                              bytearray(self.hash), len(self.rhash),
                              bytearray(self.rhash))
        for p in self.pkts:
            mymetas += p.getMetaPacket()
        return mymetas

    def addPacket(self, raw=None, pkt_order_num=0, ts=0, tus=0):
        self.pkts.append(MetaPacket(pkt_order_num, raw, ts, tus))

    def getHash(self):
        return self.hash

    def getReverseHash(self):
        return self.rhash

    def getStartSec(self):
        return self.start_sec

    def getStartUSec(self):
        return self.start_usec

    def getNextPacket(self):
        if self.hasPackets():
            pkt = self.pkts.pop(0)
            return pkt
        return None

    def hasPackets(self):
        if len(self.pkts) > 0:
            return True
        return False


class TrafficSplitter:
    def __init__(self, readfile='../sniffles.pcap', filea='tfilea',
                 fileb='tfileb'):
        self.readfile = readfile
        self.filea = filea
        self.fileb = fileb
        self.streamsa = {}
        self.streamsb = {}

    def writeMetaStreams(self, dir="a", d=None, fmap=None):
        version = getVersion()
        major, minor, patch = version.split('.')
        write_file = self.filea
        if dir != "a":
            write_file = self.fileb
        try:
            writer = open(write_file, "wb")
        except:
            print("Could not write out traffic for ", write_file)
            sys.exit(1)
        myheader = struct.pack('!8sIII', bytes('sniffles', 'utf-8'),
                               int(major), int(minor), int(patch))
        writer.write(myheader)
        mytotalstreams = struct.pack('!I', len(d))
        writer.write(mytotalstreams)
        for key in d:
            writer.write(d[key].getMetaStream())
        if fmap is not None:
            writer.write(fmap)
        writer.close()

    def getStreamUniHash(self, pkt):
        unihash = None
        if (pkt.getProto() == 0x06):
            sport = pkt.getSport()
            dport = pkt.getDport()
            if sport > dport:
                sport = dport
                dport = pkt.getSport()
            sip = pkt.getSip()
            dip = pkt.getDip()
            if sip > dip:
                sip = dip
                dip = pkt.getSip()
            unihash = struct.pack('!IIHH', sip, dip, sport, dport)
        return unihash

    def readPcap(self):
        order_mapping = {}
        frag_index = {}
        myreader = PcapReader(self.readfile)
        myreader.openPcapFile()
        pkt = myreader.getNextPacket()
        while pkt is not None:
            frag_index = pkt.getFragIndex()
            unihash = self.getStreamUniHash(pkt)
            if unihash is not None:
                if unihash in order_mapping:
                    pkt.setOrderNum(order_mapping[unihash])
                    order_mapping[unihash] += 1
                else:
                    pkt.setOrderNum(0)
                    order_mapping[unihash] = 1
            if pkt.getFlowHash() in self.streamsa:
                stream = self.streamsa[pkt.getFlowHash()]
                if pkt.getProto() == 0x06:
                    stream.addPacket(pkt.getRawPacket(), pkt.getOrderNum(), 0,
                                     0)
                else:
                    stream.addPacket(pkt.getRawPacket(), pkt.getOrderNum(),
                                     pkt.getSecond(), pkt.getUSecond())
            elif pkt.getFlowHash() in self.streamsb:
                stream = self.streamsb[pkt.getFlowHash()]
                if pkt.getProto() == 0x06:
                    stream.addPacket(pkt.getRawPacket(), pkt.getOrderNum(), 0,
                                     0)
                else:
                    stream.addPacket(pkt.getRawPacket(), pkt.getOrderNum(),
                                     pkt.getSecond(), pkt.getUSecond())

            else:
                start_sec = 0
                start_usec = 0
                if (pkt.getReverseFlowHash() not in self.streamsa and
                    pkt.getReverseFlowHash() not in self.streamsb and
                    pkt.getProto() == 0x06) or \
                   pkt.getProto() != 0x06:
                    start_sec = pkt.getSecond() + 1
                    start_usec = pkt.getUSecond()
                stream = MetaStream(start_sec, start_usec, pkt.getFlowHash(),
                                    pkt.getReverseFlowHash())
                stream.addPacket(pkt.getRawPacket(), pkt.getOrderNum(),
                                 start_sec, start_usec)
                if stream.getReverseHash() in self.streamsb:
                    self.streamsa[pkt.getFlowHash()] = stream
                elif stream.getReverseHash() in self.streamsa:
                    self.streamsb[stream.getHash()] = stream
                else:
                    self.streamsa[stream.getHash()] = stream

            pkt = myreader.getNextPacket()

        myreader.closePcapFile()
        myfmap = None
        if len(frag_index) > 0:
            myfmap = struct.pack('!I', len(frag_index))
            for f in frag_index:
                myfmap += struct.pack('!HHHH', f, frag_index[f][0],
                                      frag_index[f][1], frag_index[f][2])
#        print("Streams A:")
#        for s in self.streamsa:
#            print(self.streamsa[s])
#        print("Streams B:")
#        for s in self.streamsb:
#            print(self.streamsb[s])
#        print("myfmap: ", myfmap)
        self.writeMetaStreams("a", self.streamsa, myfmap)
        self.writeMetaStreams("b", self.streamsb, myfmap)


class PcapPacket:
    frag_index = {}

    def __init__(self, secs=0, usecs=0, len=0, pkt=None, preader=None,
                 initialize=True):
        self.secs = secs
        self.usecs = usecs
        self.len = len
        self.pkt = pkt
        self.preader = preader
        self.proto = 0
        self.sip = 0
        self.dip = 0
        self.sport = 0
        self.dport = 0
        self.frag_id = 0
        self.offset = 0
        self.hash = None
        self.reverse_hash = None
        self.order_num = 0
        if initialize:
            self.getFlowHash()

    def __str__(self):
        packet = "pkt: "
        packet += "hash: "
        bytes = bytearray(self.getFlowHash())
        packet += '-'.join(['%02x' % byte for byte in bytes])
        packet += "\n"
        packet += "reverse hash: "
        bytes = bytearray(self.getReverseFlowHash())
        packet += '-'.join(['%02x' % byte for byte in bytes])
        packet += "\n"
        packet += "Raw data: "
        packet += "\nsec: "
        packet += str(self.secs)
        packet += "\nusec: "
        packet += str(self.usecs)
        packet += "\n"
        bytes = bytearray(self.pkt)
        packet += '-'.join(['%02x' % byte for byte in bytes])
        return packet

    def getFragIndex(self):
        return self.frag_index

    def getFragID(self):
        return self.frag_id

    def getSecond(self):
        return self.secs

    def getUSecond(self):
        return self.usecs

    def getLen(self):
        return self.len

    def getProto(self):
        return self.proto

    def getSip(self):
        return self.sip

    def getDip(self):
        return self.dip

    def getSport(self):
        return self.sport

    def getDport(self):
        return self.dport

    def getFlowHash(self):
        if self.hash is not None or self.pkt is None:
            return self.hash
        etype = struct.unpack('!H', self.pkt[12:14])
        if etype[0] != 0x0800:
            return None
        ipv = struct.unpack('!B', self.pkt[14:15])
        if ipv[0] == 0x45:
            iph = struct.unpack('!ssHHHssHII', self.pkt[14:34])
            self.frag_id = int(iph[3])
            self.proto = ord(iph[6])
            self.sip = iph[8]
            self.dip = iph[9]
            if self.frag_id != 0:
                if self.frag_id in self.frag_index:
                    self.proto, self.sport, self.dport = \
                        self.frag_index[self.frag_id]
                else:
                    self.offset = int(iph[4]) & 0x1fff
                    if self.offset == 0 and \
                       (self.proto == 0x06 or self.proto == 0x11):
                        self.sport, self.dport = \
                            struct.unpack('!HH', self.pkt[34:38])
                        self.frag_index[self.frag_id] = [self.proto,
                                                         self.sport,
                                                         self.dport]
                    elif self.offset == 0:
                        self.sport = 0
                        self.dport = 0
                    else:
                        self.proto, self.sport, self.dport = \
                            self.preader.findStartFragment(self.frag_id)
                        self.frag_index[self.frag_id] = [self.proto,
                                                         self.sport,
                                                         self.dport]
            elif self.proto == 0x06 or self.proto == 0x11:
                self.sport, self.dport = struct.unpack('!HH', self.pkt[34:38])
            else:
                self.sport = 0
                self.dport = 0
        self.hash = struct.pack('!BIIHH', self.proto, self.sip,
                                self.dip, self.sport, self.dport)
        self.reverse_hash = struct.pack('!BIIHH', self.proto, self.dip,
                                        self.sip, self.dport, self.sport)
        return self.hash

    def getReverseFlowHash(self):
        if self.hash is None or self.reverse_hash is None:
            self.getFlowHash()
        return self.reverse_hash

    def getRawPacket(self):
        return self.pkt

    def getOffset(self):
        return self.offset

    def getOrderNum(self):
        return self.order_num

    def setOrderNum(self, num):
        self.order_num = num


class PcapReader:
    def __init__(self, pcap_file=None):
        self.reader = None
        self.pcap_file = None
        if pcap_file is not None:
            self.pcap_file = pcap_file
        self.file_byte_order = sys.byteorder

    def openPcapFile(self):
        if self.pcap_file is not None:
            try:
                self.reader = open(self.pcap_file, 'rb')
            except:
                print("Could not open the pcap file: ", self.pcap_file)
                sys.exit(1)
            self.readPcapHeader()
        else:
            print("You have not designated a pcap file to read.")
            sys.exit(1)

    def closePcapFile(self):
        if self.reader:
            self.reader.close()

    def readPcapHeader(self):
        if self.reader:
            header = struct.unpack('IHHIIII', self.reader.read(24))
            magic_number = header[0]
            if magic_number != 0xa1b2c3d4:
                if self.file_byte_order == 'little':
                    self.file_byte_order = 'big'
                else:
                    self.file_byte_order = 'little'

    def findStartFragment(self, frag_id):
        if self.reader:
            current_pos = self.reader.tell()
            pkt = self.getNextPacket(False)
            while pkt is not None:
                frag, off, ttl, proto = struct.unpack('!HHss', pkt.pkt[18:24])
                frag = int(frag)
                off = int(off) & 0x1ff
                if frag == frag_id:
                    if off == 0 and (ord(proto) == 0x06 or ord(proto) == 0x11):
                        sport, dport = struct.unpack('!HH', pkt.pkt[34:38])
                        self.reader.seek(current_pos)
                        return [ord(proto), sport, dport]
                    elif off == 0:
                        self.reader.seek(current_pos)
                        return [ord(proto), 0, 0]
                pkt = self.getNextPacket(False)
            self.reader.seek(current_pos)
        return [0, 0, 0]

    def getNextPacket(self, ini=True):
        pkt = None
        if self.reader:
            myblock = self.reader.read(16)
            if myblock == b'':
                return None
            if self.file_byte_order == 'little':
                pcap_header = struct.unpack('<IIII', myblock)
            else:
                pcap_header = struct.unpack('>IIII', myblock)
            data = self.reader.read(pcap_header[2])
            pkt = PcapPacket(pcap_header[0], pcap_header[1], pcap_header[2],
                             data, self, ini)
        return pkt
