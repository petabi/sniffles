import re
import sys
import codecs
from os import listdir
from os.path import isfile, join
import xml.etree.ElementTree as ET

# Variables used for Snort rules
CONTENT_MODIFIERS = ['distance', 'offset', 'nocase', 'fast_pattern',
                     'within', 'only', 'depth', 'http_client_body',
                     'http_cookie', 'http_raw_cookie', 'http_header',
                     'http_raw_header', 'http_method', 'http_uri',
                     'http_raw_uri', 'http_stat_code',
                     'http_stat_msg', 'http_encode']
CONTENT_TAGS = ['content', 'pcre', 'uricontent']
VALID_DIRECTIONS = ['to server', 'to client']


class Rule(object):
    """
        The Rule class marks the base class for any rule.
        If a rule is to have added features, then this class must
        be extended.  Currently, the rule traffic generator depends
        heavily on this class for generating content.  The rule
        is the cornerstone of generation.  It acts as the ultimate
        keeper of all the defined traffic streams.  Further, each
        TrafficStreamRule may be set to synchronize which means
        that other TrafficStreamRules will not take affect unitl
        after the TrafficStreamRule set to synchronize (and any
        before it) are finished.

        The primary API:

          addTS(TrafficStreamRule ts): This function adds a new
              TrafficStreamRule instance to this particular rule.
              A particular rule may have an arbitrary number of
              TrafficStreamRules attached to it.
          getRuleName(): Return the name for this rule.  Usually just
              a string signifying the type of rule like: Snor Rule.
          getTS(): get a list of the TrafficStreamRules for this
              Rule intance.
          setRuleName(name):  self-explanatory
    """
    def __init__(self, name=None, ts=None):
        self.name = name
        self.ts = []
        if ts is not None:
            if type(ts) is list:
                self.ts.extend(ts)
            else:
                self.ts = [ts]

    def __str__(self):
        mystr = "Rule-Name: "
        if self.name:
            mystr += self.name + "\n"
        else:
            mystr += "None\n"
        for t in self.ts:
            mystr += str(t)
        return mystr

    def addTS(self, stream=None):
        if stream:
            self.ts.append(stream)

    def getRuleName(self):
        return self.name

    def getTS(self):
        return self.ts

    def setRuleName(self, name):
        self.name = name


class RuleParser(object):
    """
        The RuleParser class defines the class that is used to parse
        a set of rules.  This is the class that must be extended to add
        a new parser to the rule reader.  The parser provides the means
        to parse a set of rules as well as the means to test a file to
        see if it fits a particular type of rule.

        The primary API:
            getRules(): return the list of rules for this instance
                of the parser.
            parseRuleFile(filename): This will cause the given filename
                to be parsed according to the methodology set in this
                function and any auxiliary functions.  Rules will be added
                to the list of rules for this instance for every correctly
                parsed rule (could be None).
            testForRuleFile(filename):  This will open the file and read
                it and attempt to discern if it is in the correct format.
                If it is not, it will return false, otherwise it should
                return true.  Note, that for this base class, it always
                returns true because the simplest behavior is to simply
                treat every line as a rule (a content string in this case).

        Building your own parser:
            1. Extend the rule parser class.
            2. Override the testForRuleFile() method and define the
                criteria for identify the particular rulefile for this
                class.
            3. Ovveride the parseRuleFile() method to parse the rule
                file as needed.
                3a. Override the parseRule() method if desired and use
                    it, or add new methods.
                3b.  Use addRule(rule) to add correctly parsed rules
                    to the instance.
    """
    def __init__(self, filename=None):
        self.rules = []
        self.filename = filename

    def addRule(self, rule=None):
        if rule:
            if self.rules:
                self.rules.append(rule)
            else:
                self.rules = [rule]

    def getRules(self):
        return self.rules

    def parseRule(self, line=None):
        basic_rule = Rule("basic")
        ts = TrafficStreamRule()
        mypkt = RulePkt()
        replace_semi = R"\x3b"
        replace_lparen = R"\x28"
        replace_rparen = R"\x29"
        line = re.sub(R"\\;", replace_semi, line)
        line = re.sub(R"\\\(", replace_lparen, line)
        line = re.sub(R"\\\)", replace_rparen, line)
        mycon = RuleContent('pcre', line)
        mypkt.addContent(mycon)
        ts.addPktRule(mypkt)
        basic_rule.addTS(ts)
        self.addRule(basic_rule)

    def parseRuleFile(self, filename=None):
        try:
            self.fd = codecs.open(filename, 'r', encoding='utf-8')
        except Exception as err:
            print("Error reading Basic rule file: Could not open: ",
                  filename)
            print("Error: ", err)
        line = self.fd.readline()
        while line:
            line = line.strip()
            if len(line) > 0 and line[0] != '#':
                self.parseRule(line)
            line = self.fd.readline()
        self.fd.close()

    def testForRuleFile(self, filename=None):
        return True


class RuleContent(object):
    """
        The RuleContent object is a means of storing multiple
        content strings for a single rule.  This is necessary for
        something like Snort Rules which can have multiple content
        and pcre tags for a single rule.

        The content can be a single content string or a list.  The
        type is used to differentiate between pcre and content, though
        it could probably be done away with.  Primarily, this
        is used for setContentString() and getContentString() and is mostly
        a container of convenience.
    """
    def __init__(self, type=None, content=None):
        self.name = "Basic Regex Rule Content"
        self.type = type
        self.content = None
        self.setContentString(content)

    def __str__(self):
        return self.toString()

    def getContentString(self):
        return self.content

    def getName(self):
        return self.name

    def getType(self):
        return self.type

    def setContentString(self, content=None):
        if content:
            self.content = content

    def setType(self, type=None):
        self.type = type

    def toString(self):
        mystr = self.name + "\n"
        mystr += "Type: " + self.type + "\n"
        mystr += "Content: "
        if self.content is None:
            mystr += "None\n"
        else:
            mystr += self.content + "\n"
        return mystr


class RulePkt(object):
    """
        Define individual packet rules.  These rules can play across multiple
        packets.
        Attributes:
          dir: to server or to client.  Indicates the direction of data flow.
                If only one direction is set and traffic is TCP and acks
                are set, then acks will be inserted for the other direction.
          content: regular expression or None.  If None, will generate random
                  data.
          fragment: 0 - 1460.  Number of fragments to break this packet into.
                  0 is default.
          times: 1+.  Number of times to repeat this packet.
          length: -1 == random length if random rule, otherwise length of
                 generated content, 0 = no data, 1+ fixes data length at
                 that value.
          ack_this: Whether or not an ack should be sent for each pkt using
                    this rule.  Only valid for TCP, will send one ack for
                    every pkt sent using this rule (though out of order
                    packets are sent in bursts).
          ooo: Out-of-order packets.  When used at this level, will
               send the pkts created by this rule in a random order.
               Resends will occur as needed, and duplicate ACKs will be sent
               if turned on.  This only works if the pkt rule is set to
               send more than one packet.  Thus, the times, or fragment,
               variable must be greater than 1.
          split: Similar to fragment, but rather than splitting up the whole
                 datagram, this splits up the content and places it into
                 the designated number of packets.  If the value for split
                 is larger than the size of the content, then it will default
                 to the size of the content.  By default this value is zero
                 implying that content will remain in one packet.  Use of
                 this with IP fragments has not been tested.
    """
    def __init__(self, dir="to server", content=None, fragment=0, times=1,
                 length=-1, ack_this=False, ooo=False, split=0):
        self.dir = dir
        self.content = None
        if content:
            self.addContent(content)
        self.fragment = fragment
        self.times = times
        self.length = length
        self.ack_this = ack_this
        self.ooo = ooo
        self.split = split
        if self.fragment > 1 and ooo:
            self.ooo = True

    def __str__(self):
        mystr = "Pkt--Dir: "
        mystr += self.dir
        mystr += "\nContent: "
        if self.content:
            for c in self.content:
                mystr += "  " + str(c)
        else:
            mystr += "  None"
        mystr += "\nFragments: "
        mystr += str(self.fragment)
        mystr += ", Times: "
        mystr += str(self.times)
        mystr += ", Length: "
        mystr += str(self.length)
        mystr += ", Ack This: "
        mystr += str(self.ack_this)
        mystr += ", OOO: "
        mystr += str(self.ooo)
        mystr += ", Split: "
        mystr += str(self.split)
        mystr += "\n"
        return mystr

    # accessors
    def ackThis(self):
        return self.ack_this

    def getContent(self):
        return self.content

    def getDir(self):
        return self.dir

    def getFragment(self):
        return self.fragment

    def getLength(self):
        return self.length

    def getOutOfOrder(self):
        return self.ooo

    def getSplit(self):
        return self.split

    def getTimes(self):
        return self.times

    # mutators
    def addContent(self, con=None):
        if con:
            tempcon = None
            if isinstance(con, str):
                tempcon = RuleContent('pcre', con)
            else:
                tempcon = con
            if self.content:
                self.content.append(tempcon)
            else:
                self.content = [tempcon]

    def setAckThis(self, a=False):
        self.ack_this = a

    def setDir(self, d="to server"):
        self.dir = d

    def setFragment(self, f=0):
        self.fragment = f

    def setLength(self, l=-1):
        self.length = l

    def setOOO(self, o=False):
        self.ooo = o

    def setSplit(self, s=0):
        self.split = s

    def setTimes(self, times=1):
        self.times = times


class TrafficStreamRule(object):
    """
        The TrafficStreamRule defines all of the particulars
        necessary to build a traffic stream in the rule traffic
        generator.  A rule is parsed from its text format, into
        a TrafficStreamRule.  The variables set in the
        TrafficStreamRule then define the ranges of possibility
        in the creation of the actual traffic.  For example, a
        src_ip of 'any' means that any actual traffic stream for
        that particular TrafficStreamRule will have a randomly
        selected source IP address from the entire space of
        total IP addresses.

        Aside from the accessors and mutators to this class,
        there are a few points of interest.  First, the content
        for a stream can be a series of RulePkts that define
        the actual traffic specifically or just within boundaries.
        Secondly, the synch variable is used as a stopping point
        from adding new streams durring processing.  For example,
        If a Rule has five TrafficStreamRules and the third such
        rule is set to synch (i.e. synch is true).  Then durring
        traffic generation, the first three rules will generate
        all of their packets and finish.  When that is done,
        the remaining two will start.  The synch option allows
        for making certain that one traffic stream happens before
        another.  The out-of-order and packet loss options are
        currently best effort.

        This class may be extended to add new features.  However,
        new features will have no effect until they are implemented
        in the ruletrafficgenerator.
    """
    def __init__(self, proto="any", sip="$EXTERNAL_NET", dip="$HOME_NET",
                 sport="any", dport="any", len=-1, ipv=4, synch=False,
                 handshake=False, teardown=False, ooo=False,
                 ooo_prob=50, loss=0, flow="to server"):
        self.proto = proto
        self.src_ip = sip
        self.dst_ip = dip
        self.sport = sport
        self.dport = dport
        self.len = len
        self.ipv = ipv
        self.flow = flow
        self.synch = synch
        self.teardown = teardown
        self.handshake = handshake
        self.ooo = False
        self.ooo_prob = ooo_prob
        self.loss = loss
        self.content = []

    def __str__(self):
        mystr = "Traffic Stream Rule\n"
        mystr += "Packet lengths are: "
        if self.len < 0:
            mystr += "based on content length\n"
        else:
            mystr += "Fixed at " + str(self.len) + " bytes\n"
        mystr += "IP Version: " + str(self.ipv) + "\n"
        mystr += "Protocol: " + self.proto + "\n"
        mystr += "Src IP: " + self.src_ip + "\n"
        mystr += "Dst IP: " + self.dst_ip + "\n"
        mystr += "Src Port: " + self.sport + "\n"
        mystr += "Dst Port: " + self.dport + "\n"
        mystr += "flow: " + self.flow + "\n"
        if self.synch:
            mystr += "Synchronized Stream.\n"
        else:
            mystr += "Asynchronous Stream.\n"
        if self.handshake:
            mystr += "Including TCP handshake.\n"
        if self.teardown:
            mystr += "Including TCP Teardwon.\n"
        if self.ooo:
            mystr += "Using Out-of-Order packets.\n"
            mystr += "Out-of-Order packet probability: " + \
                     str(self.ooo_prob) + "\n"
        if self.loss > 0:
            mystr += "Packet loss at " + str(self.loss) + " percent.\n"
        mystr += "  Packets:\n"
        for p in self.content:
            mystr += str(p)
        return mystr

    # accessors
    def getDport(self):
        return self.dport

    def getDstIp(self):
        return self.dst_ip

    def getFlowOptions(self):
        return self.flow

    def getHandshake(self):
        return self.handshake

    def getIPV(self):
        return self.ipv

    def getLength(self):
        return self.len

    def getOOOProb(self):
        return self.ooo_prob

    def getOutOfOrder(self):
        return self.ooo

    def getPacketLoss(self):
        return self.loss

    def getPkts(self):
        return self.content

    def getProto(self):
        return self.proto

    def getSport(self):
        return self.sport

    def getSrcIp(self):
        return self.src_ip

    def getSynch(self):
        return self.synch

    def getTeardown(self):
        return self.teardown

    # mutators
    def addPktRule(self, pktrule=None):
        if pktrule:
            if self.content:
                self.content.append(pktrule)
            else:
                self.content = [pktrule]

    def setDPort(self, p="any"):
        self.dport = p

    def setDstIp(self, ip="any"):
        self.dst_ip = ip

    def setFlowOptions(self, f="to server"):
        self.flow = f

    def setHandshake(self, h=False):
        self.handshake = h

    def setIPV(self, ipv=4):
        self.ipv = ipv

    def setLen(self, len=-1):
        self.len = len

    def setOOOProb(self, op=50):
        self.ooo_prob = op

    def setOOO(self, o=False):
        self.ooo = o

    def setPacketLoss(self, l=0):
        self.loss = l

    def setProto(self, p="any"):
        self.proto = p

    def setSPort(self, p="any"):
        self.sport = p

    def setSrcIp(self, ip="any"):
        self.src_ip = ip

    def setSynch(self, s=True):
        self.synch = s

    def setTeardown(self, td=False):
        self.teardown = td


class SnortRuleContent(RuleContent):
    def __init__(self, type=None, content=None):
        self.name = "Snort Rule Content"
        self.type = type
        self.content = None
        self.distance = None
        self.offset = None
        self.depth = None
        self.within = None
        self.fast_pattern = None
        self.nocase = None
        self.http_client_body = None
        self.http_cookie = None
        self.http_raw_cookie = None
        self.http_header = None
        self.http_raw_header = None
        self.http_method = None
        self.http_uri = None
        self.http_raw_uri = None
        self.http_start_code = None
        self.http_start_msg = None
        self.http_encode = None
        if content is not None:
            self.handleContent(content)

    def __str__(self):
        mystr = self.name + "\n"
        mystr += "  type: " + self.type + "\n"
        mystr += "  content: " + str(self.content) + "\n"
        if self.distance:
            mystr += "  distance: " + str(self.distance) + "\n"
        if self.offset:
            mystr += "  offset: " + str(self.offset) + "\n"
        if self.depth:
            mystr += "  depth: " + str(self.depth) + "\n"
        if self.within:
            mystr += "  within: " + str(self.within) + "\n"
        if self.fast_pattern:
            mystr += "  fast_pattern\n"
        if self.nocase:
            mystr += "  nocase\n"
        if self.isHTTP():
            mystr += "  This is an http content tag\n"
        if self.http_client_body:
            mystr += "  http_client_body: " + str(self.http_client_body) + "\n"
        if self.http_cookie:
            mystr += "  http_cookie: " + str(self.http_cookie) + "\n"
        if self.http_raw_cookie:
            mystr += "  http_raw_cookie: " + str(self.http_raw_cookie) + "\n"
        if self.http_header:
            mystr += "  http_header: " + str(self.http_header) + "\n"
        if self.http_raw_header:
            mystr += "  http_raw_header: " + str(self.http_raw_header) + "\n"
        if self.http_method:
            mystr += "  http_method: " + str(self.http_method) + "\n"
        if self.http_uri:
            mystr += "  http_uri: " + str(self.http_uri) + "\n"
        if self.http_raw_uri:
            mystr += "  http_raw_uri: " + str(self.http_raw_uri) + "\n"
        if self.http_start_code:
            mystr += "  http_start_code: " + str(self.http_start_code) + "\n"
        if self.http_start_msg:
            mystr += "  http_start_msg: " + str(self.http_start_msg) + "\n"
        if self.http_encode:
            mystr += "  http_encode: " + str(self.http_encode) + "\n"
        return mystr

    # accessors
    def getDistance(self):
        return self.distance

    def getOffset(self):
        return self.offset

    def getDepth(self):
        return self.depth

    def getWithin(self):
        return self.within

    def getFastPattern(self):
        return self.fast_pattern

    def getNocase(self):
        return self.nocase

    def getHttpClientBody(self):
        return self.http_client_body

    def getHttpCookie(self):
        return self.http_cookie

    def getHttpRawCookie(self):
        return self.http_raw_cookie

    def getHttpHeader(self):
        return self.http_header

    def getHttpRawHeader(self):
        return self.http_raw_header

    def getHttpMethod(self):
        return self.http_method

    def getHttpUri(self):
        return self.http_uri

    def getHttpRawUri(self):
        return self.http_raw_uri

    def getHttpStartCode(self):
        return self.http_start_code

    def getHttpStartMsg(self):
        return self.http_start_msg

    def getHttpEncode(self):
        return self.http_encode

    # mutators
    def handleContent(self, con=None):
        if con:
            self.content = con.pop(0)
            while con:
                tag = con.pop(0)
                if tag == 'distance':
                    if con:
                        self.setDistance(int(con.pop(0)))
                elif tag == 'offset':
                    if con:
                        self.setOffset(int(con.pop(0)))
                elif tag == 'depth':
                    if con:
                        self.setDepth(int(con.pop(0)))
                elif tag == 'within':
                    if con:
                        self.setWithin(int(con.pop(0)))
                elif tag == 'fast_pattern':
                    self.setFastPattern(True)
                elif tag == 'nocase':
                    self.setNoCase(True)
                elif tag == 'http_client_body':
                    self.setHttpClientBody(True)
                elif tag == 'http_cookie':
                    self.setHttpCookie(True)
                elif tag == 'http_method':
                    self.setHttpMethod(True)
                elif tag == 'http_raw_cookie':
                    self.setHttpRawCookie(True)
                elif tag == 'http_header':
                    self.setHttpHeader(True)
                elif tag == 'http_raw_header':
                    self.setHttpRawHeader(True)
                elif tag == 'http_uri':
                    self.setHttpUri(True)
                elif tag == 'http_raw_uri':
                    self.setHttpRawUri(True)
                elif tag == 'http_start_code':
                    self.setHttpStartCode(True)
                elif tag == 'http_start_msg':
                    self.setHttpStartMsg(True)

    def isHTTP(self):
        if self.http_client_body or \
           self.http_cookie or \
           self.http_raw_cookie or \
           self.http_header or \
           self.http_raw_header or \
           self.http_method or \
           self.http_uri or \
           self.http_raw_uri or \
           self.http_start_code or \
           self.http_start_msg or \
           self.http_encode:
            return True
        return False

    def setDistance(self, d=0):
        if d < 0:
            d = 0
        self.distance = d

    def setOffset(self, o=0):
        if o < 0:
            o = 0
        self.offset = o

    def setDepth(self, d=0):
        if d < 0:
            d = 0
        self.depth = d

    def setWithin(self, w=0):
        if w < 0:
            w = 0
        self.within = w

    def setFastPattern(self, fp=False):
        self.fast_pattern = fp

    def setNoCase(self, nc=False):
        self.no_case = nc

    def setHttpClientBody(self, h=None):
        if h is not None:
            if self.http_client_body:
                self.http_client_body += h
            else:
                self.http_client_body = h

    def setHttpCookie(self, h=None):
        if h is not None:
            if self.http_cookie:
                self.http_cookie += h
            else:
                self.http_cookie = h

    def setHttpRawCookie(self, h=None):
        if h is not None:
            if self.http_raw_cooked:
                self.http_raw_cookie += h
            else:
                self.http_raw_cookie = h

    def setHttpHeader(self, h=None):
        if h is not None:
            if self.http_header:
                self.http_header += h
            else:
                self.http_header = h

    def setHttpRawHeader(self, h=None):
        if h is not None:
            if self.http_raw_header:
                self.http_raw_header += h
            else:
                self.http_raw_header = h

    def setHttpMethod(self, h=None):
        if h is not None:
            if self.http_method:
                self.http_method += h
            else:
                self.http_method = h

    def setHttpUri(self, h=None):
        if h is not None:
            if self.http_uri:
                self.http_uri += h
            else:
                self.http_uri = h

    def setHttpRawUri(self, h=None):
        if h is not None:
            if self.http_raw_uri:
                self.http_raw_uri += h
            else:
                self.http_raw_uri = h

    def setHttpStartCode(self, h=None):
        if h is not None:
            if self.http_start_code:
                self.http_start_code += h
            else:
                self.http_start_code = h

    def setHttpStartMsg(self, h=None):
        if h is not None:
            if self.http_start_msg:
                self.http_start_msg += h
            else:
                self.http_start_msg = h

    def setHttpEncode(self, h=None):
        if h is not None:
            if self.http_encode:
                self.http_encode += h
            else:
                self.http_encode = h


class SnortRuleParser(RuleParser):

    def __init__(self, filename=None):
        self.filename = None
        self.rules = []

    def parseHeader(self, line=None, ts=None):
        if line and ts:
            header = line.partition("(")[0]
            values = header.split()
            ts.proto = values[1].lower()
            ts.src_ip = values[2]
            ts.sport = values[3]
            ts.dst_ip = values[5]
            ts.dport = values[6]

    def parseOptions(self, line, snort_ts):
        options = line.partition("(")[2]
        values = options.split(";")
        mypkt = RulePkt()
        row = []
        next = values.pop(0)
        while values:
            tag = None
            value = None
            if next.find(":") > -1:
                sections = next.partition(":")
                tag = sections[0].lower().strip()
                value = sections[2].strip()
            else:
                tag = next.lower().strip()
            if value:
                if value[0:1] == '"':
                    value = value[1:-1]
            if tag in CONTENT_TAGS:
                if len(row) > 0:
                    mypkt.addContent(SnortRuleContent(row[0], row[1:]))
                    row = []
                if tag == 'uricontent':
                    tag = 'content'
                    row.append(tag)
                    row.append(value)
                    row.append('http_uri')
                else:
                    row.append(tag)
                    if value:
                        row.append(value)
            elif tag in CONTENT_MODIFIERS:
                row.append(tag)
                if value:
                    row.append(value)
            else:
                pass
            if values:
                next = values.pop(0)
        if len(row) > 0:
            mypkt.addContent(SnortRuleContent(row[0], row[1:]))
        snort_ts.addPktRule(mypkt)

    def parseRule(self, rule=None):
        if rule:
            snort_rule = Rule("Snort")
            snort_ts = TrafficStreamRule()
            replace_semi = R"\x3b"
            replace_lparen = R"\x28"
            replace_rparen = R"\x29"
            rule = re.sub(R"\\;", replace_semi, rule)
            rule = re.sub(R"\\\(", replace_lparen, rule)
            rule = re.sub(R"\\\)", replace_rparen, rule)
            self.parseHeader(rule, snort_ts)
            self.parseOptions(rule, snort_ts)
            snort_rule.addTS(snort_ts)
            self.addRule(snort_rule)

    def parseRuleFile(self, filename=None):
        self.openSnortFile(filename)
        line = self.fd.readline()
        while line:
            line = line.strip()
            if len(line) > 0 and line[0] != '#':
                self.parseRule(line)
            line = self.fd.readline()
        self.fd.close()

    def testForRuleFile(self, filename=None):
        is_snort_rule_file = False
        snort_rule_sig = re.compile(
            "\\s*(alert|log|pass|activate|dynamic|reject|drop|sdrop)" +
            "\\s+\\w+\\s+[\\w$]+\\s+[\\w$]+\\s+<?->\\s+[\\w$]+\\s+[\\w$]+" +
            "\\s*\\([^)]+\\)")
        self.openSnortFile(filename)
        line = self.fd.readline()
        while line:
            line = line.strip()
            if len(line) > 0 and line[0] != '#':
                if snort_rule_sig.match(line):
                    is_snort_rule_file = True
                    break
            line = self.fd.readline()
        self.fd.close()
        return is_snort_rule_file

    def openSnortFile(self, filename):
        try:
            self.fd = codecs.open(filename, 'r', encoding='utf-8')
        except Exception as err:
            print("Error reading Snort rule file: Could not open: ",
                  filename)
            print("Error: ", err)
            return False
        return True


class PetabiRuleParser(RuleParser):
    def getRules(self):
        return self.rules

    def parseRuleFile(self, filename=None):
        tree = None
        try:
            tree = ET.parse(filename)
        except Exception as err:
            print(err)
            return False
        root = tree.getroot()

        for xmlrule in root.iter('rule'):
            myprule = Rule('Petabi')
            for ts in xmlrule.iter('traffic_stream'):
                mytsrule = TrafficStreamRule()
                if 'proto' in ts.attrib:
                    mytsrule.setProto(ts.attrib['proto'])
                if 'src' in ts.attrib:
                    mytsrule.setSrcIp(ts.attrib['src'])
                if 'dst' in ts.attrib:
                    mytsrule.setDstIp(ts.attrib['dst'])
                if 'sport' in ts.attrib:
                    mytsrule.setSPort(ts.attrib['sport'])
                if 'dport' in ts.attrib:
                    mytsrule.setDPort(ts.attrib['dport'])
                if 'synch' in ts.attrib:
                    if ts.attrib['synch'].lower() == 'false':
                        mytsrule.setSynch(False)
                if 'handshake' in ts.attrib:
                    if ts.attrib['handshake'].lower() == 'true':
                        mytsrule.setHandshake(True)
                if 'teardown' in ts.attrib:
                    if ts.attrib['teardown'].lower() == 'true':
                        mytsrule.setTeardown(True)
                if 'ipv' in ts.attrib:
                    if int(ts.attribg['ipv']) == 6:
                        mytsrule.setIPV(6)
                if 'out_of_order' in ts.attrib:
                    if ts.attrib['out_of_order'].lower() == 'true':
                        mytsrule.setOOO(True)
                if 'out_of_order' in ts.attrib and \
                   'out_of_order_prob' in ts.attrib:
                    if int(ts.attrib['out_of_order_prob']) > 0 and \
                       int(ts.attrib['out_of_order_prob']) < 100:
                        mytsrule.setOOOProb(
                            int(ts.attrib['out_of_order_prob']))
                if 'packet_loss' in ts.attrib:
                    if int(ts.attrib['packet_loss']) > 0:
                        mytsrule.setPacketLoss(int(ts.attrib['packet_loss']))

                for pkt in ts.iter('pkt'):
                    mypkt = RulePkt()
                    if 'ack' in pkt.attrib:
                        if pkt.attrib['ack'].lower() == 'true':
                            mypkt.setAckThis(True)
                    if 'dir' in pkt.attrib:
                        if pkt.attrib['dir'].lower() in VALID_DIRECTIONS:
                            mypkt.setDir(pkt.attrib['dir'].lower())
                        else:
                            print("You have designated an invalid direction.")
                            print("Direction should be to server or to"
                                  "client.")
                    if 'content' in pkt.attrib:
                        mycon = RuleContent('pcre', pkt.attrib['content'])
                        mypkt.addContent(mycon)
                    if 'fragment' in pkt.attrib:
                        if int(pkt.attrib['fragment']) > 0:
                            mypkt.setFragment(int(pkt.attrib['fragment']))
                    if 'times' in pkt.attrib:
                        if int(pkt.attrib['times']) > 1:
                            mypkt.setTimes(int(pkt.attrib['times']))
                    if 'length' in pkt.attrib:
                        if int(pkt.attrib['length']) > -1:
                            mypkt.setLength(int(pkt.attrib['length']))
                    if 'out_of_order' in pkt.attrib:
                        if pkt.attrib['out_of_order'].lower() == 'true':
                            mypkt.setOOO(True)
                    if 'split' in pkt.attrib:
                        if int(pkt.attrib['split']) > 0:
                            mypkt.setSplit(int(pkt.attrib['split']))
                    mytsrule.addPktRule(mypkt)
                myprule.addTS(mytsrule)
            self.addRule(myprule)

    def testForRuleFile(self, filename=None):
        tree = None
        try:
            tree = ET.parse(filename)
        except Exception as err:
            # print(err)
            return False
        root = tree.getroot()
        if root.tag == 'petabi_rules':
            return True
        return False


class RuleList:
    """
        RuleList class
            Reads and maintains a list of Snort rules.

            -readRuleFile(file) will read all rules within a file.  It
                is assumed that a valid parser exists.  If not, then
                the catch-all parser will be used which will simply
                treat every line as a rule.

            -readRuleFiles(directory): will read all rule files in
                a directory.  Assumes that all rule files have the name
                rules in them.
                *Note: this will be made a variable in the future.*

            -getParsedRules(): will return the list of all parsed rules.

            Note: The findParser(filename): function will iteratively
                attempt every know rule parser until it finds one
                that tests positively for the given file.  At that
                point it automatically assumes that is the right
                parser.  When extending parsers you should keep this
                in mind.
    """
    def __init__(self):
        self.all_rules = []

    def __str__(self):
        if self.all_rules:
            mystr = ""
            for rule in self.all_rules:
                mystr += str(rule)
            return mystr
        else:
            return "None"

    def getParsedRules(self):
        return self.all_rules

    def findParser(self, filename=None):
        if filename:
            for p in RuleParser.__subclasses__():
                myp = p()
                if myp.testForRuleFile(filename):
                    return myp
        return RuleParser()

    def readRuleFile(self, filename=None):
        if filename:

            # Note: findParser is called multiple times if readRuleFiles()
            # is used.  This is purposeful, as it allows for each of the
            # rule files to be in a different format.
            parser = self.findParser(filename)
            parser.parseRuleFile(filename)
            if parser.getRules():
                if self.all_rules:
                    self.all_rules.extend(parser.getRules())
                else:
                    self.all_rules = parser.getRules()

    def readRuleFiles(self, dirname=None):
        if dirname is None:
            print("Defaulting to current directory")
            dirname = "./"
        try:
            for f in listdir(dirname):
                if isfile(join(dirname, f)):
                    if f.find("rules") >= 0:
                        self.readRuleFile(join(dirname, f))
        except:
            print("Error: Could not read from directory: ", dirname)
            sys.exit(1)
