import re
import sys
import getopt
import os
import datetime
import calendar
import time
from os.path import normcase, join
from sniffles.rulereader import *
from sniffles.ruletrafficgenerator import *
from pkg_resources import get_distribution, DistributionNotFound


def getVersion():
    version = 0
    try:
        _dist = get_distribution('sniffles')
        dist_loc = os.path.normcase(_dist.location)
        here = os.path.normcase(__file__)
        if not here.startswith(os.path.join(dist_loc, 'sniffles')):
            raise DistributionNotFound
    except DistributionNotFound:
        version = '1.3.3'  # first version using this check.
    else:
        version = _dist.version
    return version


class SnifflesConfig(object):
    """
    Class SnifflesConfig:
      The Configuration object for Sniffles.  This object holds the
      global options for a particular test run of Sniffles.
    """

    def __init__(self, cmd=None):
        self.bi = False
        self.concurrent_flows = 1000
        self.config_file = None
        self.eval = False
        self.full_eval = False
        self.full_match = False
        self.intensity = 1
        self.ipv4_home = None
        self.ipv6_home = None
        self.ipv6_percent = 0
        self.mac_addr_def = None
        self.output_file = "sniffles.pcap"
        self.pcap_start_sec = int(calendar.timegm(time.gmtime()))
        self.pkt_length = -1
        self.pkts_per_stream = 1
        self.rand = False
        self.rule_dir = None
        self.rule_file = None
        self.scan = False
        self.scan_duration = 1
        self.scan_offset = 0
        self.scan_randomize_offset = False
        self.scan_targets = []
        self.scan_type = SYN_SCAN
        self.scan_reply_chance = OPEN_PORT_CHANCE
        self.target_ports = []
        self.tcp_ack = False
        self.tcp_handshake = False
        self.tcp_teardown = False
        self.time_lapse = 1
        self.total_streams = 1
        self.traffic_duration = 0
        self.verbosity = False
        self.version = 0
        self.write_reg_ex = False
        self.split_file = None
        self.is_sqllite_db = False

        if cmd:
            self.parse_cmd(cmd)

    def __str__(self):
        mystr = "Sniffles Configuration: \n"
        if self.bi:
            mystr += "  Bi-directional content generation is turned on.\n"
        if self.config_file:
            mystr += "  Using a configuration file: " + self.config_file + \
                     ".\n"
        if self.rule_file:
            mystr += "  Using the rule file: " + self.rule_file + ".\n"
        if self.rule_dir:
            mystr += "  Using all .rules files in dir: " + self.rule_dir + \
                     ".\n"
        mystr += "  Output file is: " + self.output_file + ".\n"
        if self.eval or self.full_eval:
            if self.full_eval:
                mystr += "  A full "
            else:
                mystr += "  An "
            mystr += "evaluation pcap is being generated.\n"
            mystr += "  All other options except the ruleset are irrelevant.\n"
            return mystr
        if self.full_match:
            mystr += "  Data-bearing content will match fully to a rule.\n"
        elif not self.rand:
            mystr += "  Data-bearing content will almost match to a rule.\n"
        else:
            mystr += "  Data-bearing content will be uniformly random chars.\n"
        mystr += "  Percent of IPv6 packets is: " + str(self.ipv6_percent) + \
                 "%.\n"
        if self.ipv4_home:
            mystr += "  IPv4 Home addresses are: " + str(self.ipv4_home) + \
                     ".\n"
        if self.ipv6_home:
            mystr += "  IPv6 Home addresses are: " + str(self.ipv6_home) + \
                     ".\n"
        if self.tcp_handshake:
            mystr += "  TCP handshakes will be included in the pcap.\n"
        if self.tcp_teardown:
            mystr += "  TCP teardown sequences will be inlcuded in the pcap.\n"
        if self.tcp_ack:
            mystr += "  TCP acknowledgements will be sent.\n"

        if self.scan:
            mystr += "  Will insert Scan attacks into the pcap.\n"
            mystr += "    Scan intensity: " + str(self.intensity) + ".\n"
            mystr += "    Scan Duration: " + str(self.scan_duration) + ".\n"
            mystr += "    Scan Offset: " + str(self.scan_offset) + ".\n"
            mystr += "    Scan Targets: " + str(self.scan_targets) + ".\n"
            if self.scan_type == SYN_SCAN:
                mystr += "    SYN scan.\n"
            elif self.scan_type == CONNECTION_SCAN:
                mystr += "    Connection Scan.\n"
            else:
                mystr += "    Unknown scan type...How did that happen?\n"
            mystr += "    Scan Reply Chance: " + str(self.scan_reply_chance) + \
                     ".\n"
            mystr += "    Scan target ports: " + str(self.target_ports) + ".\n"

        if self.traffic_duration > 0:
            mystr += "  Generating traffic for " + str(self.traffic_duration) + \
                     "seconds\n"
        else:
            mystr += "  Generating " + str(self.total_streams) + \
                     " total streams.\n"
        if self.pkts_per_stream < 0:
            mystr += "  Generating an average of " + \
                str(abs(self.pkts_per_stream))
            mystr += " data-bearing packets per stream.\n"
        else:
            mystr += "  Generating " + str(self.pkts_per_stream) + \
                " data-bearing packet per stream.\n"
        if self.time_lapse > 1:
            mystr += "  An average of " + str(self.time_lapse) + \
                     " microsecond delay between each packet.\n"
        else:
            mystr += "  One microsecond delay between packets.\n"
        if self.pkt_length >= 0:
            mystr += "  Data-bearing packets will have " + str(self.pkt_length)
            mystr += " bytes of content.\n"
        else:
            mystr += "  Data-bearing packets have between 10 and 1500" \
                     " bytes of content.\n"
        if not self.eval and not self.full_eval:
            mystr += "  Will generate at " + str(self.concurrent_flows)
            mystr += " concurrent flows when possible."
        mystr += "\n  Starting timestamp: " + str(self.pcap_start_sec) + \
            " seconds or: " + str(datetime.datetime.fromtimestamp(
                self.pcap_start_sec)) + "\n"
        return mystr

    def getBi(self):
        return self.bi

    def getConcurrentFlows(self):
        return self.concurrent_flows

    def getEval(self):
        return self.eval

    def getFirstTimestamp(self):
        return self.pcap_start_sec

    def getFullEval(self):
        return self.full_eval

    def getFullMatch(self):
        return self.full_match

    def getIntensity(self):
        return self.intensity

    def getIPV4Home(self):
        return self.ipv4_home

    def getIPV6Home(self):
        return self.ipv6_home

    def getIPV6Percent(self):
        return self.ipv6_percent

    def getMacAddrDef(self):
        return self.mac_addr_def

    def getOutputFile(self):
        return self.output_file

    def getPktLength(self):
        return self.pkt_length

    def getPktsPerStream(self):
        return self.pkts_per_stream

    def getRandom(self):
        return self.rand

    def getRuleDir(self):
        return self.rule_dir

    def getRuleFile(self):
        return self.rule_file

    def getScan(self):
        return self.scan

    def getScanDuration(self):
        return self.scan_duration

    def getScanOffset(self):
        return self.scan_offset

    def getRandomizeOffset(self):
        return self.scan_randomize_offset

    def getScanTargets(self):
        return self.scan_targets

    def getScanType(self):
        return self.scan_type

    def getScanReplyChance(self):
        return self.scan_reply_chance

    def getSplitFile(self):
        return self.split_file

    def getSQLLiteDB(self):
        return self.is_sqllite_db

    def getTargetPorts(self):
        return self.target_ports

    def getTCPACK(self):
        return self.tcp_ack

    def getTCPHandshake(self):
        return self.tcp_handshake

    def getTCPTeardown(self):
        return self.tcp_teardown

    def getTimeLapse(self):
        return self.time_lapse

    def getTotalStreams(self):
        return self.total_streams

    def getTrafficDuration(self):
        return self.traffic_duration

    def getVerbosity(self):
        return self.verbosity

    def getWriteRegEx(self):
        return self.write_reg_ex

    def parse_cmd(self, cmd):
        cmd_options = "abc:C:d:D:eEf:F:g:h:H:i:I:l:L:" + \
                      "mM:o:O:p:P:rRs:S:tTvwW:x:zZ:?"
        try:
            options, args = getopt.getopt(cmd, cmd_options, [])
        except getopt.GetoptError as err:
            print("Error reading command line: ", err)
            self.usage()
        for opt, arg in options:
            self.parse_opt_arg(opt, arg)

    def parse_config_file(self, cfg_file=None):
        if cfg_file:
            print("Reading config file: ", cfg_file)
            try:
                fd = open(cfg_file, 'r')
            except:
                print("Error: Could not open provided config file: ", filename)
                sys.exit(1)
            line = fd.readline()

            while line:
                line = line.strip()
                if len(line) > 0 and line[0] != '#':
                    try:
                        opt, arg = line.split('=')
                    except Exception as err:
                        print("Could not parse line in config file: ", line)
                        print("Error: ", err)
                        sys.exit(1)
                    opt = opt.strip()
                    arg = arg.strip()
                    self.parse_opt_arg(opt, arg)
                line = fd.readline()
            fd.close()

    def parse_opt_arg(self, opt, arg):
        if opt == "-a":
            self.tcp_ack = True
        elif opt == "-b":
            self.bi = True
            self.tcp_ack = True
        elif opt == "-c":
            self.total_streams = int(arg)
            if self.total_streams < 1:
                print("Must designate one or more streams to create.")
                self.usage()
        elif opt == "-C":
            if int(arg) > 0:
                self.concurrent_flows = int(arg)
        elif opt == "-d":
            self.rule_dir = arg
        elif opt == "-D":
            if int(arg) > 0:
                self.traffic_duration = int(arg)
        elif opt == "-e":
            self.eval = True
        elif opt == "-E":
            self.full_eval = True
        elif opt == "-f":
            self.rule_file = arg
        elif opt == "-F":
            self.config_file = arg
            self.parse_config_file(arg)
        elif opt == "-g":
            if self.pcap_start_sec > 0:
                self.pcap_start_sec = int(arg)
        elif opt == "-h":
            self.ipv4_home = [temp.strip() for temp in arg.split(",")]
        elif opt == "-H":
            self.ipv6_home = [temp.strip() for temp in arg.split(",")]
        elif opt == "-i":
            self.ipv6_percent = int(arg)
            if self.ipv6_percent > 100 or self.ipv6_percent < 1:
                print("IPv6 percentage must be between 1 and 100 to be set.")
                self.usage()
        elif opt == "-I":
            if int(arg) > 0:
                self.intensity = int(arg)
        elif opt == "-l":
            self.pkt_length = int(arg)
        elif opt == "-L":
            if int(arg) > 1:
                self.time_lapse = int(arg)
        elif opt == "-m":
            self.full_match = True
        elif opt == "-M":
            self.mac_addr_def = arg
        elif opt == "-o":
            self.output_file = arg
        elif opt == "-O":
            if float(arg) > 0:
                self.scan_offset = float(arg)
        elif opt == "-p":
            self.pkts_per_stream = int(arg)
        elif opt == "-P":
            self.target_ports = arg.split(',')
        elif opt == "-r":
            self.rand = True
        elif opt == "-R":
            self.scan_randomize_offset = True
        elif opt == "-s":
            self.scan = True
            self.scan_targets = arg.split(',')
        elif opt == "-S":
            if int(arg) in range(1, 2):
                self.scan_type = int(arg)
        elif opt == "-t":
            self.tcp_handshake = True
        elif opt == "-T":
            self.tcp_teardown = True
        elif opt == "-v":
            self.verbosity = True
        elif opt == "-w":
            self.write_reg_ex = True
        elif opt == "-W":
            if int(arg) > 1:
                self.scan_duration = int(arg)
        elif opt == "-x":
            self.split_file = arg
        elif opt == "-z":
            self.is_sqllite_db = True
        elif opt == "-Z":
            if int(arg) > 0 and int(arg) <= 100:
                self.scan_reply_chance = int(arg)
        elif opt == "-?":
            self.usage()
        else:
            print("Unrecognized Option: ", opt)
            self.usage()

    def usage(self):
        print("Sniffles--Traffic Generator for testing IDS")
        print("usage: ./sniffles [-d dir | -f file] [-c count]")
        print(" [-C # concurrent flows] [-D traffic duration] [-F config]")
        print(" [-h \"comma-sep list\"] [-H \"comma-sep list\"]")
        print(" [-i ipv6 chance] [-I scan intensity]")
        print(" [-l pkt_length] [-L time lapse] [-M mac_addr_def file]")
        print(" [-o output_file] [-O scan start offset] [-p pkts_per_stream]")
        print(" [-P scan port(s)] [-s scan target(s)] [-S scan type]")
        print(" [-W scan window] [-z sql file] [-Z Reply %] [-abeEmrRtTvwx]")
        print("")
        print("-a TCP Ack: Send a TCP acknowledgment for every data packet")
        print("   sent.  Off by default.")
        print("-b Bi-directional data: Send data in both directions.")
        print("   Off by default.  Automatically set TCP acks.")
        print("-c Count: Number of streams to create.  Each stream will")
        print("   contain a minimum of 1 packet.  Packet will be between")
        print("   two end-points as defined by the rule or randomly chosen.")
        print("   tcp_handshake, tcp_teardown, and packets_per_stream will")
        print("   increase the number of packets per stream.")
        print("-C Concurrent Flows: Number of flows that will be open at one")
        print("   time.  Best effort in that if there are fewer flows than")
        print("   the number of concurrent flows designated then all of the")
        print("   current flows will be used.  For example, if there are only")
        print("   1000 flows remaining, but the number of concurrent flows")
        print("   was set to 10000, still only 1000 flows will be written out")
        print("   at that time.  The default value is 1000.  If used with")
        print("   duration the -C flows will be maintained throughout the")
        print("   duration which will ultimately disregard any input from -c.")
        print("-d Rules Directory: path to directory containing rule")
        print("   files.  Will read every enabled rule in all rules file in")
        print("   the directory.  Assumes all rules end with extension")
        print("   .rules.  Use this option or -f, but not both.")
        print("-D Duration: Generate based on duration rather than")
        print("   on count.  This will disregard the -c input.")
        print("-f Rule File: read a single rule file as per the provided")
        print("   path and file name. A rule file may be an infnis rules.xml,")
        print("   a list of regular expressions (one to a row), or a snort")
        print("   rule file.")
        print("-e eval: Create just one packet for each rule in the")
        print("   rule-set with data matching to that rule.")
        print("   Ignores all other options except -f.")
        print("-E Full Eval: Create one packet for each viable path in")
        print("   a pcre rule in the rule set.  In other words ab(c|d)e would")
        print("   create two packets with data: abce and abde respectively.")
        print("   Ignores all other options except -f.")
        print("-F Config: Designate a config file for Sniffles options.  The")
        print("   config file fixes the parameters used for a run")
        print("   of Sniffles.")
        print("-g Start timestamp: set the second for the starting timestamp")
        print("   in the capture.  All other timestamps are derived from")
        print("   this value.  The default is the current time (in seconds).")
        print("-h IP Home Prefixes: A list of IP Home Network Prefixes.")
        print("   IP addresses meant to come from an internal address will")
        print("   use these prefixes.  Prefixes may desginate an entire, or")
        print("   partial 4 byte IPv4 address in xxx.xxx format.")
        print("   For example: \"10.192.168.,172.16\".")
        print("-H IP v6 Home Prefixes: Same as IPv4 Home Prefixes just")
        print("   for IPv6.  Notable exceptions, the separator is a colon")
        print("   with two bytes represented between colons.")
        print("-i IPv6 percentage: Set this value between 1 and 100 to ")
        print("   generate packets with IPv6 packets.  This will determine")
        print("   the percentage of streams that will be IPv6.  By default,")
        print("   all streams are IPv4.")
        print("-I Intensity of scan attack (i.e. scan packets per second).")
        print("-l Content Length: Fix the Content length to the number of")
        print("   bytes designated. Less than one will set the length equal")
        print("   to the content generated by nfa, or a random number between")
        print("   10 and 1410 if random.  This length is applied to all data")
        print("   bearing packets.")
        print("-L Lapse: Time lapse between packets (microsecs). Default")
        print("   is 1us. A value larger than 1 here will cause a random time")
        print("   lapse between packets with the value as the average.")
        print("-m Full match: Fully match rules.  By default, generated")
        print("   content will only partially match rules, thus alerts")
        print("   should not be generated (not guaranteed though).")
        print("-o output file: designate the name of the output file.")
        print("   by default, the file is named: sniffles.pcap.")
        print("-O Offset: Offset before starting a scan attack.")
        print("   If used with the -R option this becomes the")
        print("   offset for each new attack after the last attack")
        print("   has finished.")
        print("-p Packets-per-stream: designate the number of ")
        print("   content-bearing packets for a single stream.")
        print("   If the value is a positive integer, then this is the exact")
        print("   number of content-bearing packets that will appear in the")
        print("   streams. If the number is a negative integer, then a random")
        print("   number of packets will be chosen between 1 and abs(x)")
        print("   where x is the provided negative integer. If not set, each")
        print("   stream will have exactly 1 data-bearing packet.")
        print("-P Target Port list: For a scan attack. Provide a comma-sep")
        print("   list of possible ports, or a single starting port.")
        print("   Otherwise ports will be scanned at random.")
        print("   If a single port is provided, then ports are sequentially")
        print("   scanned from that point onward, returning to the starting")
        print("   port after 65535 is reached.")
        print("-r Random: Generate random content rather than from the")
        print("   rules.  If rules are still provided, the rules are used")
        print("   in the generation of the headers if they provide headers")
        print("   (like in Snort rules.")
        print("-R Random Syn Attacks: Will use the Offset to create scan")
        print("   attacks in the traffic, but will use the offset only as a")
        print("   median.  When all scan attacks are finished, more scans")
        print("   will be created unitl the duration is finished.")
        print("-s Scan Attack: followed by a comma-sep list of ipv4 addrs")
        print("   indicating what ip address to target.  Each IP range will")
        print("   create will create one scan attack.  The ranges should be")
        print("   like: 192.168.1.1 which would target exactly that one")
        print("   ip address while 192.168.1 would target one ip addresses ")
        print("   from between 192.168.1.0 and 192.168.1.255.")
        print("-S Scan type: 1==Syn scan (default) 2 == Connection scan.")
        print("-t TCP Handshake: Include a TCP handshake in all TCP")
        print("   streams.  Off by default.")
        print("-T TCP Teardown: Include a TCP teardown in all TCP")
        print("   streams.  Off by default.")
        print("-v Verbosity: Increase the level of output messages.")
        print("-w write content: Write the content strings to a file")
        print("   called \'all.re\'.")
        print("-W Window: The window, or duration, of a scan attack.")
        print("-x Split a pcap into two meta-files for use with traffobot.")
        print("   no other options are valid if this is used.  This will")
        print("   generate a pcap, but takes a pcap and generates two files")
        print("   representing both sides of that pcap.")
        print("-Z Reply Chance: chance that a scan will have a reply.")
        print("   In other words, chance the targer port is open")
        print("   (default 20%).")
        print("")
        print("Please see README for examples and further details.")

        sys.exit(0)
