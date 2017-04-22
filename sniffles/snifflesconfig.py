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
    """
    getVersion()
      Queries the distribution package to get the current version of
      Sniffles.  The version number is used for informational purposes
      as well as reference.
    """
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
        self.background_traffic = 0
        self.concurrent_flows = 1000
        self.config_file = None
        self.mix_mode = False
        self.mix_count = 0
        self.eval = False
        self.full_eval = False
        self.full_match = False
        self.intensity = 1
        self.proto = 'any'
        self.ipv4_home = None
        self.ipv6_home = None
        self.ipv6_percent = 0
        self.mac_addr_def = None
        self.output_file = "sniffles.pcap"
        self.result_file = "result.txt"
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
        self.latency = 0
        self.total_streams = 1
        self.traffic_duration = 0
        self.verbosity = False
        self.version = 0
        self.write_reg_ex = False

        if cmd:
            self.parse_cmd(cmd)

    def __str__(self):
        mystr = "Sniffles Configuration: \n"
        if self.bi:
            mystr += "  Bi-directional content generation is turned on.\n"
        mystr += "  Background Traffic percentage set to: " + \
                      str(self.background_traffic) + "%.\n"
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
        if self.proto:
            mystr += "  Protocol specified is: " + self.proto + ".\n"
        if self.tcp_handshake:
            mystr += "  TCP handshakes will be included in the pcap.\n"
        if self.tcp_teardown:
            mystr += "  TCP teardown sequences will be inlcuded in the pcap.\n"
        if self.tcp_ack:
            mystr += "  TCP acknowledgements will be sent.\n"

        if self.mix_mode:
            mystr += "  Will use mix mode (with " + str(self.mix_count) + " streams matched).\n"

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
        if self.latency > 1:
            mystr += "  An average of " + str(self.latency) + \
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

    def setBi(self, value):
        self.bi = value

    def getBackgroundTraffic(self):
        return self.background_traffic

    def getConcurrentFlows(self):
        return self.concurrent_flows

    def setConcurrentFlows(self, value):
        self.concurrent_flows = value

    def getEval(self):
        return self.eval

    def setEval(self, value):
        self.eval = value

    def getFirstTimestamp(self):
        return self.pcap_start_sec

    def setFirstTimestamp(self, value):
        self.pcap_start_sec = value

    def getFullEval(self):
        return self.full_eval

    def setFullEval(self, value):
        self.full_eval = value

    def getFullMatch(self):
        return self.full_match

    def setFullMatch(self, value):
        self.full_match = value

    def getIntensity(self):
        return self.intensity

    def setIntensity(self, value):
        self.intensity = value

    def getIPV4Home(self):
        return self.ipv4_home

    def setIPV4Home(self, value):
        self.ipv4_home = value

    def getIPV6Home(self):
        return self.ipv6_home

    def setIPV6Home(self, value):
        self.ipv6_home = value

    def getIPV6Percent(self):
        return self.ipv6_percent

    def setIPV6Percent(self, value):
        self.ipv6_percent = value

    def getMacAddrDef(self):
        return self.mac_addr_def

    def setMacAddrDef(self, value):
        self.mac_addr_def = value

    def getOutputFile(self):
        return self.output_file

    def getResultFile(self):
        return self.result_file

    def setOutputFile(self, value):
        self.output_file = value

    def getPktLength(self):
        return self.pkt_length

    def setPktLength(self, value):
        self.pkt_length = value

    def getPktsPerStream(self):
        return self.pkts_per_stream

    def setPktsPerStream(self, value):
        self.pkts_per_stream = value

    def getProto(self):
        return self.proto

    def getMixMode(self):
        return self.mix_mode

    def getMixCount(self):
        return self.mix_count

    def getRandom(self):
        return self.rand

    def setRandom(self, value):
        self.rand = value

    def getRuleDir(self):
        return self.rule_dir

    def setRuleDir(self, value):
        self.rule_dir = value

    def getRuleFile(self):
        return self.rule_file

    def setRuleFile(self, value):
        self.rule_file = value

    def getScan(self):
        return self.scan

    def setScan(self, value):
        self.scan = value

    def getScanDuration(self):
        return self.scan_duration

    def setScanDuration(self, value):
        self.scan_duration = value

    def getScanOffset(self):
        return self.scan_offset

    def setScanOffset(self, value):
        self.scan_offset = value

    def getRandomizeOffset(self):
        return self.scan_randomize_offset

    def setRandomizeOffset(self, value):
        self.scan_randomize_offset = value

    def getScanTargets(self):
        return self.scan_targets

    def setScanTargets(self, value):
        self.scan_targets = value

    def getScanType(self):
        return self.scan_type

    def setScanType(self, value):
        self.scan_type = value

    def getScanReplyChance(self):
        return self.scan_reply_chance

    def setScanReplyChance(self, value):
        self.scan_reply_chance = value

    def getTargetPorts(self):
        return self.target_ports

    def setTargetPorts(self, value):
        self.target_ports = value

    def getTCPACK(self):
        return self.tcp_ack

    def setTCPACK(self, value):
        self.tcp_ack = value

    def getTCPHandshake(self):
        return self.tcp_handshake

    def setTCPHandshake(self, value):
        self.tcp_handshake = value

    def getTCPTeardown(self):
        return self.tcp_teardown

    def setTCPTeardown(self, value):
        self.tcp_teardown = value

    def getLatency(self):
        return self.latency

    def setLatency(self, value):
        self.latency = value

    def getTotalStreams(self):
        return self.total_streams

    def setTotalStreams(self, value):
        self.total_streams = value

    def getTrafficDuration(self):
        return self.traffic_duration

    def setTrafficDuration(self, value):
        self.traffic_duration = value

    def getVerbosity(self):
        return self.verbosity

    def setVerbosity(self, value):
        self.verbosity = value

    def getWriteRegEx(self):
        return self.write_reg_ex

    def setWriteRegExe(self, value):
        self.write_reg_ex = value

    def parse_cmd(self, cmd):
        """
            Standard function for reading command line input.
        """
        cmd_options = "abB:c:C:d:D:eEf:F:g:h:H:i:I:l:L:" + \
                      "mM:o:O:p:P:q:rRs:S:tTvwW:x:Z:?"
        long_options = ["resultfile="]
        try:
            options, args = getopt.getopt(cmd, cmd_options, long_options)
        except getopt.GetoptError as err:
            print("Error reading command line: ", err)
            self.usage()
        for opt, arg in options:
            self.parse_opt_arg(opt, arg)

    def parse_config_file(self, cfg_file):
        """
            It is possible to use a config file to fix the command
            line arguments.  In that case, the arguments are read
            as a file of key-value pairs and parsed accordingly.
            Lines starting with the # symbol are ignored.
        """
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
        """
            Since there are two ways to read the command-line
            parameters (command line or config file) the
            actual parsing of values has been pulled out into
            a separate function to decrease redundancy of code.
        """

        # Designate an ACK for every packet from client to server
        if opt == "-a":
            self.tcp_ack = True

        # Designate that data also flow from server to client.
        # Requires that the server is also ACKing data from client.
        # This is the command-line version, more fine-grained control
        # can be achieved using a rule.
        elif opt == "-b":
            self.bi = True
            self.tcp_ack = True
        # Set percentage of background traffics to be added
        elif opt == "-B":
            self.background_traffic = int(arg)
            if self.background_traffic < 0 or self.background_traffic > 100:
                print("Must set percentage between 0 and 100")
                self.usage()

        # Set total number of streams.  The amount of traffic generated
        # is dependent on either the number of streams, of a duration.
        elif opt == "-c":
            self.total_streams = int(arg)
            if self.total_streams < 1:
                print("Must designate one or more streams to create.")
                self.usage()

        # Concurrent streams (conversations really).  The larger
        # this number the more memory required.  Values in the
        # millions may lead to exhausting available memory.  Also,
        # pcap creation times are greatly increased.
        elif opt == "-C":
            if int(arg) > 0:
                self.concurrent_flows = int(arg)

        # Designate a directory of .rules files to read.  Will
        # read all files with the .rules designation and parse
        # them as best as possible.
        elif opt == "-d":
            self.rule_dir = arg

        # Set the duration of traffic generation in total seconds.
        elif opt == "-D":
            if int(arg) > 0:
                self.traffic_duration = int(arg)

        # Create eval pcaps for testing ability to match.
        elif opt == "-e":
            self.eval = True
        elif opt == "-E":
            self.full_eval = True

        # Read a specific rule file.
        elif opt == "-f":
            self.rule_file = arg

        # Use a config file, rather than just the command line
        elif opt == "-F":
            self.config_file = arg
            self.parse_config_file(arg)

        # Designate a start time for the pcap.  Default is now!
        elif opt == "-g":
            if self.pcap_start_sec > 0:
                self.pcap_start_sec = int(arg)

        # Set home address ranges.
        elif opt == "-h":
            self.ipv4_home = [temp.strip() for temp in arg.split(",")]
        elif opt == "-H":
            self.ipv6_home = [temp.strip() for temp in arg.split(",")]

        # Set the chance for ipv6 packets.  Roughly, that percent of
        # streams will be ipv6.  Rules will override this setting.
        elif opt == "-i":
            self.ipv6_percent = int(arg)
            if self.ipv6_percent > 100 or self.ipv6_percent < 1:
                print("IPv6 percentage must be between 1 and 100 to be set.")
                self.usage()

        # For scan attacks.  Set the number of scan attempts per second.
        elif opt == "-I":
            if int(arg) > 0:
                self.intensity = int(arg)

        # Fix the data length for each packet.  Will pad or truncate
        # packets as necessary to meet this requirement.
        # This only affects the data, not the headers.
        elif opt == "-l":
            self.pkt_length = int(arg)

        # Fix a latency for the streams.  Overriden by rules.
        elif opt == "-L":
            if int(arg) > 1:
                self.latency = int(arg)

        # By default, packets almost match content of rules.
        # This switch makes them match.
        elif opt == "-m":
            self.full_match = True

        # Provide a MAC address distribution file for generating
        # MAC addresses with specific values.
        elif opt == "-M":
            self.mac_addr_def = arg

        # Set output file name, default is sniffles.pcap.
        elif opt == "-o":
            self.output_file = arg

        # Set result file name, default is result.txt
        elif opt == "--resultfile":
            self.result_file = arg

        # For scan attacks.  The offset designates the offset from
        # the beginning of the traffic generation to when the
        # scan attack will start.  If used with Random, this becomes
        # the average of an exponential distribution.
        elif opt == "-O":
            if int(arg) > 0:
                self.scan_offset = int(arg)

        # Number of packets per stream.  Should be 1 or more.
        elif opt == "-p":
            self.pkts_per_stream = int(arg)

        # Designate a port, or list of ports, to target for
        # a scan attack.
        elif opt == "-P":
            self.target_ports = arg.split(',')


        # This setting tells sniffles what protocol to use
        # when it's not obvious which protocol to use
        elif opt == "-q":
            if arg is not None:
                global SUPPORTED_PROTOCOLS
                if arg.lower() in SUPPORTED_PROTOCOLS:
                    self.proto = arg.lower()

        # This setting tells sniffles to use random generation wherever
        # possible.  When used with a rule, most of the rule features
        # will override this option.
        elif opt == "-r":
            self.rand = True

        # Randomize a scan attack's start.  Use with -O to create
        # a random start to the scan.
        elif opt == "-R":
            self.scan_randomize_offset = True

        # A list of scan targets.  One scan will be created for
        # each target.  If there are other streams, then those
        # will show up in the pcap as well.
        elif opt == "-s":
            self.scan = True
            self.scan_targets = arg.split(',')

        # Adjust the scan type.  Currently only two types.
        elif opt == "-S":
            if int(arg) in range(1, 2):
                self.scan_type = int(arg)

        # Turn on TCP handshake and teardown.  Off by default.
        elif opt == "-t":
            self.tcp_handshake = True
        elif opt == "-T":
            self.tcp_teardown = True

        # Will print out the rules read, and used in the traffic.
        elif opt == "-v":
            self.verbosity = True

        # Creates a file with the content strings and regex used
        # for this run of sniffles.
        elif opt == "-w":
            self.write_reg_ex = True

        # Sets the duration of a scan attack (in seconds)
        elif opt == "-W":
            if int(arg) > 1:
                self.scan_duration = int(arg)

        # Sets the mix mode and count
        elif opt == "-x":
            if arg is not None and int(arg) > 0:
                self.mix_mode = True
                self.mix_count = int(arg)

        # Ran out of letters.  This sets the chance that a
        # target will reply to a scan packet.
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
        print("usage: ./sniffles [-d dir | -f file] [-B percentage] [-c count]")
        print(" [-C # concurrent flows] [-D traffic duration] [-F config]")
        print(" [-h \"comma-sep list\"] [-H \"comma-sep list\"]")
        print(" [-i ipv6 chance] [-I scan intensity]")
        print(" [-l pkt_length] [-L time lapse] [-M mac_addr_def file]")
        print(" [-o output_file] [-O scan start offset] [-p pkts_per_stream]")
        print(" [-P scan port(s)] [-s scan target(s)] [-S scan type]")
        print(" [-W scan window] [-Z Reply %] [-abeEmrRtTvw]")
        print("")
        print("-a TCP Ack: Send a TCP acknowledgment for every data packet")
        print("   sent.  Off by default.")
        print("-b Bi-directional data: Send data in both directions.")
        print("   Off by default.  Automatically sets TCP acks.")
        print("-B Background Traffic Percentage: Set this value between 1 and")
        print("   100 to produce Background Traffic. This traffic will")
        print("   consist of even selections of following generic application")
        print("   protocols: FTP, HTTP, IMAP, POP and SMTP. By default, ")
        print("   it is set to 0.")
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
        print("   path and file name. A rule file may be a petabi rules.xml,")
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
        print("   config file offers a means of saving the command line")
        print("   options for use across different runs.")
        print("-g Start timestamp: set the seconds for the starting timestamp")
        print("   in the capture.  All other timestamps are derived from")
        print("   this value.  The default is the current time (in seconds).")
        print("-h IP Home Prefixes: A list of IP Home Network Prefixes.")
        print("   IP addresses meant to come from an internal address will")
        print("   use these prefixes.  Prefixes may designate an entire, or")
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
        print("   bytes designated. Less than zero will set the length equal")
        print("   to the content generated by nfa, or a random number between")
        print("   10 and 1410 if random.  This length is applied to all data")
        print("   bearing packets.  Greater than zero will fix the content")
        print("   length for each packet potentially padding or truncating")
        print("   as necessary.")
        print("-L Latency: Average latency for streams (microsecs). Default")
        print("   is a random value between 1 and 200 microseconds for each.")
        print("   stream.  The average will be different for each stream.")
        print("-m Full match: Fully match rules.  By default, generated")
        print("   content will only partially match rules, thus alerts")
        print("   should not be generated (not guaranteed though).")
        print("-M Allows the use of a MAC distribution to have a custom MAC")
        print("   addresses in the traffic.  By default, MAC addresses are")
        print("   randomly generated. More information about the MAC")
        print("   definition file can be found in the")
        print("   examples/mac_definition_file.txt.")
        print("   Note:  You can specify up to two MAC definition files")
        print("   in order to set different values dependent on source or")
        print("   destination MACs.  If you specify only one file, it will")
        print("   be used for either direction. If you use the following")
        print("   notation you can specify for specific directions.")
        print("   For example: 'path1:path2'. Path1 will be MAC definition")
        print("   file for source MACs and path2 will be the MAC definition")
        print("   file for destination MACs. You may also use a question")
        print("   mark (?) to designate one or the other as random as in:")
        print("   '?:path2' to have random source MACs but use the file for.")
        print("   destination MACs.")
        print("-o output file: designate the name of the output file.")
        print("   by default, the file is named: sniffles.pcap.")
        print("-O Offset: Offset before starting a scan attack.")
        print("   If used with the -R option this becomes the")
        print("   average Offset for attacks.")
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
        print("   port after 65535 is reached.  For a list, the ports are")
        print("   scanned through in round-robin fashion.")
        print("-q protocol: specify protocol to use when not specified")
        print("-r Random: Generate random content rather than from the")
        print("   rules.  If rules are still provided, the rules are used")
        print("   in the generation of the headers if they provide headers")
        print("   (like in Snort rules).")
        print("-R Random scan Attacks: Will use the Offset to create scan")
        print("   attacks in the traffic, but will use the offset only as an")
        print("   average. ")
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
        print("-x MixCount: will use rule pattern for MixCount streams.")
        print("   (while rest of the streams are random)")
        print("-Z Reply Chance: chance that a scan will have a reply.")
        print("   In other words, chance the target port is open")
        print("   (default 20%).")
        print("--resultfile result file: designate the name of the result file.")
        print("   it conatains information about how packets are created")
        print("   for example which rules are used for which packets.")
        print("   by default, the file is named: result.txt.")
        print("")
        print("Please see README for examples and further details.")

        sys.exit(0)
