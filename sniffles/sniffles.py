import getopt
import datetime
import random
import sys
import copy
from sniffles.rulereader import *
from sniffles.ruletrafficgenerator import *
from sniffles.traffic_writer import *
from sniffles.snifflesconfig import *
from sniffles.traffic_splitter import *

"""Sniffles.py
   Traffic generator for IDS evaluation.  Please see the usage section
   for a description of all the available options in Sniffles.
   For detailed information please see the README file.
   Running Sniffles without any arguments will generate a
   single, completely random packet.  The various options can be
   used to modify how packets are generated.  Note, Sniffles can build
   packets based on rules. Running Sniffles with rules will still
   generate traffic even if the rules are incorrect or contain
   features not implemented by Sniffles.  Of course, the resultant
   traffic may not be what is intended.
   It is a good idea to confirm that the data generated is what is
   expected.
   Another note about rulesets: only enabled rules are considered.
   Any rule that is commented out in the ruleset will be ignored.
   Commentted rules are preceded by a # symbol.

   Note, designating the length only determines the content length.
   Headers will be added in addition to the designated size.

   Packets are written into a pcap file.
"""

##############################################################################
# Main Processing
##############################################################################

SLOW_FLOW_COUNT = 3
SLOW_FLOW_THRESHOLD = 1000000


def main():
    sconf = SnifflesConfig(sys.argv[1:])
    start = datetime.datetime.now()
    print("")
    print("!^!Sniffles v" + getVersion() +
          " -- Traffic Generation for NIDS evaluation.")
    print("Started at: ", start)
    if sconf.getSplitFile():
        myts = TrafficSplitter(sconf.getSplitFile())
        myts.readPcap()
        print("Split pcap: ", sconf.getSplitFile())
        print("Into meta files: tfilea and tfileb")
    else:
        print(str(sconf))
        mystats = start_generation(sconf)
        print("Generated Streams: ", mystats[0])
        print("Generated Packets: ", mystats[1])
        tduration = mystats[2] - sconf.getFirstTimestamp()
        if tduration < 0:
            tduration = 0
        print("Traffic Duration: ", tduration)
    end = datetime.datetime.now()
    print("Ending at: ", end)
    duration = end - start
    print("Generation Time: ", duration)
    sys.exit(0)

##############################################################################
# End Main Processing
##############################################################################

##############################################################################
# Support Functions
##############################################################################


def start_generation(sconf=None):
    """ This function controls the reading of rules and the actual
        generation of traffic.
    """
    rand = sconf.getRandom()
    myrulelist = RuleList()
    slow_flows = None
    slow_flow_counter = 0
    if sconf.getRuleFile() and sconf.getRuleDir():
        print("You must specify either a single rule file, "
              "or a directory containing multiple rule files, not both.")
        sconf.usage()
    elif sconf.getRuleFile():
        myrulelist.readRuleFile(sconf.getRuleFile())
    elif sconf.getRuleDir():
        myrulelist.readRuleFiles(sconf.getRuleDir())
    else:
        print("Random Content and Random headers")
        rand = True
    if sconf.getIPV4Home() is not None:
        set_ipv4_home(sconf.getIPV4Home())
    if sconf.getIPV6Home() is not None:
        set_ipv6_home(sconf.getIPV6Home())
    allrules = myrulelist.getParsedRules()
    total_rules = len(allrules)
    scanners = []
    if sconf.getWriteRegEx():
        return printRegEx(allrules)
    if sconf.getScan():
        base_offset = sconf.getFirstTimestamp()
        for t in sconf.getScanTargets():
            if sconf.getRandomizeOffset():
                base_offset += int(
                    random.normalvariate(sconf.getScanOffset(),
                                         sconf.getScanOffset()/4))
            else:
                base_offset += int(sconf.getScanOffset())
            scanner = ScanAttack(None, sconf.getScanType(), t,
                                 sconf.getTargetPorts(), None,
                                 sconf.getMacAddrDef(),
                                 sconf.getScanDuration(),
                                 sconf.getIntensity(),
                                 base_offset,
                                 sconf.getScanReplyChance())
            scanners.append(scanner)

    traffic_writer = TrafficWriter(sconf.getOutputFile(),
                                   sconf.getFirstTimestamp())
    traffic_queue = []
    total_generated_streams = 0
    total_generated_packets = 0
    final = 0
    lapse = 0
    timer = 0
    if sconf.getEval() or sconf.getFullEval():
        return build_eval_pcap(allrules, total_rules, traffic_writer, sconf)
    current = 0
    end = 0
    if sconf.getTrafficDuration() > 0:
        end = sconf.getTrafficDuration() + sconf.getFirstTimestamp()
    else:
        end = sconf.getTotalStreams()
    if sconf.getConcurrentFlows() > SLOW_FLOW_THRESHOLD:
        slow_flows = []
    while current < end:
        lapse = current
        mycon = None
        if allrules:
            myrand = random.randint(0, total_rules-1)
            mycon = copy.deepcopy(allrules[myrand])
            if sconf.getVerbosity():
                print(mycon)
        conversation = Conversation(mycon, sconf.getFullMatch(), False,
                                    sconf.getPktsPerStream(),
                                    sconf.getTCPACK(), sconf.getTCPHandshake(),
                                    sconf.getTCPTeardown(),
                                    sconf.getIPV6Percent(),
                                    rand, sconf.getPktLength(),
                                    sconf.getMacAddrDef(), sconf.getBi())
        if slow_flows is None or slow_flow_counter != SLOW_FLOW_COUNT:
            traffic_queue.append(conversation)
        else:
            if slow_flow_counter == SLOW_FLOW_COUNT:
                slow_flows.append(conversation)
                slow_flow_counter = 0
        slow_flow_counter += 1

        total_generated_streams += conversation.getNumberOfStreams()
        con_flows = len(traffic_queue) + (len(slow_flows) if slow_flows else 0)
        if con_flows >= sconf.getConcurrentFlows():
            pkts, lapse = write_packets(traffic_queue, traffic_writer,
                                        sconf.getTimeLapse(), sconf.getScan(),
                                        scanners, slow_flows)
            total_generated_packets += pkts
        if sconf.getScan() and len(scanners) < 1 and \
           sconf.getRandomizeOffset():
            for t in sconf.getScanTargets():
                scanner = ScanAttack(None, sconf.getScanType(), t,
                                     sconf.getTargetPorts(), None,
                                     sconf.getMacAddrDef(),
                                     sconf.getScanDuration(),
                                     sconf.getIntensity(),
                                     (final + int(random.normalvariate(
                                                  sconf.getScanOffset(),
                                                  sconf.getScanOffset()/4))),
                                     sconf.getScanReplyChance())
                scanners.append(scanner)
        if sconf.getTrafficDuration() > 0:
            current = lapse
        elif sconf.getTrafficDuration() <= 0:
            current = total_generated_streams
    final = lapse
    while traffic_queue and len(traffic_queue) > 0:
        pkts, final = write_packets(traffic_queue, traffic_writer,
                                    sconf.getTimeLapse(), sconf.getScan(),
                                    scanners, slow_flows)
        total_generated_packets += pkts
    while slow_flows and len(slow_flows) > 0:
        pkts, final = write_packets(slow_flows, traffic_writer,
                                    sconf.getTimeLapse())
        total_generated_packets += pkts
    traffic_writer.close_save_file()
    return [total_generated_streams, total_generated_packets, final]


def build_eval_pcap(rules, num_rules, traffic_writer, sconf):
    """
        This function is used to build an evaluation pcap.  An evaluation
        pcap will take a set of regular expression rules and build a pcap
        with the following constraints:

        eval: Exactly one packet per regular expression with each packet
        content derived from one regular expression.  The packets will be in
        the same order as the regular expressions and should have a 1-to-1
        correspondence.

        full eval: Takes a set of regular expressions and attempts to make
        a packet content matching data for that regular expression.  It will
        create a packet for every branch in the regular expression, though
        not for every possible combination.  For example: /^abcd/ would create
        exactly one packet, while /^a(b|c)d/ would create two.  Note,
        an extra branch is created if the regex is not anchored.
        This is because it is possible for the regex to match inside a
        string.  Thus, /abcd/ would actually have two branches, one abcd and
        the other .abcd where the . could be any character.
    """
    traffic_queue = []
    total_pkts = 0
    for i in range(0, num_rules):
        mycon = Conversation(rules[i], sconf.getEval(), sconf.getFullEval(), 1,
                             sconf.getTCPACK(), sconf.getTCPHandshake(),
                             sconf.getTCPTeardown())
        traffic_queue.append(mycon)
    print("Now write the traffic")
    while traffic_queue:
        current_stream = traffic_queue.pop(0)
        while current_stream.has_packets():
            pkts = current_stream.getNextPkts()
            if pkts:
                for pkt in pkts:
                    current_time = traffic_writer.write_packet(
                        pkt.get_size(), pkt.get_packet(), 1)
                total_pkts += len(pkts)

    traffic_writer.close_save_file()
    return [num_rules, total_pkts, current_time]


def printRegEx(rules=None):
    """
        This is a utility function to print out all of the content strings
        currently in memory (i.e. read in from rules).
    """
    fd = None
    try:
        fd = open("all.re", 'w')
    except:
        print("Could not open file to write out regex.")
    for r in rules:
        for ts in r.getTS():
            for p in ts.getPkts():
                for c in p.getContent():
                    fd.write(c.getContentString())
                    fd.write("\n")
    if fd:
        fd.close()
    return [0, 0, 0]


def write_packets(queue=None, traffic_writer=None, time_lapse=1,
                  scan=False, scanners=None, slow_flows=None):
    """
        Packets are written out interleaved (round-robin) from
        each stream until the batch is complete, or there are no more packets
        to write.  This helps defeat locality in that packets from a single
        stream (assuming some streams have more than one packet) will be
        roughly the length of the queue apart in the traffic stream.
    """
    if not queue:
        print("No packets to write")
        return (0, traffic_writer.get_timestamp())
    else:
        # write out packets
        reg_packets = 0
        scan_packets = 0
        slow_flow_counter = 0
        current_time = time_lapse
        last_scan = current_time
        index = random.randint(0, len(queue)-1)
        if slow_flows:
            for sf in slow_flows:
                if not sf.has_started():
                    pkts = sf.getNextPkts()
                    if pkts:
                        for pkt in pkts:
                            current_time = traffic_writer.write_packet(
                                pkt.get_size(), pkt.get_packet(), time_lapse)
                        reg_packets += len(pkts)
                    else:
                        slow_flows.remove(sf)
        while queue:

            index = index % len(queue)
            current_stream = queue[index]
            if current_stream.has_packets():
                # write that packet
                pkts = []
                pkts.extend(current_stream.getNextPkts())
                if pkts is not None and len(pkts) > 0:
                    for pkt in pkts:
                        if pkt is not None:
                            current_time = traffic_writer.write_packet(
                                pkt.get_size(), pkt.get_packet(), time_lapse)
                    reg_packets += len(pkts)

                else:
                    print("packets is none!!! Something is wrong")
                    del queue[index]

            else:
                del queue[index]

            # Add scan packets interleaving with regular packets.
            if scan:
                last_time = current_time
                for s in scanners:
                    if s.get_offset() <= current_time and s.has_packets():
                        last = s.get_last_sent()
                        diff = (current_time - last) / s.get_pkt_interval()
                        pkts = []
                        while diff > 0:
                            pkt = s.get_next_packet()
                            if pkt is not None:
                                pkts.append(pkt)
                            diff -= 1
                        for pkt in pkts:
                            last_time = traffic_writer.write_packet(
                                pkt.get_size(), pkt.get_packet(),
                                time_lapse)
                            scan_packets += 1
                    if not s.has_packets():
                        scanners.remove(s)
                current_time = last_time

            # Add in flows designed to extend across the entire pcap
            if slow_flows and slow_flow_counter == SLOW_FLOW_COUNT:
                sf_index = random.randint(0, len(slow_flows)-1)
                sf = slow_flows[sf_index]
                pkts = []
                pkts.extend(sf.getNextPkts())
                if pkts is not None and len(pkts) > 0:
                    for pkt in pkts:
                        current_time = traffic_writer.write_packet(
                            pkt.get_size(), pkt.get_packet(), time_lapse)
                    reg_packets += len(pkts)

                else:
                    del slow_flows[sf_index]
                if not sf.has_packets():
                    del slow_flows[sf_index]

            slow_flow_counter += 1
            index += 1
        return (reg_packets + scan_packets, current_time)

if __name__ == "__main__":
    main()
