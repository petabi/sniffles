import getopt
import datetime
import random
import sys
import signal
import copy
from sortedcontainers import SortedDict
from sniffles.rulereader import *
from sniffles.ruletrafficgenerator import *
from sniffles.traffic_writer import *
from sniffles.snifflesconfig import *
TOTAL_GENERATED_PACKETS = 0
TOTAL_GENERATED_STREAMS = 0
GLOBAL_SCONF = None
START = None
FINAL = 0

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


def main():
    global GLOBAL_SCONF
    global START
    signal.signal(signal.SIGINT, handlerKeyboardInterupt)
    sconf = SnifflesConfig(sys.argv[1:])
    GLOBAL_SCONF = sconf
    start = datetime.datetime.now()
    START = start
    print("")
    print("!^!Sniffles v" + getVersion() +
          " -- Traffic Generation for NIDS evaluation.")
    print("Started at: ", start)
    print(str(sconf))
    mystats = start_generation(sconf)
    print("Generated Streams: ", mystats[0])
    print("Generated Packets: ", mystats[1])
    tduration = mystats[2] - sconf.getFirstTimestamp()
    if tduration < 0:
        tduration = 0
    print("Traffic Duration in seconds (rounded down): ", tduration)
    end = datetime.datetime.now()
    print("Generation finished at: ", end)
    duration = end - start
    print("Generation Time: ", duration)
    sys.exit(0)

##############################################################################
# End Main Processing
##############################################################################

##############################################################################
# Support Functions
##############################################################################


def start_generation(sconf):
    """ This function controls the reading of rules and the actual
        generation of traffic.
    """
    global TOTAL_GENERATED_STREAMS
    global TOTAL_GENERATED_PACKETS
    global FINAL
    myrulelist = RuleList()
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
        sconf.setRandom(True)

    if sconf.getIPV4Home() is not None:
        set_ipv4_home(sconf.getIPV4Home())
    if sconf.getIPV6Home() is not None:
        set_ipv6_home(sconf.getIPV6Home())
    allrules = myrulelist.getParsedRules()
    # Retrieve Background Traffic percentage
    back_traffic_percent = sconf.getBackgroundTraffic()
    back_dist_list = None
    back_absent_proto = None
    # Get Background Traffic Rule if given
    if myrulelist.getBackgroundTraffic():
        bt_rule = myrulelist.getBackgroundTraffic()
        back_traffic_percent = bt_rule.getBackgroundPercent()
        back_dist_list = bt_rule.getProbabilityDist()
        back_absent_proto = bt_rule.getAbsentProtocol()
    current = 0
    end = 0
    current_sec = sconf.getFirstTimestamp()
    current_usec = 0
    total_generated_streams = 0
    total_generated_packets = 0
    flow_start_offset = 0
    mix_count = sconf.getMixCount()
    traffic_queue = SortedDict()

    if sconf.getWriteRegEx():
        return printRegEx(allrules)

    # If we define a scan attack from the command line, add it to the traff
    # here.
    if sconf.getScan():
        base_offset = 0
        for t in sconf.getScanTargets():
            if sconf.getRandomizeOffset():
                base_offset += int(
                    random.normalvariate(sconf.getScanOffset(),
                                         sconf.getScanOffset()/4))
            else:
                base_offset += int(sconf.getScanOffset())
            rule = Rule("Scan Attack")
            r_ts = ScanAttackRule(sconf.getScanType(), t,
                                  sconf.getTargetPorts(),
                                  None,
                                  sconf.getScanDuration(),
                                  sconf.getIntensity(),
                                  base_offset,
                                  sconf.getScanReplyChance())
            rule.addTS(r_ts)
            conversation = Conversation(rule, sconf, current_sec)
            sec, usec = conversation.getNextTimeStamp()
            timekey = sec + (usec/1000000)
            if timekey in traffic_queue:
                traffic_queue[timekey].append(conversation)
            else:
                traffic_queue[timekey] = [conversation]
            total_generated_streams += conversation.getNumberOfStreams()

    traffic_writer = TrafficWriter(sconf.getOutputFile(),
                                   sconf.getFirstTimestamp())

    if sconf.getEval() or sconf.getFullEval():
        return build_eval_pcap(allrules, traffic_writer, sconf)

    if sconf.getTrafficDuration() > 0:
        end = sconf.getTrafficDuration() + sconf.getFirstTimestamp()
    else:
        end = sconf.getTotalStreams()

    fd_result = open(sconf.getResultFile(), 'w') # for recording how packets are generated

    while current < end:
        myrule = None
        if sconf.getMixMode() and mix_count >= 0:
            if mix_count > 0 and allrules:
                myrule = copy.deepcopy(random.choice(allrules))
                mix_count = mix_count - 1
        elif allrules:
            myrule = copy.deepcopy(random.choice(allrules))
        if sconf.getVerbosity():
            print(myrule)

        flow_start_offset = random.randint(
            1, sconf.getConcurrentFlows() + 100000
        )
        # Create background traffic conversation based on
        # Background traffic rule
        if back_traffic_percent > 0:
            pick = random.randint(0, 99)
            if pick < back_traffic_percent:
                btrule = Rule("Background Traffic")
                # Update the content with saved information
                bt_rule = BackgroundTrafficRule()
                bt_rule.updateContent(None, back_dist_list, back_absent_proto)
                btrule.addTS(bt_rule)
                conversation = Conversation(btrule, sconf, current_sec,
                                            current_usec + flow_start_offset)
            else:
                conversation = Conversation(myrule, sconf, current_sec,
                                            current_usec + flow_start_offset)
        else:
            conversation = Conversation(myrule, sconf, current_sec,
                                        current_usec + flow_start_offset)

        sec, usec = conversation.getNextTimeStamp()
        timekey = timekey = sec + (usec/1000000)
        if timekey in traffic_queue:
            traffic_queue[timekey].append(conversation)
        else:
            traffic_queue[timekey] = [conversation]
        total_generated_streams += conversation.getNumberOfStreams()

        # Need to track global value in case of interupt
        TOTAL_GENERATED_STREAMS = total_generated_streams
        if len(traffic_queue) >= sconf.getConcurrentFlows():
            pkts, current_sec, current_usec = write_packets(
                traffic_queue, traffic_writer, sconf, fd_result
            )
            total_generated_packets += pkts

            # Need to track global values in case of interupt
            TOTAL_GENERATED_PACKETS = total_generated_packets
            FINAL = current_sec

        if sconf.getTrafficDuration() > 0:
            current = current_sec
        elif sconf.getTrafficDuration() <= 0:
            current = total_generated_streams

    while traffic_queue and len(traffic_queue) > 0:
        pkts, current_sec, current_usec = write_packets(
            traffic_queue, traffic_writer, sconf, fd_result
        )
        total_generated_packets += pkts

        # Track global values
        TOTAL_GENERATED_PACKETS = total_generated_packets
        FINAL = current_sec
    traffic_writer.close_save_file()
    fd_result.close()
    return [total_generated_streams, total_generated_packets, current_sec]


def build_eval_pcap(rules, traffic_writer, sconf):
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
    if rules is None:
        print("No rules were provided.")
        return [0, 0, 0]
    for rule in rules:
        sconf.setFullMatch(sconf.getEval())
        mycon = Conversation(rule, sconf, 0)
        traffic_queue.append(mycon)
    mytimer = 0
    while traffic_queue:
        current_stream = traffic_queue.pop(0)
        while current_stream.hasPackets():
            s, u, pkt = current_stream.getNextPacket()
            if pkt:
                traffic_writer.write_packet(
                    pkt.get_size(), pkt.get_packet(),
                    0, mytimer)
                mytimer += 1
                total_pkts += 1
                TOTAL_GENERATED_PACKETS = total_pkts
    traffic_writer.close_save_file()
    return [len(rules), total_pkts, 0]


def printRegEx(rules):
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


def write_packets(queue, traffic_writer, sconf, fd_result):
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
    half_threshold = 0
    last_sec = 0
    last_usec = 0
    if len(queue) >= sconf.getConcurrentFlows():
        half_threshold = int(len(queue)/2)
    num_packets = 0
    while queue and len(queue) > half_threshold:
        key, con_list = queue.popitem(last=False)
        for current_conversation in con_list:
            if current_conversation.hasPackets():
                # write that packet
                pkt = None
                s, u, pkt = current_conversation.getNextPacket()
                if s > last_sec:
                    last_sec = s
                if u > last_usec:
                    last_usec = u
                if pkt is not None:
                    traffic_writer.write_packet(
                        pkt.get_size(), pkt.get_packet(), s, u
                    )
                    num_packets += 1

                    # print the rule & traffic stream info
                    result_line = "\n"
                    pkt_rule = None
                    pkt_rule_idx = 0
                    pkt_ts_rule = pkt.get_ts_rule()
                    if pkt_ts_rule:
                        pkt_rule = pkt_ts_rule.getRule()
                        pkt_rule_idx = pkt_ts_rule.getRuleIndex()
                    if pkt_rule:
                        result_line = "Pkt " + \
                          str(traffic_writer.get_total_pkts()) + \
                          " : rule = " + pkt_rule.getRuleName() + \
                          ", ts idx = " + str(pkt_rule_idx)
                        if pkt.get_content_set():
                            result_line += ", content_set ";
                            result_line += ("(truncated)" \
                              if pkt.get_content_truncated() else "")
                            result_line += "\n"
                    else:
                        result_line = "Pkt " + str(traffic_writer.get_total_pkts()) + \
                                " : (rule none)\n"
                    fd_result.write(result_line)

                else:
                    print("Packets is none!!! Something is wrong")

        for current_conversation in con_list:
            if current_conversation.hasPackets():
                next_sec, next_usec = current_conversation.getNextTimeStamp()
                if next_sec > last_sec:
                    last_sec = next_sec
                if next_usec > last_usec:
                    last_usec = next_usec
                timekey = next_sec + (next_usec/1000000)
                if timekey in queue:
                    queue[timekey].append(current_conversation)
                else:
                    queue[timekey] = [current_conversation]

    return (num_packets, last_sec, last_usec)


def handlerKeyboardInterupt(signum, frame):
    '''
    When Sniffles is killed through a keyboard interrupt, it will
    be gracefully shutdown. It was handled using interrupt handler
    '''
    global TOTAL_GENERATED_PACKETS
    global TOTAL_GENERATED_STREAMS
    global GLOBAL_SCONF
    global START
    global FINAL
    print()
    print(
        "Generated Streams: ",
        TOTAL_GENERATED_STREAMS if TOTAL_GENERATED_STREAMS else 0
        )
    print(
        "Generated Packets: ",
        TOTAL_GENERATED_PACKETS if TOTAL_GENERATED_PACKETS else 0
        )
    tduration = 0
    if GLOBAL_SCONF:
        tduration = FINAL - GLOBAL_SCONF.getFirstTimestamp()
        if tduration < 0:
            tduration = 0
    print("Traffic Duration in seconds (rounded down): ", tduration)
    end = datetime.datetime.now()
    print("Generation finished at: ", end)
    duration = 0
    if START:
        duration = end - START
    print("Generation Time: ", duration)
    sys.exit(0)

if __name__ == "__main__":
    main()
