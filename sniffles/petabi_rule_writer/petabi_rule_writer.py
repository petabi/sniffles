import argparse
import random
import re
import sys
from collections import OrderedDict

import sniffles.pcrecomp
from sniffles.nfa import PCRE_OPT


"""petabi_rule_writer. This is a simple petabi rule writer.
It takes a regex file and simple parameters to create petabi rule
formatted file. The options on this programme is focused on options
that is not present in sniffles (i.e. IP4fragmentisation has to be
explicitly written in the rules) hence, this program will explicitly
write such features in the rule. Note that this program will create
same number of rules as number of regex present in regex file.
This program contains following options:
- Fragment
- Out-of-order
- Packet-loss
- Split
- Tcp-overlap
- TTL-expiry
- Protocol Distribution of Background Traffic
"""


def probability(string):
    value = int(string)
    if value < 1 or value > 100:
        msg = "%r is not a valid percentage" % string
        raise argparse.ArgumentTypeError(msg)
    return value


def main():
    protocol_dist = []
    proto = 'tcp'
    src = 'any'
    dst = 'any'
    sport = 'any'
    dport = 'any'

    parser = argparse.ArgumentParser(description='Petabi Rule Writer')
    parser.add_argument('-A', '--flow_ack', type=bool, default=False,
                        help='''
                        send ACK for all packets in flow (default: False)''')
    parser.add_argument('-a', '--packet_ack', type=bool, default=False,
                        help='send ACK to all packets (default: False)')
    parser.add_argument('-b', '--background', type=probability,
                        help='''
                        background traffic rule. Set the probability of
                        creating background traffic. There will only be one
                        rule for background traffic. The value must be between
                        1 and 99 inclusive.''')
    parser.add_argument('-c', '--count', type=int, default=1,
                        help='number of packets for each regex (default: 1)')
    parser.add_argument('-D', '--protocol_distribution',
                        help='''
                        protocol distribution. Set distribution for each
                        bakcground traffic protocols. Input must be comma
                        seperated list in following order: [http, ftp, pop,
                        smtp, imap]. Also sum of percentage values must not
                        exceed 100. Also if all protocols are designated with
                        percentage then they must add up to 100. Star symbol(*)
                        can be used to ignore protocols that will form
                        remainder. Option must be used with background traffic
                        rule option (-b).
                        Example: -D 70, *, 10, *, 10 will mean 70%% http, 10%%
                        pop and 10%% imap. Remaining 10%% will be produced from
                        ftp and smtp.''')
    parser.add_argument('-d', '--direction', default='to server',
                        help='''the direction of traffic stream. Valid
                        directions are "to server", "to client", or "random".
                        Default is set to "to server".''')
    parser.add_argument('-F', '--fragment', default=False,
                        help='set number of fragments for each packet.')
    parser.add_argument('-f', '--regex_file',
                        help='Regex file. Reads regex per line in a file.')
    parser.add_argument('-n', '--rule_name',
                        help='''the name of the rule for the documentation
                        purpose. Default name is set to "Rule#" and incrementing
                        number for each rule.''')
    parser.add_argument('-O', '--out_of_order', default=False,
                        help='''Randomly have packets arrive out-of-order.
                        Note, this only works with packets that use the "times"
                        option. Further, this option should also be used with
                        ack so that proper duplicate acks will appear in the
                        traffic trace. Default is False.''')
    parser.add_argument('-o', '--output', default='petabi_rule.xml',
                        help='''Set the file name of output file. Default name
                        is petabi_rule.xml.''')
    parser.add_argument('-P', '--out_of_order_prob', type=int, default=50,
                        help='''Set the probabilty that packets
                        will arive out-of-order. The value must be between 1
                        and 99. Default is set to 50.''')
    parser.add_argument('-p', '--packet_loss', type=probability,
                        help='''the probability random packets be droped. This
                        only works with the "times" option. Further, this
                        option should also be used with the ack option set to
                        true so that duplicate acks will appear in the traffic
                        trace. The value must be between 1 to 99. The packet
                        drop only happens on data-bearing packets, not on the
                        acks.''')
    parser.add_argument('-s', '--split', default=False,
                        help='''the number of split. Split the content among
                        the designated number of packets. By default, all
                        content is sent in a single packet.''')
    parser.add_argument('-T', '--ttl_expiry', type=int, default=0,
                        help='''simulate the ttl expiry attack by breaking
                        packets into multiple packet with one malicious packet
                        between two good packet. By default, the value is 0 (No
                        malicious packet). If the value is nonzero, it will
                        insert malicious packet with this ttl equals ttl_expiry
                        value. If the ttl value is set, good packe will be set
                        with new ttl value.''')
    parser.add_argument('-t', '--ttl', default=None,
                        help='the time for time to live value for packet')
    parser.add_argument('-v', '--overlap', default=False,
                        help='''sets tcp overlap. when set, one extra
                        content of packet will be shifted to next packet and
                        the tcp sequence number will be reduced by one to
                        simulate the tcp overlapping. (default: False)''')
    args = parser.parse_args()
    if args.protocol_distribution:
        protocol_dist = re.split(r'[\s,;]+', args.protocol_distribution)
        percent_sum = 0
        for percentage in protocol_dist:
            if percentage == "*":
                continue
            percent_sum += int(percentage)
        if percent_sum > 100:
            print("Sum of protocol percentages exceed 100")
            sys.exit(1)
    regexList = regexParser(args.regex_file)
    ruleList = formatRule(regexList, args.rule_name, proto, src, dst, sport,
                          dport, args.out_of_order, args.out_of_order_prob,
                          args.packet_loss, args.overlap, args.count, args.fragment,
                          args.direction, args.split, args.ttl, args.ttl_expiry, args.packet_ack,
                          args.flow_ack, args.background, protocol_dist)
    printRule(ruleList, args.output)


# Parses regex file and checks if each regex can be compiled using pcre
# compiler.
# Pre-conditions: regex file containing a regex per line.
# Output: regex list
def regexParser(filename=None):
    regex = []
    if filename:
        try:
            fd = open(filename, encoding='utf-8')
        except Exception as err:
            print("Could not read regex file")
            print("regexParser: " + str(err))
            raise Exception("The program will stop.")
        line = fd.readline()
        while line:
            myregex = line.strip()
            # Check if content is in right format
            if not check_pcre_compile(myregex):
                print("Error: Unknown regex format")
                print("Regex: \"" + myregex + "\" will be ignored")
                line = fd.readline()
                continue
            regex.append(myregex)
            line = fd.readline()
        fd.close()
    return regex


# Checks if a regex can be compiled using pcre compiler.
# A regex is legitimate regex if it gets compiled.
# Output: True or False
def check_pcre_compile(re):
    options = []
    if len(re) and re[0] == '/':
        optp = re.rfind('/')
        if optp > 0:
            options = list(re[optp + 1:])
            re = re[1:optp]
    opts = 0
    for opt in options:
        if opt in PCRE_OPT:
            opts |= PCRE_OPT[opt]
    try:
        sniffles.pcrecomp.compile(re, opts)
    except:
        return False
    return True


# Formats background traffic rule to a petabi rule format.
# There can only be 1 background traffic rule in a whole rule file.
# Output: foramtted background traffic rule
def formatBackgroundTrafficRule(background_traffic, protocol_dist=None):
    bgTrafficInfo = []
    bgTrafficInfo.append("    <traffic_stream")
    bgTrafficInfo.append("typets=\"BackgroundTraffic\"")
    bgTrafficInfo.append('percentage="{}"'.format(background_traffic))
    if protocol_dist:
        protocol_dict = protocolPercentage(protocol_dist)
        for protocol in protocol_dict:
            distribution = protocol + "=\"" + str(protocol_dict[protocol]) + \
                "\""
            bgTrafficInfo.append(distribution)
    bgTrafficInfo.append(">\n")
    background_rule = ' '.join(bgTrafficInfo)
    return background_rule


# Label protocol percentage with given distribution.
# Wildcard (* symbol) is used to denote even percentage among wildcards.
# Wildcard protocol will not be shown in the rule, but will be applied
# in sniffles. When all protocols are given a percentage and their sum
# does not add up to 100, Error will be shown and exit programme.
# Output: Dictionary containing protocol percentage
def protocolPercentage(protocol_dist):
    protocol_percent = OrderedDict()
    protocol_list = ['http', 'ftp', 'pop', 'smtp', 'imap']
    i = 0
    protocol_sum = 0
    protocol_num = 0
    while i < len(protocol_list):
        if protocol_dist[i] != "*":
            protocol_percent[protocol_list[i]] = int(protocol_dist[i])
            protocol_sum += int(protocol_dist[i])
            protocol_num += 1
        i += 1

    if protocol_num == 5 and protocol_sum != 100:
        print("Distribution values must add up to 100 when all 5 protocols "
              "are designated")
        sys.exit(1)
    return protocol_percent


# Formats whole rule file to a petabi rule format.
# Combine and forms background rule, traffic rules and pkt rules into
# petabi rule.
# Output: Petabi rule formatted rule
def formatRule(regexList=None, ruleName=None, proto='tcp', src='any',
               dst='any', dport='any', sport='any', out_of_order=False,
               out_of_order_prob=False, packet_loss=False, tcpOverlap=False,
               count='1', fragment=False, flow='to server', split=False,
               ttl=None, ttlExpiry=False, pktAck=False, trafficAck=False,
               background_traffic=None, protocol_dist=None):

    rule = OrderedDict()
    ruleNo = 0
    if background_traffic:
        bgTraffic = formatBackgroundTrafficRule(background_traffic,
                                                protocol_dist)
        rule['Background'] = bgTraffic
    if ruleName is None:
        ruleName = "Rule #"
    for regex in regexList:
        ruleNo += 1
        ruleID = ruleName + str(ruleNo)
        trafficStreamRule = formatTrafficStreamRule(proto, src, dst, sport,
                                                    dport, trafficAck,
                                                    out_of_order,
                                                    out_of_order_prob,
                                                    packet_loss, tcpOverlap)
        pktRule = formatPktRule(regex, count, fragment, flow, split,
                                ttl, ttlExpiry, pktAck)
        ruleInfo = trafficStreamRule + pktRule
        rule[ruleID] = ruleInfo
    return rule


# Creates Traffic Stream Rule by inputting stream infos, and formats
# rule into petabi rule format.
# Output: Traffic Stream Rule
def formatTrafficStreamRule(proto='tcp', src='any', dst='any', dport='any',
                            sport='any', trafficAck=False,
                            out_of_order=False, out_of_order_prob=False,
                            packet_loss=False, tcpOverlap=False):
    trafficStreamFormat = []
    trafficStreamFormat.append("<traffic_stream")
    protoFormat = "proto=\"" + proto + "\""
    trafficStreamFormat.append(protoFormat)
    srcFormat = "src=\"" + src + "\""
    trafficStreamFormat.append(srcFormat)
    dstFormat = "dst=\"" + dst + "\""
    trafficStreamFormat.append(dstFormat)
    dportFormat = "dport=\"" + dport + "\""
    trafficStreamFormat.append(dportFormat)
    sportFormat = "sport=\"" + sport + "\""
    trafficStreamFormat.append(sportFormat)

    if trafficAck:
        myAck = "ack=\"true\""
        trafficStreamFormat.append(myAck)
    if out_of_order:
        out_of_order_format = "out_of_order=\"true\""
        trafficStreamFormat.append(out_of_order_format)
    if out_of_order_prob:
        oopFormat = "out_of_order_prob=\"" + out_of_order_prob + "\""
        trafficStreamFormat.append(oopFormat)
    if packet_loss:
        packet_loss_format = "packet_loss=\"" + packet_loss + "\""
        trafficStreamFormat.append(packet_loss_format)
    if tcpOverlap:
        tcpOverlapFormat = "tcp_overlap=\"true\""
        trafficStreamFormat.append(tcpOverlapFormat)
    trafficStream = ' '.join(trafficStreamFormat)
    trafficStream = "    " + trafficStream + ">" + "\n"
    return trafficStream


# Creates petabi rule formatted packet rule by inputting regex list and
# packet rule infos.
# Output: petabi rule formatted packet rule.
def formatPktRule(regex=None, count='1', fragment=False,
                  flow='to server', split=False, ttl=None, ttlExpiry=False,
                  pktAck=False):
    pktRule = ''
    count = "times=\"" + count + "\""
    flowOpt = flow
    if regex:
        pktInfo = []
        pktInfo.append("<pkt")
        # Random pick flow option if random is selected
        if flow == 'random':
            flowOpt = random.choice(['to server', 'to client'])
        dirOption = "dir=\"" + flowOpt + "\""
        pktInfo.append(dirOption)
        content = "content=" + "\"" + regex + "\""
        pktInfo.append(content)
        # set Ack for packet if defined
        if pktAck:
            myAck = "ack=\"true\""
            pktInfo.append(myAck)
        # set fragment if defined
        if fragment:
            myFragment = "fragment=\"" + fragment + "\""
            pktInfo.append(myFragment)
        # set ttl time if defined
        if ttl:
            myTTL = "ttl=\"" + ttl + "\""
            pktInfo.append(myTTL)
        # set ttl expiry attack if defined
        if ttlExpiry:
            myTtlExpiry = "ttl_expiry=\"" + ttlExpiry + "\""
            pktInfo.append(myTtlExpiry)
        # Set split option if available
        if split:
            splitFormat = "split=\"" + split + "\""
            pktInfo.append(splitFormat)
        pktInfo.append(count)
        pktInfo.append("/>")
        pktRule = ' '.join(pktInfo)
        pktRule = "      " + pktRule + "\n"

    return pktRule


# Creates petabi rule file by inputting Rule list created by formatRule
# function. Also adds xml header and rule tags.
# Output: petabi rule file.
def printRule(ruleList=None, outfile=None):
    if ruleList:
        fd = open(outfile, 'w', encoding='utf-8')
        fd.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
        fd.write("<petabi_rules>\n")
        for key in ruleList:
            fd.write("  <rule name=\"" + key + "\">\n")
            fd.write(ruleList[key])
            fd.write("    </traffic_stream>\n" + "  </rule>\n")
        fd.write("</petabi_rules>")
        fd.close()


if __name__ == "__main__":
    main()
