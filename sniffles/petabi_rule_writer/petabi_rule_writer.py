import getopt
import sys
from datetime import date
import re
import random
import codecs
import sniffles.pcrecomp
from sniffles.nfa import PCRE_OPT

"""
   petabi_rule_writer. This is a simple petabi rule writer.
   It takes a regex file and simple parameters to create petabi rule
   formatted file. The options on this programme is focused on options
   that is not present in sniffles (i.e. IP4fragmentisation has to be
   explicitly written in the rules) hence, this program will explicitly
   write such features in the rule. Note that this program will create
   same number of pkt rules as number of regex present in regex file.
   This program contains following options:
   - Fragment
   - Out-of-order
   - Packet-loss
   - Split
   - Tcp-overlap
   - TTL-expiry

"""


def main():

    print("Petabi Rule Generator")

    outfile = "petabi_rule.xml"
    filename = ''
    time = date.today()
    ruleName = str(time)

    count = '1'
    trafficAck = False
    pktAck = False
    fragment = False
    split = False
    proto = 'tcp'
    src = 'any'
    dst = 'any'
    sport = 'any'
    dport = 'any'
    flow = 'to server'
    out_of_order = False
    out_of_order_prob = False
    packet_loss = False
    ttl = None
    ttlExpiry = False
    tcpOverlap = False

    cmd_options = "aAc:d:f:F:n:o:OP:p:s:T:t:v?"
    try:
        options, args = getopt.getopt(sys.argv[1:], cmd_options)
    except getopt.GetoptError as err:
        print("Error:", err)
    for opt, arg in options:
        if opt == "-a":
            pktAck = True
        elif opt == "-A":
            trafficAck = True
        elif opt == "-c":
            if arg is not None:
                count = arg
        elif opt == "-d":
            if arg is not None:
                if arg == 'c':
                    flow = 'to client'
                elif arg == 'r':
                    flow = 'random'
                else:
                    print("Unknown Flow Direction:", arg)
                    usage()
        elif opt == "-f":
            if arg is not None:
                filename = arg
        elif opt == "-F":
            if arg is not None:
                fragment = arg
        elif opt == "-n":
            if arg is not None:
                ruleName = arg
        elif opt == "-o":
            if arg is not None:
                outfile = arg
        elif opt == "-O":
            out_of_order = True
        elif opt == "-P":
            if arg is not None:
                out_of_order_prob = arg
                if int(out_of_order_prob) < 1 or int(out_of_order_prob) > 99:
                    print(opt, "This value must be between 1 and 99")
                    usage()
        elif opt == "-p":
            if arg is not None:
                packet_loss = arg
                if int(packet_loss) < 1 or int(packet_loss) > 99:
                    print(opt, "This value must be between 1 and 99")
                    usage()
        elif opt == "-s":
            if arg is not None:
                split = arg
        elif opt == "-T":
            if arg is not None:
                ttlExpiry = arg
        elif opt == "-t":
            if arg is not None:
                ttl = arg
        elif opt == "-v":
            tcpOverlap = True
        elif opt == "-?":
            usage()
        else:
            print("Unrecognized Option:", opt)
            usage()
    try:
        regexList = regexParser(filename)
        trafficStreamRule = formatTrafficStreamRule(proto, src, dst, sport,
                                                    dport, trafficAck,
                                                    out_of_order,
                                                    out_of_order_prob,
                                                    packet_loss, tcpOverlap)
        pktRule = formatPktRule(regexList, count, fragment, flow, split,
                                ttl, ttlExpiry, pktAck)
        printRule(trafficStreamRule, pktRule, outfile, ruleName)
    except Exception as err:
        print("PetabiRuleGen-main: " + str(err))


def regexParser(filename=None):
    regex = []
    if filename:
        try:
            fd = codecs.open(filename, 'r', encoding='utf-8')
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


def check_pcre_compile(re):
    optiosn = []
    if len(re) and re[0] == '/':
        optp = re.rfind('/')
        if optp > 0:
            options = list(re[optp + 1:])
            re = re[1:optp]
    opts = 0
    for opt in optiosn:
        if opt in PCRE_OPT:
            opts |= PCRE_OPT[opt]
    try:
        sniffles.pcrecomp.compile(re, opts)
    except:
        return False
    return True


def formatTrafficStreamRule(proto='tcp', src='any', dst='any', dport='any',
                            sport='any', trafficAck=False,
                            out_of_order=False, out_of_order_prob=False,
                            packet_loss=False, tcpOverlap=False):
    trafficStreamFormat = []
    header = "    <traffic_stream"
    trafficStreamFormat.append(header)
    tail = ">"
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
    trafficStream = trafficStream + tail + "\n"
    return trafficStream


def formatPktRule(regexList=None, count='1', fragment=False,
                  flow='to server', split=False, ttl=None, ttlExpiry=False,
                  pktAck=False):
    pktRule = []
    count = "times=\"" + count + "\""
    flowOpt = flow
    if regexList:
        head = "<pkt"
        tail = "/>"
        for regex in regexList:
            pktInfo = []
            pktInfo.append(head)
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
            pktInfo.append(tail)
            rule = ' '.join(pktInfo)
            rule = "      " + rule + "\n"
            pktRule.append(rule)

    return pktRule


def printRule(trafficStreamRule=None, packetRule=None, outfile=None,
              ruleName=None):
    if trafficStreamRule and packetRule:
        fd = codecs.open(outfile, 'w', encoding='utf-8')
        fd.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
        fd.write("<petabi_rules>\n")
        fd.write("  <rule name=\"" + ruleName + "\">\n")
        fd.write(trafficStreamRule)
        for rule in packetRule:
            fd.write(rule)
        fd.write("    </traffic_stream>\n")
        fd.write("  </rule>\n")
        fd.write("</petabi_rules>")
        fd.close()
        print("Petabi Rule Generated!!")


def usage():
    print("Petabi Rule Generator")
    print("usage: ./petabi_rule_gen [-c packet counts] [-d direction]")
    print(" [-f file] [-F number of fragments] [-n rule name]")
    print(" [-o output file name] [-P out_of_order probability]")
    print(" [-p packet_loss probability] [-s split number]")
    print(" [-t ttl time]")
    print("")
    print("-a Packet ACK: send ACK to all packets. Default is false")
    print("-A Traffic Stream ACK: send ACK for all packets in flow.")
    print("   Default is false.")
    print("-c Number of packets: Set number of packets for each regex.")
    print("   Default is one.")
    print("-d Direction: Set the direction of Traffic Stream. Valid ")
    print("   directions are \"to server\" or \"to client\".")
    print("   Type \"c\" for to client, Type \"r\" for random flow.")
    print("   Default is set to server.")
    print("-f Regex file: reads regex per line in a file")
    print("-F Fragment: set number of fragments for each packet.")
    print("-n Rule name: enter the name of the rule for the documentation")
    print("   purpose. Default name is set to creation date.")
    print("-o Output file name: set the file name of output file.")
    print("   Default name is petabi_rule.xml.")
    print("-O Out-of-order: Randomly have packets arrive out-of-order.")
    print("   Note, this only works with packets that use the \'times\'")
    print("   option. Further, this option should also be used with ack")
    print("   so that proper duplicate acks will appear in the traffic")
    print("   trace. Default is False.")
    print("-P Out-of-order probability: Set the probabilty that packets")
    print("   will arive out-of-order. The value must be between 1 and 99")
    print("   Default is set to 50.")
    print("-p Packet Loss: the probability random packets be droped. This")
    print("   only works with the \'times\' option. Further, this option")
    print("   should also be used with the ack option set to true so that")
    print("   duplicate acks will appear in the traffic trace. The value")
    print("   must be between 1 to 99. The packet drop only happens on ")
    print("   data-bearing packets, not on the acks.")
    print("-s Split: the number of split. Split the content among the")
    print("   designated number of packets. By default, all content is")
    print("   sent in a single packet.")
    print("-t TTL: set the time for time to live value for packet.")
    print("-T TTL_expiry: simulate the ttl expiry attack by breaking")
    print("   packets into multiple packet with one malicious packet")
    print("   between two good packet. By default, the value is 0(No ")
    print("   malicious packet). If the value is nonzero, it will insert")
    print("   malicious packet with this ttl equals ttl_expiry value.")
    print("   if the ttl value is set, good packe will be set with new ttl")
    print("   value.")
    print("-v Tcp Overlap: sets tcp overlap, when set, one extra")
    print("   content of packet will be shifted to next packet and the tcp")
    print("   sequence number will be reduced by one to simulate the tcp")
    print("   overlapping. By default, it is set to false.")
    sys.exit(0)


if __name__ == "__main__":
    main()
