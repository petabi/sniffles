import getopt
import sys
import codecs
from sniffles.feature import *
from sniffles.rule_formats import *


def main():
    featurefile = 'features.txt'
    outfile = "rules.txt"
    count = 1
    rfmt = None
    print("Random Rule Generator")
    try:
        options, args = getopt.getopt(sys.argv[1:], "c:f:o:prs?",
                                      [])
    except getopt.GetoptError as err:
        print("Error: ", err)
        usage()
    for opt, arg in options:
        if opt == "-c":
            if arg is not None and int(arg) > 0:
                count = int(arg)
        elif opt == "-f":
            if arg is not None:
                featurefile = arg
        elif opt == "-o":
            if arg is not None:
                outfile = arg
        elif opt == "-p":
            rfmt = "petabipktclass"
        elif opt == "-r":
            rfmt = "regex"
        elif opt == "-s":
            rfmt = "snort"
        elif opt == "-?":
            usage()
        else:
            print("Unrecognized Option: ", opt)
    try:
        myfp = FeatureParser(featurefile)
        myfeatures = myfp.getFeatures()
        myrules = generateRules(myfeatures, count)
        printRules(myrules, outfile, rfmt)
    except Exception as err:
        print("RandRuleGen-main: " + str(err))


def generateRules(feature_list=None, count=1):
    rule_list = []
    if feature_list:
        for i in range(0, count):
            myrule = ""
            for f in feature_list:
                myrule += str(f) + "; "
            rule_list.append(myrule)
    return rule_list


def printRules(rule_list=None, outfile=None, rule_format=None):
    if rule_list and outfile:
        fd = codecs.open(outfile, 'w', encoding='utf-8')
        for rule in rule_list:
            rwf = getRuleWithFormat(rule, rule_format)
            fd.write(str(rwf))
            fd.write("\n")
        fd.close()


def getRuleWithFormat(rule=None, fmt=None):
    rulefmt = None
    if rule:
        if fmt is not None:
            if fmt == "snort":
                rulefmt = SnortRuleFormat(
                    rule, getRuleWithFormat.rule_counter)
                getRuleWithFormat.rule_counter += 1
            if fmt == "petabipktclass":
                rulefmt = PetabiPacketClassifierFormat(rule)
            if fmt == "regex":
                rulefmt = RegexFormat(rule)

        if rulefmt is None:
            rulefmt = RuleFormat(rule)
    return rulefmt


getRuleWithFormat.rule_counter = 1


def usage():
    print("Random Rule Generator")
    print("usage: rand_rule_gen -c <number of rules -f <feature set>")
    print("       -o <outfile> -[s]")
    print("")
    print("-c  Number of rules: The number of rules to generate.")
    print("    Default is one.")
    print("-f  Feature set: The file containing the feature set description.")
    print("    Please see the documentation for further explanation of")
    print("    feature sets and how to describe them.")
    print("-o  outfile: output file to which rules are written.")
    print("    Default is rules.txt")
    print("-s  Snort rule format: write rules to a snort rule format.")
    print("    No options, defaults to off.")
    sys.exit(0)


if __name__ == "__main__":
    main()
