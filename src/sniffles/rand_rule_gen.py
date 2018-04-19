import argparse

from sniffles.feature import FeatureParser
from sniffles.rule_formats import (PetabiPacketClassifierFormat, RegexFormat,
                                   RuleFormat, SnortRuleFormat)


def main():
    parser = argparse.ArgumentParser(description='Random Rule Generator')
    parser.add_argument('-c', '--count', type=int, default=1,
                        help='the number of rules to generate (default: 1)')
    parser.add_argument('-f', '--feature_file',
                        help='the file containing the feature set description')
    parser.add_argument('-o', '--output_file', default='rules.txt',
                        help='the output file to which rules are written '
                        '(default: rules.txt)')
    parser.add_argument('-r', '--rule_format',
                        choices=['petabipktclass', 'regex', 'snort'],
                        default='regex',
                        help='rule format')
    args = parser.parse_args()
    try:
        myfp = FeatureParser(args.feature_file)
        myfeatures = myfp.getFeatures()
        myrules = generateRules(myfeatures, args.count)
        printRules(myrules, args.output_file, args.rule_format)
    except Exception as err:
        print("RandRuleGen-main: " + str(err))


def generateRules(feature_list, count=1):
    return ['; '.join(map(str, feature_list)) + '; '] * count


def printRules(rule_list=None, outfile=None, rule_format=None):
    if rule_list and outfile:
        fd = open(outfile, 'w', encoding='utf-8')
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


if __name__ == "__main__":
    main()
