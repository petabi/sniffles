import random
import unittest

from sniffles.rule_formats import SnortRuleFormat


class TestRuleFormat(unittest.TestCase):

    def test_snort_rule_formats(self):
        test = SnortRuleFormat("alert=log;proto=TCP;sip=20.0.0.1;"
                               "sport=1200;dir=<>;dip=15.5.2.3;"
                               "dport=3000;content=abcde3453fdds;", 5)
        self.assertEqual('log TCP 20.0.0.1 1200 <> 15.5.2.3 3000 ( '
                         'content:"abcde3453fdds"; sid:5;)', str(test))

        test = SnortRuleFormat("", 4)
        self.assertEqual("alert IP $HOME_NET any -> $EXTERNAL_NET any "
                         "( sid:4;)", str(test))

        test = SnortRuleFormat("alert=raise", 0)
        self.assertEqual("raise IP $HOME_NET any -> $EXTERNAL_NET any "
                         "( sid:0;)", str(test))

        test = SnortRuleFormat("proto=TCP", 0)
        self.assertEqual("alert TCP $HOME_NET any -> $EXTERNAL_NET any "
                         "( sid:0;)", str(test))

        test = SnortRuleFormat("sip=20.0.0.1", 0)
        self.assertEqual("alert IP 20.0.0.1 any -> $EXTERNAL_NET any ( "
                         "sid:0;)", str(test))

        test = SnortRuleFormat("sport=1200", 0)
        self.assertEqual("alert IP $HOME_NET 1200 -> $EXTERNAL_NET any "
                         "( sid:0;)", str(test))

        test = SnortRuleFormat("dir=<>;", 0)
        self.assertEqual("alert IP $HOME_NET any <> $EXTERNAL_NET any ("
                         " sid:0;)", str(test))

        test = SnortRuleFormat("dip=15.5.2.3", 0)
        self.assertEqual("alert IP $HOME_NET any -> 15.5.2.3 any ( sid:"
                         "0;)", str(test))

        test = SnortRuleFormat("dport=3000", 0)
        self.assertEqual("alert IP $HOME_NET any -> $EXTERNAL_NET 3000 "
                         "( sid:0;)", str(test))

        test = SnortRuleFormat("content=abcde3453fdds;", 0)
        self.assertEqual('alert IP $HOME_NET any -> $EXTERNAL_NET any ('
                         ' content:"abcde3453fdds"; sid:0;)', str(test))
