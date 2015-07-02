from unittest import *
from sniffles.rand_rule_gen import *
from sniffles.feature import *
import random


class TestRandRuleGen(TestCase):

    def test_generate_rule(self):
        # testing generic feature
        featureParser = FeatureParser()
        line = "type=feature;name=music;complexity_prob=100;" \
               "ambiguity_list=[any,{beethoven,mozart,bach}" \
               ",[5,150],[20:25]];"
        featureParser.parseLine(line)
        myfeatures = featureParser.getFeatures()

        myrules = generateRules(myfeatures, 1)
        self.assertEqual(len(myrules), 1)
        rule = myrules[0]
        self.assertEqual(rule[0:5], "music")
        value = rule[6:]

        myrules = generateRules(myfeatures, 2)
        self.assertEqual(len(myrules), 2)
        rule = myrules[0]
        self.assertEqual(rule[0:5], "music")
        value = rule[6:]

        # testing protocol feature
        featureParser = FeatureParser()
        line = "type=protocol; name=proto; proto_list=[IP,UDP," \
               "ICMP]; complexity_prob=0;ambiguity_list=None;"
        featureParser.parseLine(line)
        myfeatures = featureParser.getFeatures()
        myrules = generateRules(myfeatures, 1)
        self.assertEqual(len(myrules), 1)
        rule = myrules[0]
        self.assertTrue(rule == "proto=IP; " or rule == "proto=UDP; "
                        or rule == "proto=ICMP; ")

        # testing ip feature
        featureParser = FeatureParser()
        line = "type=ip; name=sip; version=4; complexity_prob=-1;"
        featureParser.parseLine(line)
        line = "type=ip; name=dip; version=4; complexity_prob=100;"
        featureParser.parseLine(line)
        line = "type=ip; name=mip; version=6; complexity_prob=-1;"
        featureParser.parseLine(line)
        line = "type=ip; name=tip; version=6; complexity_prob=100;"
        featureParser.parseLine(line)
        myfeatures = featureParser.getFeatures()
        myrules = generateRules(myfeatures, 1)
        self.assertEqual(len(myrules), 1)
        elements = myrules[0].split("; ")
        element = elements[0]
        self.assertEqual(element[0:4], "sip=")
        value = element[4:]
        self.assertTrue("/" not in value)
        values = value.split(".")
        self.assertEqual(len(values), 4)
        for i in range(0, 4):
            val = int(values[0])
            self.assertTrue(val >= 0 and val <= 255)

        element = elements[1]
        self.assertEqual(element[0:4], "dip=")
        value = element[4:]
        self.assertTrue("/" in value)
        tmp = value.split("/")
        values = tmp[0].split(".")
        self.assertEqual(len(values), 4)
        for i in range(0, 4):
            val = int(values[0])
            self.assertTrue(val >= 0 and val <= 255)
        val = int(tmp[1])
        self.assertTrue(val >= 0 and val <= 255)

        element = elements[2]
        self.assertEqual(element[0:4], "mip=")
        value = element[4:]
        self.assertTrue("/" not in value)
        values = value.split(":")
        self.assertEqual(len(values), 8)
        for i in range(0, 8):
            val = int(values[0], 16)
            self.assertTrue(val >= 0 and val <= 65535)

        element = elements[3]
        self.assertEqual(element[0:4], "tip=")
        value = element[4:]
        self.assertTrue("/" in value)
        tmp = value.split("/")
        values = tmp[0].split(":")
        self.assertEqual(len(values), 8)
        for i in range(0, 4):
            val = int(values[0], 16)
            self.assertTrue(val >= 0 and val <= 65535)

    def test_snort_rule_getRuleWithFormat(self):
        featureParser = FeatureParser()
        line = "type=feature; name=alert; complexity_prob=100; " \
               "ambiguity_list=[alert, log, dyn" \
               "amic, drop, sdrop]"
        testAlert = ['alert', 'log', 'dynamic', 'drop', 'sdrop']
        featureParser.parseLine(line)

        line = "type=protocol; name=proto; proto_list=[TCP,UDP];"
        testProtocol = ['TCP', 'UDP']
        featureParser.parseLine(line)

        line = "type=ip; name=sip; complexity_prob=100; version=4;"
        featureParser.parseLine(line)

        line = "type=feature; name=sport; complexity_prob=100; " \
               "ambiguity_list=[1500,1600,{1400,1300,1670}]"
        featureParser.parseLine(line)

        line = "type=ip; name=dip; complexity_prob=100; version=6;"
        featureParser.parseLine(line)

        line = "type=feature; name=dport; complexity_prob=100; amb" \
               "iguity_list=[1250,[6000,7000]]"
        featureParser.parseLine(line)

        line = "type=content; name=content; regex=True"
        featureParser.parseLine(line)

        line = "type=feature; name=dir; complexity_prob=100; " \
               "ambiguity_list=[->,<>];"
        featureParser.parseLine(line)

        myfeatures = featureParser.getFeatures()
        myrules = generateRules(myfeatures, 1)
        myrule = myrules[0]
        myvals = myrule.split(";")
        mymap = {}
        for v in myvals:
            v = v.strip()
            if len(v) > 0:
                v_list = v.split("=")
                mymap[v_list[0]] = v_list[1]
        self.assertTrue(mymap['alert'] in testAlert)
        self.assertTrue(mymap['proto'] in testProtocol)

        sip = mymap['sip']
        self.assertTrue("/" in sip)
        sipPart = sip.split("/")[0]
        sipPart = sipPart.split(".")
        self.assertEqual(len(sipPart), 4)
        for i in range(0, 4):
            val = int(sipPart[i])
            self.assertTrue(val >= 0 and val <= 255)

        dip = mymap['dip']
        self.assertTrue("/" in dip)
        dipPart = dip.split("/")[0]
        dipPart = dipPart.split(":")
        self.assertEqual(len(dipPart), 8)
        for i in range(0, 8):
            val = int(dipPart[i], 16)
            self.assertTrue(val >= 0 and val <= 65535)

        rule_list = generateRules(myfeatures, 1)

        for rule in rule_list:

            myvals = rule.split(";")
            mymap = {}
            for v in myvals:
                v = v.strip()
                if len(v) > 0:
                    v_list = v.split("=")
                    mymap[v_list[0]] = v_list[1]

            result = getRuleWithFormat(rule,  "snort")
            testStr = mymap["alert"] + " " + mymap["proto"] + " " + \
                mymap["sip"] + " " + mymap["sport"] + " " + \
                mymap["dir"] + " " + mymap["dip"] + " " + \
                mymap["dport"] + ' ( content:"' + \
                mymap["content"] + '"; sid:1;)'
            self.assertEqual(str(result), testStr)
