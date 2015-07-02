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
        pass
