import random
import unittest

import sniffles.feature as feature


class TestFeature(unittest.TestCase):
    def test_ambigous_notation_class(self):
        ambigous = feature.AmbiguousNotation("[5,3,8]")
        self.assertEqual(str(ambigous), "[5,3,8]")

    def test_set_notation_class(self):
        test = feature.SetNotation("{mon,tues,wed,thurs,fri,sat,sun}")
        testList = ["mon", "tues", "wed", "thurs", "fri", "sat", "sun"]
        for _ in range(0, 10):
            values = (str(test)[1:-1]).split(",")
            for value in values:
                self.assertTrue(value in testList)

    def test_range_notation_class(self):
        for _ in range(0, 5):
            lower = random.randint(0, 20)
            upper = random.randint(21, 25)
            test = feature.RangeNotation("[" + str(lower) + ":" +
                                         str(upper) + "]")
            result = str(test)
            myrange = result[1:-1]
            bounds = myrange.split(":")
            lower = int(bounds[0])
            upper = int(bounds[1])
            self.assertTrue(lower >= 0)
            self.assertTrue(upper <= 25)
            self.assertTrue(lower <= upper)

    def test_list_notation_class_distribution(self):
        test = feature.ListNotation("[5,1500000]")
        mySplit = str(test)[1:-1]
        values = mySplit.split(",")
        for value in values:
            iVal = int(value)
            self.assertTrue(iVal >= 5)
            self.assertTrue(iVal <= 1500000)

        test = feature.ListNotation("[0, 4294967295]")
        mySplit = str(test)[1:-1]
        values = mySplit.split(",")
        for value in values:
            iVal = int(value)
            self.assertTrue(iVal >= 0)
            self.assertTrue(iVal <= 4294967295)

    def test_list_notation_class(self):
        # basic test case [5,6]
        test1 = feature.ListNotation("[5,6]")
        self.assertEqual(str(test1), "[5,6]")

        # # every value in the list should be in
        # # range [5, 150]
        test2 = feature.ListNotation("[5,150]")
        mySplit = str(test2)[1:-1]
        values = mySplit.split(",")
        for value in values:
            iVal = int(value)
            self.assertTrue(iVal >= 5)
            self.assertTrue(iVal <= 150)

    def test_feature_class(self):
        # no ambiguity list
        myfeature = feature.Feature("f1", 20, 30, 0)
        self.assertEqual(str(myfeature)[0:2], "f1")

        # [mozart,[5,6]]
        ambiguity_list = []
        ambiguity_list.append(feature.AmbiguousNotation("mozart"))
        ambiguity_list.append(feature.ListNotation("[5,9]"))
        ambiguity_list.append(feature.RangeNotation("[9:15]"))
        myfeature = feature.Feature("f1", 20, 30, 100, ambiguity_list)
        for _ in range(0, 5):
            myresult = str(myfeature)
            self.assertEqual(myresult[0:2], "f1")
            if "," in myresult:
                mySplit = myresult[4:-1]
                values = mySplit.split(",")
                for value in values:
                    iVal = int(value)
                    self.assertTrue(iVal >= 5)
                    self.assertTrue(iVal <= 9)
            elif ":" in myresult:
                myrange = myresult[4:-1]
                bounds = myrange.split(":")
                lower = int(bounds[0])
                upper = int(bounds[1])
                self.assertTrue(lower >= 9)
                self.assertTrue(upper <= 15)
                self.assertTrue(lower <= upper)
            else:
                self.assertEqual(myresult[3:], "mozart")

        myfeature = feature.Feature("f1", 20, 30, -1)
        myresult = str(myfeature)
        value = int(myresult[3:])
        self.assertTrue(value >= 20)
        self.assertTrue(value <= 30)

    def test_contentfeature_class(self):
        # need more test cases for content features
        feature.ContentFeature("content", False, 100, 5)

    def test_protocolfeature_class(self):
        protocolFea = feature.ProtocolFeature("p1", ["IP", "TCP"], -1)
        myresult = str(protocolFea)
        for _ in range(0, 10):
            if "I" in myresult:
                self.assertEqual(myresult, "p1=IP")
            elif "T" in myresult:
                self.assertEqual(myresult, "p1=TCP")

    def test_ipfeature_class(self):
        ip = feature.IPFeature("i1", 4, -1)
        for _ in range(0, 100):
            myresult = str(ip)[3:]
            values = myresult.split(".")
            mytest = ""
            for j, value in enumerate(values):
                value = int(value)
                self.assertTrue(value >= 0)
                self.assertTrue(value <= 255)
                mytest += str(value)
                if j != 3:
                    mytest += "."
            self.assertEqual(myresult, mytest)

        ip = feature.IPFeature("i1", 4, 100)
        for _ in range(0, 100):
            myresult = str(ip)[3:]
            self.assertTrue("/" in myresult)
            removeBackSpash = myresult.split("/")
            values = removeBackSpash[0].split(".")
            mytest = ""
            for j, value in enumerate(values):
                value = int(value)
                self.assertTrue(value >= 0)
                self.assertTrue(value <= 255)
                mytest += str(value)
                if j != 3:
                    mytest += "."
            self.assertEqual(removeBackSpash[0], mytest)

        ip = feature.IPFeature("i1", 6, -1)
        for _ in range(0, 100):
            myresult = str(ip)[3:]
            values = myresult.split(":")
            self.assertEqual(len(values), 8)
            for value in values:
                self.assertEqual(len(value), 4)

        ip = feature.IPFeature("i1", 6, 100)
        for _ in range(0, 100):
            myresult = str(ip)[3:]
            self.assertTrue("/" in myresult)
            removeBackSpash = myresult.split("/")
            values = removeBackSpash[0].split(":")
            self.assertEqual(len(values), 8)
            for value in values:
                self.assertEqual(len(value), 4)

    def test_featureparser_tokenizeAmbiguityList(self):
        featureParser = feature.FeatureParser()
        test = featureParser.tokenizeAmbiguityList("[any,5,haha]")
        self.assertEqual(len(test), 3)
        self.assertEqual(test[0], "any")
        self.assertEqual(test[1], "5")
        self.assertEqual(test[2], "haha")

        test = featureParser.tokenizeAmbiguityList("[any,[5,6],haha]")
        self.assertEqual(len(test), 3)
        self.assertEqual(test[0], "any")
        self.assertEqual(test[1], "[5,6]")
        self.assertEqual(test[2], "haha")

        test = featureParser.tokenizeAmbiguityList("[[8,4],[5,6],[3,2]]")
        self.assertEqual(len(test), 3)
        self.assertEqual(test[0], "[8,4]")
        self.assertEqual(test[1], "[5,6]")
        self.assertEqual(test[2], "[3,2]")

        test = featureParser.tokenizeAmbiguityList("[{8,4,6,  3,4}]")
        self.assertEqual(len(test), 1)
        self.assertEqual(test[0], "{8,4,6,3,4}")

        test = featureParser.tokenizeAmbiguityList("[[8,4]]")
        self.assertEqual(len(test), 1)
        self.assertEqual(test[0], "[8,4]")

        test = featureParser.tokenizeAmbiguityList("[any]")
        self.assertEqual(len(test), 1)
        self.assertEqual(test[0], "any")

        test = featureParser.tokenizeAmbiguityList("[[8,4],[5:6]"
                                                   ",[3:2],any]")
        self.assertEqual(len(test), 4)
        self.assertEqual(test[0], "[8,4]")
        self.assertEqual(test[1], "[5:6]")
        self.assertEqual(test[2], "[3:2]")
        self.assertEqual(test[3], "any")

        test = featureParser.tokenizeAmbiguityList("[[8,4],[5:6]"
                                                   ",{3,5,6}, any]")
        self.assertEqual(len(test), 4)
        self.assertEqual(test[0], "[8,4]")
        self.assertEqual(test[1], "[5:6]")
        self.assertEqual(test[2], "{3,5,6}")
        self.assertEqual(test[3], "any")

        test = featureParser.tokenizeAmbiguityList("[ [8,4], [5:6]"
                                                   ",kaka, {3,5,6}]")
        self.assertEqual(len(test), 4)
        self.assertEqual(test[0], "[8,4]")
        self.assertEqual(test[1], "[5:6]")
        self.assertEqual(test[2], "kaka")
        self.assertEqual(test[3], "{3,5,6}")

        test = featureParser.tokenizeAmbiguityList("[ [8,4] , [5:6] "
                                                   ", kaka  , {3,5,6}  ]")
        self.assertEqual(len(test), 4)
        self.assertEqual(test[0], "[8,4]")
        self.assertEqual(test[1], "[5:6]")
        self.assertEqual(test[2], "kaka")
        self.assertEqual(test[3], "{3,5,6}")

    def test_featureparser_parseLine(self):
        pass

    def test_featureparser_buildAmbiguity(self):
        featureParser = feature.FeatureParser()

        # testing build ambiguitylist [any,5]
        test = featureParser.buildAmbiguityList("[any,5]")
        self.assertEqual(len(test), 2)
        for i in range(0, len(test)):
            if i == 0:
                self.assertEqual(str(test[i]), "any")
            elif i == 1:
                self.assertEqual(str(test[i]), "5")

        # testing build ambiguitylist [mozart,beethoven, bach]
        test = featureParser.buildAmbiguityList("[mozart,beethoven,"
                                                "bach]")
        self.assertEqual(len(test), 3)
        self.assertEqual(str(test[0]), "mozart")
        self.assertEqual(str(test[1]), "beethoven")
        self.assertEqual(str(test[2]), "bach")

        def convertToList(strList):
            return (strList[1:-1]).split(",")

        def convertToRange(strList):
            return (strList[1:-1]).split(":")

        # testing build ambiguitylist [mozart,[5,15]]
        # testing feature.ListNotation
        test = featureParser.buildAmbiguityList("[mozart,[5,15]]")
        self.assertEqual(len(test), 2)
        self.assertEqual(str(test[0]), "mozart")
        self.assertTrue(isinstance(test[1], feature.ListNotation))
        for value in convertToList(str(test[1])):
            iVal = int(value)
            self.assertTrue(iVal >= 5)
            self.assertTrue(iVal <= 15)

        test = featureParser.buildAmbiguityList("[mozart,[5,15],[9:13]]")
        self.assertEqual(len(test), 3)
        self.assertEqual(str(test[0]), "mozart")
        self.assertTrue(isinstance(test[1], feature.ListNotation))
        for value in convertToList(str(test[1])):
            iVal = int(value)
            self.assertTrue(iVal >= 5)
            self.assertTrue(iVal <= 15)
        self.assertTrue(isinstance(test[2], feature.RangeNotation))
        values = convertToRange(str(test[2]))
        lower = int(values[0])
        upper = int(values[1])
        self.assertTrue(lower < upper)

        test = featureParser.buildAmbiguityList("[mozart,[5,15],[9:13]"
                                                ", {mon, fri,wed}]")
        self.assertEqual(len(test), 4)
        self.assertEqual(str(test[0]), "mozart")
        self.assertTrue(isinstance(test[1], feature.ListNotation))
        for value in convertToList(str(test[1])):
            iVal = int(value)
            self.assertTrue(iVal >= 5)
            self.assertTrue(iVal <= 15)
        self.assertTrue(isinstance(test[2], feature.RangeNotation))
        values = convertToRange(str(test[2]))
        lower = int(values[0])
        upper = int(values[1])
        self.assertTrue(lower < upper)
        for i in range(3, 4):
            self.assertTrue(isinstance(test[i], feature.SetNotation))
            testList = ["mon", "wed", "fri"]
            for _ in range(0, 10):
                values = str(test[i])[1:-1].split(",")
                for value in values:
                    self.assertTrue(value in testList)
