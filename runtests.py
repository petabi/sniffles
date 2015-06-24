import sys
import sysconfig
import unittest

if __name__ == '__main__':
    sys.path.insert(0, sys.path[0] + '/build/lib.' +
                    sysconfig.get_platform() + '-' +
                    sysconfig.get_python_version())
    sys.path.insert(1, sys.path[1])
    from sniffles.test.test_ttl_expiry_attack import *
    from sniffles.test.test_rule_reader import *
    from sniffles.test.test_rule_traffic_generator import *
    from sniffles.test.test_traffic_splitter import *
    from sniffles.test.test_xml_rule_reader import *
    from sniffles.test.test_examples import *
    from sniffles.test.test_pcrecomp import *
    from sniffles.test.test_nfa_build import *
    suites = [
        unittest.TestLoader().loadTestsFromTestCase(TestTTLExpiryAttack),
        unittest.TestLoader().loadTestsFromTestCase(TestRuleReader),
        unittest.TestLoader().loadTestsFromTestCase(TestRuleTrafficGenerator),
        unittest.TestLoader().loadTestsFromTestCase(TestTrafficSplitter),
        unittest.TestLoader().loadTestsFromTestCase(TestXMLRuleReader),
        unittest.TestLoader().loadTestsFromTestCase(TestExamples),
        unittest.TestLoader().loadTestsFromTestCase(TestPcreComp),
        unittest.TestLoader().loadTestsFromTestCase(TestNFABuild),
        unittest.TestLoader().loadTestsFromTestCase(TestOpAny),
        unittest.TestLoader().loadTestsFromTestCase(TestOpBra),
        unittest.TestLoader().loadTestsFromTestCase(TestOpBraZero),
        unittest.TestLoader().loadTestsFromTestCase(TestOpCbra),
        unittest.TestLoader().loadTestsFromTestCase(TestOpChar),
        unittest.TestLoader().loadTestsFromTestCase(TestOpCirc),
        unittest.TestLoader().loadTestsFromTestCase(TestOpClass),
        unittest.TestLoader().loadTestsFromTestCase(TestOpDigit),
        unittest.TestLoader().loadTestsFromTestCase(TestOpExact),
        unittest.TestLoader().loadTestsFromTestCase(TestOpKetRMax),
        unittest.TestLoader().loadTestsFromTestCase(TestOpNot),
        unittest.TestLoader().loadTestsFromTestCase(TestOpNotDigit),
        unittest.TestLoader().loadTestsFromTestCase(TestOpNotExact),
        unittest.TestLoader().loadTestsFromTestCase(TestOpNotPlus),
        unittest.TestLoader().loadTestsFromTestCase(TestOpNotStar),
        unittest.TestLoader().loadTestsFromTestCase(TestOpNotUpTo),
        unittest.TestLoader().loadTestsFromTestCase(TestOpNotWhitespace),
        unittest.TestLoader().loadTestsFromTestCase(TestOpNotWordchar),
        unittest.TestLoader().loadTestsFromTestCase(TestOpPlus),
        unittest.TestLoader().loadTestsFromTestCase(TestOpQuery),
        unittest.TestLoader().loadTestsFromTestCase(TestOpStar),
        unittest.TestLoader().loadTestsFromTestCase(TestOpTypeExact),
        unittest.TestLoader().loadTestsFromTestCase(TestOpTypePlus),
        unittest.TestLoader().loadTestsFromTestCase(TestOpTypeQuery),
        unittest.TestLoader().loadTestsFromTestCase(TestOpTypeStar),
        unittest.TestLoader().loadTestsFromTestCase(TestOpTypeUpTo),
        unittest.TestLoader().loadTestsFromTestCase(TestOpWhitespace),
        unittest.TestLoader().loadTestsFromTestCase(TestOpWordchar),
        unittest.TestLoader().loadTestsFromTestCase(TestOpNotStarI),
        unittest.TestLoader().loadTestsFromTestCase(TestRegexOptions)
    ]
    tests = unittest.TestSuite(suites)
    unittest.TextTestRunner().run(tests)
