import unittest

import sniffles.rulereader as reader


class TestXMLRuleReader(unittest.TestCase):
    def test_parse_rule(self):
        myrl = reader.RuleList()
        myrl.readRuleFile('tests/data_files/test_all.xml')
        self.assertEqual(len(myrl.getParsedRules()), 1)
        for r in myrl.getParsedRules():
            tsrules = r.getTS()
            self.assertEqual(len(tsrules), 6)
            self.assertEqual(4, tsrules[0].getIPV())
            self.assertEqual('tcp', tsrules[0].getProto())
            self.assertEqual('1.2.3.1', tsrules[0].getSrcIp())
            self.assertEqual('9000', tsrules[0].getSport())
            self.assertEqual('9.8.7.1', tsrules[0].getDstIp())
            self.assertEqual('100', tsrules[0].getDport())
            self.assertEqual("to server", tsrules[0].getFlowOptions())
            self.assertEqual(True, tsrules[0].getSynch())
            self.assertEqual(True, tsrules[0].getTeardown())
            self.assertEqual(True, tsrules[0].getHandshake())
            self.assertEqual(4, tsrules[0].getIPV())
            self.assertEqual(False, tsrules[0].getOutOfOrder())
            self.assertEqual(False, tsrules[0].getPacketLoss())
            pkts = tsrules[0].getPkts()
            self.assertEqual(len(pkts), 2)
            self.assertEqual('to server', pkts[0].getDir())
            self.assertEqual('/abc/i',
                             pkts[0].getContent()[0].getContentString())
            self.assertEqual(0, pkts[0].getFragment())
            self.assertEqual(False, pkts[0].getOutOfOrder())
            self.assertEqual(1, pkts[0].getTimes())
            self.assertEqual(False, pkts[0].ackThis())
            self.assertEqual('to client', pkts[1].getDir())
            pkts = tsrules[1].getPkts()
            self.assertEqual(1, len(pkts))
            self.assertEqual(5, pkts[0].getFragment())
            self.assertEqual(True, tsrules[1].getOutOfOrder())
            self.assertEqual('udp', tsrules[2].getProto())
            self.assertEqual(True, tsrules[2].getOutOfOrder())
            self.assertEqual(True, tsrules[3].getPkts()[0].ackThis())
            self.assertEqual(30, tsrules[4].getPacketLoss())
            self.assertEqual(3, tsrules[5].getPkts()[0].getTimes())
