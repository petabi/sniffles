import random
import struct
import unittest
import warnings

import sniffles.ruletrafficgenerator as rtgen
from sniffles.rulereader import (BackgroundTrafficRule, RuleList, RulePkt,
                                 ScanAttackRule, SnortRuleParser,
                                 TrafficStreamRule)
from sniffles.snifflesconfig import SnifflesConfig
from sniffles.vendor_mac_list import VENDOR_MAC_OUI


class TestRuleTrafficGenerator(unittest.TestCase):
    def test_tcp_overlap(self):
        myurl = RuleList()
        myurl.readRuleFile('tests/data_files/test_tcp_overlap.xml')
        rules = myurl.getParsedRules()
        self.assertEqual(len(rules), 1)
        rules = myurl.getParsedRules()
        tsrules = rules[0].getTS()
        firstTSRule = tsrules[0]
        self.assertEqual(firstTSRule.getTCPOverlap(), True)
        self.assertEqual(firstTSRule.getHandshake(), True)
        self.assertEqual(firstTSRule.getTeardown(), True)
        myTS = rtgen.TrafficStream(firstTSRule)
        pkt = myTS.getNextPacket()
        initSeqClient = pkt.get_seq_num()
        pkt = myTS.getNextPacket()
        initSeqServer = pkt.get_seq_num()
        pkt = myTS.getNextPacket()
        self.assertEqual(pkt.get_seq_num() - initSeqClient, 1)
        pkt = myTS.getNextPacket()
        self.assertEqual(pkt.get_seq_num() - initSeqClient, 7)
        pkt = myTS.getNextPacket()
        self.assertEqual(pkt.get_seq_num() - initSeqClient, 12)
        pkt = myTS.getNextPacket()
        self.assertEqual(pkt.get_seq_num() - initSeqClient, 18)
        pkt = myTS.getNextPacket()
        self.assertEqual(pkt.get_seq_num() - initSeqClient, 24)
        pkt = myTS.getNextPacket()
        self.assertEqual(pkt.get_seq_num() - initSeqClient, 30)
        pkt = myTS.getNextPacket()
        self.assertEqual(pkt.get_seq_num() - initSeqClient, 36)
        pkt = myTS.getNextPacket()
        self.assertEqual(pkt.get_seq_num() - initSeqClient, 43)
        pkt = myTS.getNextPacket()
        self.assertEqual(pkt.get_seq_num() - initSeqServer, 1)
        pkt = myTS.getNextPacket()
        self.assertEqual(pkt.get_seq_num() - initSeqServer, 1)
        pkt = myTS.getNextPacket()
        self.assertEqual(pkt.get_seq_num() - initSeqClient, 44)

    def test_build_random_ethernet_header(self):
        random.seed()
        myehdr = rtgen.EthernetFrame(
            '10.0.0.1', '10.1.1.1', rtgen.ETHERNET_HDR_GEN_RANDOM)
        self.assertIn(myehdr.get_d_mac()[0:3], VENDOR_MAC_OUI)
        self.assertIn(myehdr.get_s_mac()[0:3], VENDOR_MAC_OUI)
        myehdrstr1 = str(myehdr)
        myehdr = rtgen.EthernetFrame(
            '10.0.0.1', '10.1.1.1', rtgen.ETHERNET_HDR_GEN_RANDOM)
        myehdrstr2 = str(myehdr)
        self.assertEqual(myehdrstr1, myehdrstr2)
        self.assertEqual(((myehdr.get_ether_type() >> 8) & 0xff), 0x08)
        self.assertEqual((myehdr.get_ether_type() & 0xff), 0x00)
        myehdr.clear_globals()
        myehdr = rtgen.EthernetFrame(
            '10.0.0.1', '10.1.1.1', rtgen.ETHERNET_HDR_GEN_RANDOM)
        self.assertNotEqual(myehdrstr1, str(myehdr))

    def test_build_ethernet_header_dist(self):
        testVENDOR_MAC_OUI = [''.join(['%02x' % i for i in addr])
                              for addr in VENDOR_MAC_OUI]

        # source is 0800, destination is 0800
        myehdr = rtgen.EthernetFrame('10.2.2.2', '10.3.3.3',
                                     rtgen.ETHERNET_HDR_GEN_DISTRIBUTION,
                                     'tests/data_files/'
                                     'mac_definition_file.txt')
        self.assertEqual(''.join(['%02x' % i
                                  for i in myehdr.get_d_mac()[0:2]]),
                         '0080')

        self.assertEqual(''.join(['%02x' % i
                                  for i in myehdr.get_s_mac()[0:2]]),
                         '0080')
        mystr1 = str(myehdr)
        myehdr = rtgen.EthernetFrame('10.2.2.2', '10.3.3.3',
                                     rtgen.ETHERNET_HDR_GEN_DISTRIBUTION,
                                     'tests/data_files/'
                                     'mac_definition_file.txt')
        self.assertEqual(mystr1, str(myehdr))
        myehdr.clear_globals()
        myehdr = rtgen.EthernetFrame('10.2.2.2', '10.3.3.3',
                                     rtgen.ETHERNET_HDR_GEN_DISTRIBUTION,
                                     'tests/data_files/'
                                     'mac_definition_file.txt')
        self.assertNotEqual(mystr1, str(myehdr))

        myehdr.clear_globals()

        # source is 0070, destination is 0080
        myehdr = rtgen.EthernetFrame('10.2.2.2', '10.3.3.3',
                                     rtgen.ETHERNET_HDR_GEN_DISTRIBUTION,
                                     'tests/data_files/'
                                     'mac_definition_file.txt:'
                                     'tests/data_files/'
                                     'mac_definition_file1.txt')

        self.assertEqual(''.join(['%02x' % i
                                  for i in myehdr.get_d_mac()[0:2]]),
                         '0070')

        self.assertEqual(''.join(['%02x' % i
                                  for i in myehdr.get_s_mac()[0:2]]),
                         '0080')
        myehdr.clear_globals()

        # source is randomly, destination is 0070
        myehdr = rtgen.EthernetFrame('10.2.2.2', '10.3.3.3',
                                     rtgen.ETHERNET_HDR_GEN_DISTRIBUTION,
                                     '?:'
                                     'tests/data_files/'
                                     'mac_definition_file1.txt')

        self.assertTrue(''.join(['%02x' % i
                                 for i in myehdr.get_s_mac()[0:3]])
                        in testVENDOR_MAC_OUI)

        self.assertEqual(''.join(['%02x' % i
                                  for i in myehdr.get_d_mac()[0:2]]),
                         '0070')
        myehdr.clear_globals()

        # source is 0800, destination is randomly
        myehdr = rtgen.EthernetFrame('10.2.2.2', '10.3.3.3',
                                     rtgen.ETHERNET_HDR_GEN_DISTRIBUTION,
                                     'examples/mac_definition_file.txt:'
                                     '?')

        self.assertEqual(''.join(['%02x' % i
                                  for i in myehdr.get_s_mac()[0:2]]),
                         '0080')

        self.assertTrue(''.join(['%02x' % i
                                 for i in myehdr.get_d_mac()[0:3]])
                        in testVENDOR_MAC_OUI)

        # if we dont clear the global, it will be the same
        myehdr = rtgen.EthernetFrame('10.2.2.2', '10.3.3.3',
                                     rtgen.ETHERNET_HDR_GEN_DISTRIBUTION,
                                     'examples/mac_definition_file1.txt:'
                                     'examples/mac_definition_file.txt')

        self.assertEqual(''.join(['%02x' % i
                                  for i in myehdr.get_s_mac()[0:2]]),
                         '0080')

        self.assertTrue(''.join(['%02x' % i
                                 for i in myehdr.get_d_mac()[0:3]])
                        in testVENDOR_MAC_OUI)
        myehdr.clear_globals()

        # both is randomly
        myehdr = rtgen.EthernetFrame('10.2.2.2', '10.3.3.3',
                                     rtgen.ETHERNET_HDR_GEN_DISTRIBUTION,
                                     '?:'
                                     '?')

        self.assertTrue(''.join(['%02x' % i
                                 for i in myehdr.get_s_mac()[0:3]])
                        in testVENDOR_MAC_OUI)

        self.assertTrue(''.join(['%02x' % i
                                 for i in myehdr.get_d_mac()[0:3]])
                        in testVENDOR_MAC_OUI)
        myehdr.clear_globals()

    def test_get_dist_mac_oui_with_empty_dist(self):
        ef = rtgen.EthernetFrame('10.2.2.2', '10.3.3.3',
                                 rtgen.ETHERNET_HDR_GEN_DISTRIBUTION)
        with self.assertRaises(KeyError):
            ef.get_dist_mac_oui('src')

    def test_build_ip_header(self):
        myipv4a = rtgen.IPV4(None, None)
        myipv4b = rtgen.IPV4(myipv4a.get_sip(), myipv4a.get_dip())
        self.assertEqual(myipv4a.get_sip(), myipv4b.get_sip())
        self.assertEqual(myipv4a.get_dip(), myipv4b.get_dip())
        myipv6a = rtgen.IPV6(None, None)
        myipv6b = rtgen.IPV6(myipv6a.get_sip(), myipv6a.get_dip())
        self.assertEqual(myipv6a.get_sip(), myipv6b.get_sip())
        self.assertEqual(myipv6a.get_dip(), myipv6b.get_dip())

    def test_get_ports(self):
        myport = rtgen.Port("80")
        self.assertEqual(myport.get_port_value(), 80)
        myport = rtgen.Port("$rtgen.HTTP_PORTS")
        self.assertIn(myport.get_port_value(), rtgen.HTTP_PORTS)
        myport = rtgen.Port("$rtgen.FTP_PORTS")
        self.assertIn(myport.get_port_value(), rtgen.FTP_PORTS)
        myport = rtgen.Port("$rtgen.MAIL_PORTS")
        self.assertIn(myport.get_port_value(), rtgen.MAIL_PORTS)
        myport = rtgen.Port("$rtgen.POP_PORTS")
        self.assertIn(myport.get_port_value(), rtgen.POP_PORTS)
        myport = rtgen.Port("$rtgen.SMB_PORTS")
        self.assertIn(myport.get_port_value(), rtgen.SMB_PORTS)
        myport = rtgen.Port("$rtgen.NBT_PORTS")
        self.assertIn(myport.get_port_value(), rtgen.NBT_PORTS)
        myport = rtgen.Port("$rtgen.NNTP_PORTS")
        self.assertIn(myport.get_port_value(), rtgen.NNTP_PORTS)
        myport = rtgen.Port("$rtgen.DNS_PORTS")
        self.assertIn(myport.get_port_value(), rtgen.DNS_PORTS)
        myport = rtgen.Port("$rtgen.FILE_PORTS")
        self.assertIn(myport.get_port_value(), rtgen.FILE_PORTS)
        myport = rtgen.Port("$rtgen.ORACLE_PORTS")
        self.assertIn(myport.get_port_value(), rtgen.ORACLE_PORTS)
        myport = rtgen.Port("[10:20]")
        self.assertIn(myport.get_port_value(), range(10, 21))
        myport = rtgen.Port("[:10]")
        self.assertIn(myport.get_port_value(), range(0, 11))
        myport = rtgen.Port("[65530:]")
        self.assertIn(myport.get_port_value(), range(65530, 65536))
        myport = rtgen.Port("1,5,80,1000,4000,50000")
        self.assertIn(myport.get_port_value(), [1, 5, 80, 1000, 4000, 50000])

    def test_transport_header(self):
        mydata = struct.pack("!HH", 0, 0)
        mytrans = rtgen.ICMP("1", "0")
        mytesttrans = struct.pack("!BBHI", 1, 0, 0, 0)
        self.assertEqual(mytrans.get_transport_header(), mytesttrans)
        mytrans.set_checksum('10.0.0.1', '10.0.0.2', 1, mytrans.get_size() + 4,
                             mydata)
        self.assertEqual(mytrans.get_checksum(), 0xeaef)

        mytrans = rtgen.TCP("4660", "128", 1, 0)
        mytesttrans = struct.pack("!HHIIHHHH", 0x1234, 0x80, 1, 0, 0x5000,
                                  0xfde8, 0, 0)
        self.assertEqual(mytrans.get_transport_header(), mytesttrans)
        mytrans.set_checksum('10.0.0.1', '10.0.0.2', 6, mytrans.get_size() + 4,
                             mydata)
        self.assertEqual(mytrans.get_checksum(), 0x8b40)

        mytrans = rtgen.UDP("17185", "83")
        mytesttrans = struct.pack("!HHHH", 0x4321, 0x53, 0, 0)
        self.assertEqual(mytrans.get_transport_header(), mytesttrans)
        mytrans.set_checksum('10.0.0.1', '10.0.0.2', 17,
                             mytrans.get_size() + 4, mydata)
        self.assertEqual(mytrans.get_checksum(), 0xa86B)

    def test_http_content_are_properly_constructed(self):

        def convert_to_binary_data(data):
            binary_data = struct.pack("!" + str(len(data)) + "s",
                                      bytearray(map(ord, data)))
            return binary_data

        mysrp = SnortRuleParser()

        # TESTING GET REQUEST AND HTTP_URI
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"test-rule"; content:"GET"; http_method; ' \
                   'content:"/tutorials/other/"; http_uri;' \
                   'classtype:protocol-command-decode; sid:1; ' \
                   'rev:1;)'
        mysrp.parseRule(textrule)

        # TESTING POST REQUEST AND HTTP_URI
        textrule1 = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                    '(msg:"test-rule"; content:"POST"; http_method; ' \
                    'content:"/tutorials/other/"; http_uri;' \
                    'classtype:protocol-command-decode; sid:1; ' \
                    'rev:1;)'
        mysrp.parseRule(textrule1)

        # TESTING POST REQUEST AND HTTP_URI AND HTTP_COOKIE
        textrule2 = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                    '(msg:"test-rule"; content:"POST"; http_method; ' \
                    'content:"/tutorials/other/"; http_uri;' \
                    'content:"cookie: SESSIONID=560"; http_cookie;' \
                    'classtype:protocol-command-decode; sid:1; ' \
                    'rev:1;)'
        mysrp.parseRule(textrule2)

        # TESTING POST REQUEST AND HTTP_STAT_CODE AND HTTP_COOKIE
        textrule3 = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                    '(msg:"test-rule"; content:"POST"; http_method; ' \
                    'content:"/tutorials/other/"; http_uri;' \
                    'content:"301"; http_stat_code;' \
                    'content:"cookie: SESSIONID=560"; http_cookie;' \
                    'classtype:protocol-command-decode; sid:1; ' \
                    'rev:1;)'
        mysrp.parseRule(textrule3)

        # TESTING POST REQUEST AND HTTP_STAT_CODE AND HTTP_COOKIE
        # AND HTTP_STAT_MSG
        textrule4 = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                    '(msg:"test-rule"; content:"POST"; http_method; ' \
                    'content:"/tutorials/other/"; http_uri;' \
                    'content:"301"; http_stat_code;' \
                    'content:"Moved Permanently"; http_stat_msg;' \
                    'content:"cookie: SESSIONID=560"; http_cookie;' \
                    'classtype:protocol-command-decode; sid:1; ' \
                    'rev:1;)'
        mysrp.parseRule(textrule4)

        # TESTING HTTP_METHOD HTTP_URI HTTP_STAT_CODE
        # HTTP_STAT_MSG HTTP_COOKIE HTTP_CLIENT_BODY
        textrule4 = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                    '(msg:"test-rule"; content:"POST"; http_method; ' \
                    'content:"/tutorials/other/"; http_uri;' \
                    'content:"301"; http_stat_code;' \
                    'content:"Moved Permanently"; http_stat_msg;' \
                    'content:"cookie: SESSIONID=560"; http_cookie;' \
                    'pcre:"/abcde{5}/"; http_client_body;' \
                    'classtype:protocol-command-decode; sid:1; ' \
                    'rev:1;)'
        mysrp.parseRule(textrule4)

        myrules = mysrp.getRules()

        # TESTING GET REQUEST AND HTTP_URI
        myrule = myrules.pop(0)
        myts = myrule.getTS()[0]
        mycontent = rtgen.ContentGenerator(myts.getPkts()[0], -1, False, True)
        myhttpdata = mycontent.get_next_published_content().get_data()
        textruledata = struct.pack(
            "!59s", bytearray(map(ord, 'GET /tutorials/other/ '
                                  'HTTP/1.1\r\n'
                                  'content-type: text-html\r\n\r\n'
                                  )))
        self.assertEqual(myhttpdata, textruledata)

        # TESTING POST REQUEST AND HTTP_URI
        myrule = myrules.pop(0)
        myts = myrule.getTS()[0]
        mycontent = rtgen.ContentGenerator(myts.getPkts()[0], -1, False, True)
        myhttpdata = mycontent.get_next_published_content().get_data()
        textruledata = convert_to_binary_data('POST /tutorials/other/ '
                                              'HTTP/1.1\r\n'
                                              'content-type: text-html\r\n\r\n'
                                              )
        self.assertEqual(myhttpdata, textruledata)

        # TESTING POST REQUEST AND HTTP_URI AND HTTP_COOKIE
        myrule = myrules.pop(0)
        myts = myrule.getTS()[0]
        mySnortContents = myts.getPkts()[0].getContent()
        self.assertEqual(len(mySnortContents), 3)

        self.assertEqual(mySnortContents[0].getName(), "Snort Rule Content")
        self.assertTrue(mySnortContents[0].getHttpMethod())
        self.assertEqual(mySnortContents[0].getContentString(), "POST")

        self.assertEqual(mySnortContents[1].getName(), "Snort Rule Content")
        self.assertTrue(mySnortContents[1].getHttpUri())
        self.assertEqual(mySnortContents[1].getContentString(),
                         "/tutorials/other/")

        self.assertEqual(mySnortContents[2].getName(), "Snort Rule Content")
        self.assertTrue(mySnortContents[2].getHttpCookie())
        self.assertEqual(mySnortContents[2].getContentString(),
                         "cookie: SESSIONID=560")

        mycontent = rtgen.ContentGenerator(myts.getPkts()[0], -1, False, True)
        myhttpdata = mycontent.get_next_published_content().get_data()
        test_str = 'POST /tutorials/other/ ' \
                   'HTTP/1.1\r\n' \
                   'content-type: text-html\r\n' \
                   'cookie: SESSIONID=560' \
                   '\r\n\r\n'
        textruledata = convert_to_binary_data(test_str)
        self.assertEqual(myhttpdata, textruledata)

        # TESTING POST REQUEST AND HTTP_STAT_CODE AND HTTP_COOKIE
        myrule = myrules.pop(0)
        myts = myrule.getTS()[0]
        mySnortContents = myts.getPkts()[0].getContent()
        self.assertEqual(len(mySnortContents), 4)

        self.assertEqual(mySnortContents[0].getName(), "Snort Rule Content")
        self.assertTrue(mySnortContents[0].getHttpMethod())
        self.assertEqual(mySnortContents[0].getContentString(), "POST")

        self.assertEqual(mySnortContents[1].getName(), "Snort Rule Content")
        self.assertTrue(mySnortContents[1].getHttpUri())
        self.assertEqual(mySnortContents[1].getContentString(),
                         "/tutorials/other/")

        self.assertEqual(mySnortContents[2].getName(), "Snort Rule Content")
        self.assertTrue(mySnortContents[2].getHttpStatCode())
        self.assertEqual(mySnortContents[2].getContentString(),
                         "301")

        self.assertEqual(mySnortContents[3].getName(), "Snort Rule Content")
        self.assertTrue(mySnortContents[3].getHttpCookie())
        self.assertEqual(mySnortContents[3].getContentString(),
                         "cookie: SESSIONID=560")

        mycontent = rtgen.ContentGenerator(myts.getPkts()[0], -1, False, True)
        myhttpdata = mycontent.get_next_published_content().get_data()
        test_str = 'POST /tutorials/other/ ' \
                   'HTTP/1.1 ' \
                   '301\r\n' \
                   'content-type: text-html\r\n' \
                   'cookie: SESSIONID=560' \
                   '\r\n\r\n'
        textruledata = convert_to_binary_data(test_str)
        self.assertEqual(myhttpdata, textruledata)

        # TESTING POST REQUEST AND HTTP_STAT_CODE AND HTTP_COOKIE
        # AND HTTP_STAT_MSG
        myrule = myrules.pop(0)
        myts = myrule.getTS()[0]
        mySnortContents = myts.getPkts()[0].getContent()
        self.assertEqual(len(mySnortContents), 5)

        self.assertEqual(mySnortContents[0].getName(), "Snort Rule Content")
        self.assertTrue(mySnortContents[0].getHttpMethod())
        self.assertEqual(mySnortContents[0].getContentString(), "POST")

        self.assertEqual(mySnortContents[1].getName(), "Snort Rule Content")
        self.assertTrue(mySnortContents[1].getHttpUri())
        self.assertEqual(mySnortContents[1].getContentString(),
                         "/tutorials/other/")

        self.assertEqual(mySnortContents[2].getName(), "Snort Rule Content")
        self.assertTrue(mySnortContents[2].getHttpStatCode())
        self.assertEqual(mySnortContents[2].getContentString(),
                         "301")

        self.assertEqual(mySnortContents[3].getName(), "Snort Rule Content")
        self.assertTrue(mySnortContents[3].getHttpStatMsg())
        self.assertEqual(mySnortContents[3].getContentString(),
                         "Moved Permanently")

        self.assertEqual(mySnortContents[4].getName(), "Snort Rule Content")
        self.assertTrue(mySnortContents[4].getHttpCookie())
        self.assertEqual(mySnortContents[4].getContentString(),
                         "cookie: SESSIONID=560")

        mycontent = rtgen.ContentGenerator(myts.getPkts()[0], -1, False, True)
        myhttpdata = mycontent.get_next_published_content().get_data()
        test_str = 'POST /tutorials/other/ ' \
                   'HTTP/1.1 ' \
                   '301 Moved Permanently\r\n' \
                   'content-type: text-html\r\n' \
                   'cookie: SESSIONID=560' \
                   '\r\n\r\n'
        textruledata = convert_to_binary_data(test_str)
        self.assertEqual(myhttpdata, textruledata)

        # TESTING HTTP_METHOD HTTP_URI HTTP_STAT_CODE
        # HTTP_STAT_MSG HTTP_COOKIE HTTP_CLIENT_BODY
        myrule = myrules.pop(0)
        myts = myrule.getTS()[0]
        mySnortContents = myts.getPkts()[0].getContent()
        self.assertEqual(len(mySnortContents), 6)

        mycontent = rtgen.ContentGenerator(myts.getPkts()[0], -1, False, True)
        myhttpdata = mycontent.get_next_published_content().get_data()
        test_str = 'POST /tutorials/other/ ' \
                   'HTTP/1.1 ' \
                   '301 Moved Permanently\r\n' \
                   'content-type: text-html\r\n' \
                   'cookie: SESSIONID=560' \
                   '\r\n\r\n' \
                   'abcdeeeee'
        textruledata = convert_to_binary_data(test_str)
        self.assertEqual(myhttpdata, textruledata)

    def test_snort_content_generator(self):
        textruledata = [48, 49, 50, 51, 52, 53, 97, 98, 99, 100, 101, 53, 52,
                        51, 50, 49, 48, 101, 100, 99, 98, 97]
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"test-rule"; content:"0|31 32 33|45"; ' \
                   'pcre:"/^abcde/"; content:"54|33 32 31|0"; ' \
                   'pcre:"/edcba/"; classtype:protocol-command-decode; ' \
                   'sid:1; rev:1;)'
        mysrp = SnortRuleParser()
        mysrp.parseRule(textrule)
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"test-rule"; content:"12345"; offset: 10; ' \
                   'pcre:"/abcde/"; distance: 10; ' \
                   'classtype:protocol-command-decode; sid:1; rev:1;)'
        mysrp.parseRule(textrule)
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"test-rule"; content:"POST"; http_method; ' \
                   'content:"www.test.com/hello/"; http_uri; ' \
                   'pcre:"my_header\x3a testing"; http_header; ' \
                   'pcre:"/abcde/"; http_client_body; ' \
                   'classtype:protocol-command-decode; sid:1; rev:1;)'
        mysrp.parseRule(textrule)
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"test-rule"; content:"POST"; http_method; ' \
                   'content:"www.test.com/hello/"; ' \
                   'http_uri; pcre:"my_header\x3a testing"; http_header; ' \
                   'pcre:"/abcde/"; http_client_body; content:"|30|12|33|"; ' \
                   'pcre:"/hij/"; classtype:protocol-command-decode; sid:1; ' \
                   'rev:1;)'
        mysrp.parseRule(textrule)
        myrules = mysrp.getRules()
        self.assertEqual(len(myrules), 4)

        myrule = myrules.pop(0)
        myts = myrule.getTS()[0]
        mycontent = rtgen.ContentGenerator(myts.getPkts()[0], -1, False, True)
        mytestcontent = struct.pack("!22s", bytearray(textruledata))
        self.assertEqual(mycontent.get_next_published_content().get_data(),
                         mytestcontent)

        myrule = myrules.pop(0)
        myts = myrule.getTS()[0]
        mycontent = rtgen.ContentGenerator(myts.getPkts()[0], -1, False, True)
        self.assertEqual(
            len(mycontent.get_next_published_content().get_data()), 30)

        myrule = myrules.pop(0)
        myts = myrule.getTS()[0]
        mycontent = rtgen.ContentGenerator(myts.getPkts()[0], -1, False, True)
        myhttpdata = mycontent.get_next_published_content().get_data()

        textruledata = struct.pack(
            "!62s", bytearray(map(ord, "POST www.test.com/hello/ "
                                  "HTTP/1.1\r\nmy_header: "
                                  "testing\r\n\r\nabcde")))

        self.assertEqual(myhttpdata, textruledata)

        myrule = myrules.pop(0)
        myts = myrule.getTS()[0]
        self.assertEqual(len(myrules), 0)
        mycontent = rtgen.ContentGenerator(myts.getPkts()[0], -1, False, True)
        myhttpdata = mycontent.get_next_published_content().get_data()
        textruledata = struct.pack(
            "!69s", bytearray(map(ord, "POST www.test.com/hello/ "
                                  "HTTP/1.1\r\nmy_header: "
                                  "testing\r\n\r\nabcde0123hij")))
        self.assertEqual(myhttpdata, textruledata)

    def test_content_gen(self):
        cg = rtgen.ContentGenerator()
        mycon = cg.get_next_published_content()
        self.assertNotEqual(mycon.get_size(), 0)

        mypkt = RulePkt("to client", "/abcdef/m", 1, 150)
        cg = rtgen.ContentGenerator(mypkt, 150, False, True)
        mycon = cg.get_next_published_content()
        self.assertEqual(mycon.get_size(), 150)
        self.assertEqual(
            mycon.get_data(),
            b'abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc' +
            b'abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc' +
            b'abcabcabcabcabcabcabcabcabcdef')

        mypkt = RulePkt("to server", "/1234567890/", 1, 5)
        cg = rtgen.ContentGenerator(mypkt, 5, False, True)
        mycon = cg.get_next_published_content()
        self.assertEqual(mycon.get_size(), 5)
        self.assertEqual(mycon.get_data(), b'12345')

        mypkt = RulePkt("to server", "/abc(cd|ef)g/")
        cg = rtgen.ContentGenerator(mypkt, -1, False, True, True)

        # Note: 4 is the correct number of published content as the above
        # regex is not anchored and thus can begin with an arbitrary
        # character, or directly with the start of the expression.
        self.assertEqual(cg.get_number_of_published_content(), 4)
        for _ in range(0, 3):
            cg.get_next_published_content()
        self.assertEqual(cg.get_number_of_published_content(), 1)

        mypkt = RulePkt("to server", "/^1234567890/")
        cg = rtgen.ContentGenerator(mypkt)
        mycon = cg.get_next_published_content()
        self.assertEqual(mycon.get_size(), 10)

    def test_content_gen_zero_data(self):
        with warnings.catch_warnings(record=True) as w:
            for _ in range(0, 200):
                mypkt = RulePkt("to client", "/a*/", 1)
                cg = rtgen.ContentGenerator(mypkt)
                mycon = cg.get_next_published_content()
                if mycon.get_size() > 0:
                    self.assertEqual(mycon.get_size(), 1)
                    self.assertEqual(mycon.get_data(), b'a')
                else:
                    self.assertEqual(len(w), 1)
                    self.assertIn("No content generated for regex:",
                                     str(w[-1].message))

                mypkt2 = RulePkt("to client", "/b?/", 1)
                cg2 = rtgen.ContentGenerator(mypkt2)
                mycon2 = cg2.get_next_published_content()
                if mycon2.get_size() > 0:
                    self.assertEqual(mycon2.get_size(), 1)
                    self.assertEqual(mycon2.get_data(), b'b')
                else:
                    self.assertEqual(len(w), 1)
                    self.assertIn("No content generated for regex:",
                                     str(w[-1].message))


    def test_packet(self):
        myrpkt = RulePkt("to server", "/12345/")
        cg = rtgen.ContentGenerator(myrpkt)
        mypkt = rtgen.Packet('udp', '10.11.12.13', '13.12.11.10', 4, '1234', '4321',
                             rtgen.ACK, 0, 0, rtgen.ETHERNET_HDR_GEN_RANDOM, None,
                             cg.get_next_published_content())
        self.assertEqual(mypkt.get_src_ip(), '10.11.12.13')
        self.assertEqual(mypkt.get_dst_ip(), '13.12.11.10')
        self.assertEqual(mypkt.get_size(), 47)
        self.assertEqual(mypkt.get_content_length(), 5)
        self.assertEqual(mypkt.get_content().get_data()[0:4], b'1234')

    def test_background_traffic(self):

        rule = BackgroundTrafficRule()
        protocol_list = rule.getProtocolList()

        for protocol in protocol_list:
            rule = BackgroundTrafficRule()
            rule.updateContent(protocol)
            backgroundTraffic = rtgen.BackgroundTraffic(rule, None)

            # Get port value depending on flow
            flow = rule.getFlowOptions()
            if flow == 'to client':
                port = backgroundTraffic.getSport()
                port_value = port.get_port_value()
            elif flow == 'to server':
                port = backgroundTraffic.getDport()
                port_value = port.get_port_value()

            # Check if the port is chosen from correct list
            if protocol == 'http':
                self.assertIn(port_value, rtgen.HTTP_PORTS)
            elif protocol == 'ftp':
                self.assertIn(port_value, rtgen.FTP_PORTS)
            elif protocol == 'pop':
                self.assertIn(port_value, rtgen.POP_PORTS)
            elif protocol == 'imap':
                self.assertEqual(port_value, 143)
            elif protocol == 'smtp':
                self.assertIn(port_value, [25, 465])

    def test_scan(self):

        rule = ScanAttackRule(rtgen.SYN_SCAN, '192.168.1.2', ['1', '2', '3', '4'],
                              '4567', 1, 100, 0, 100)
        rule.setSrcIp('192.168.1.1')
        scanner = rtgen.ScanAttack(rule, None)

        self.assertEqual(scanner.getPacketsRemaining(), 100)
        mypkt = scanner.getNextPacket()
        self.assertEqual(scanner.getPacketsRemaining(), 100)
        self.assertEqual(mypkt.get_content_length(), 0)
        self.assertEqual(mypkt.get_src_ip(), '192.168.1.1')
        mypkt = scanner.getNextPacket()
        self.assertEqual(scanner.getPacketsRemaining(), 99)
        for _ in range(0, 197):
            scanner.getNextPacket()
        self.assertEqual(scanner.getPacketsRemaining(), 1)

        rule = ScanAttackRule(rtgen.CONNECTION_SCAN, '192.168.1.2',
                              ['1', '2', '3', '4'],
                              '4567', 1, 100, 0, 100)
        rule.setSrcIp('192.168.1.1')

        scanner = rtgen.ScanAttack(rule, None)

        self.assertEqual(scanner.getPacketsRemaining(), 100)
        for _ in range(0, 299):
            scanner.getNextPacket()
        self.assertEqual(scanner.getPacketsRemaining(), 1)

    def test_traffic_stream_rand(self):
        myts = rtgen.TrafficStream()
        self.assertEqual(myts.hasPackets(), True)
        myp = myts.getNextPacket()
        self.assertNotEqual(myp.get_size(), 0)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(100)
        myConfig.setPktsPerStream(5)

        myts = rtgen.TrafficStream(None, myConfig)

        mycount = 0
        while myts.hasPackets():
            mypkt = myts.getNextPacket()
            if mypkt.get_proto() == 'tcp':
                self.assertEqual(mypkt.get_size(), 154)
            elif mypkt.get_proto() == 'udp':
                self.assertEqual(mypkt.get_size(), 142)
            elif mypkt.get_proto() == 'icmp':
                self.assertEqual(mypkt.get_size(), 142)
            mycount += 1
        self.assertEqual(mycount, 5)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(200)
        myConfig.setPktsPerStream(1)
        myConfig.setTCPACK(True)
        myConfig.setTCPHandshake(True)
        myConfig.setTCPTeardown(True)

        myts = rtgen.TrafficStream(None, myConfig)

        mypkt = myts.getNextPacket()
        while mypkt.get_proto() != 'tcp':
            myts = rtgen.TrafficStream(None, myConfig)
            mypkt = myts.getNextPacket()
        myseq = mypkt.transport_hdr.get_seq_num()

        self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.SYN)
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_flags(),
                         (rtgen.SYN + rtgen.ACK))
        myack = mypkt.transport_hdr.get_seq_num()
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.ACK)
        self.assertEqual(mypkt.transport_hdr.get_seq_num(), myseq + 1)
        self.assertEqual(mypkt.transport_hdr.get_ack_num(), myack + 1)
        self.assertEqual(mypkt.get_size(), 254)
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_ack_num(), (myseq + 201))
        self.assertEqual(mypkt.get_size(), 54)
        self.assertEqual(mypkt.get_content().get_size(), 0)
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_flags(),
                         rtgen.FIN + rtgen.ACK)
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.ACK)
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_flags(),
                         rtgen.FIN + rtgen.ACK)
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.ACK)

    def test_traffic_stream_frags(self):

        myrpkt = RulePkt("to client", "/abcdef/i", 3, 2, 500, True, True)
        mytsrule = TrafficStreamRule('tcp', '1.1.1', '2.2.2', '[100:200]',
                                     '[10,20,30,40,50]', -1, 4, False, True,
                                     True)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(500)
        myConfig.setIPV6Percent(0)
        myConfig.setTCPACK(True)
        myConfig.setTCPHandshake(True)
        myConfig.setTCPTeardown(True)
        myConfig.setFullMatch(True)

        myts = rtgen.TrafficStream(mytsrule, myConfig)

        mypkt = myts.getNextPacket()
        myseq = mypkt.transport_hdr.get_seq_num()
        self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.SYN)
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_flags(),
                         (rtgen.SYN + rtgen.ACK))
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.ACK)
        self.assertEqual(mypkt.transport_hdr.get_seq_num(), myseq + 1)
        mypkt = myts.getNextPacket()
        self.assertNotEqual(mypkt.network_hdr.get_frag_id(), 0)
        self.assertIn(mypkt.network_hdr.get_frag_offset(), [8192, 8213, 42])
        self.assertIn(mypkt.get_size(), [202, 218])
        mypkt = myts.getNextPacket()
        self.assertIn(mypkt.get_size(), [202, 218])
        self.assertIn(mypkt.network_hdr.get_frag_offset(), [8192, 8213, 42])
        mypkt = myts.getNextPacket()
        self.assertIn(mypkt.network_hdr.get_frag_offset(), [8192, 8213, 42])
        self.assertIn(mypkt.get_size(), [202, 218])
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.get_size(), 54)
        self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.ACK)
        mypkt = myts.getNextPacket()
        self.assertNotEqual(mypkt.network_hdr.get_frag_id(), 0)
        self.assertIn(mypkt.network_hdr.get_frag_offset(), [8192, 8213, 42])
        self.assertIn(mypkt.get_size(), [202, 218])
        mypkt = myts.getNextPacket()
        self.assertIn(mypkt.get_size(), [202, 218])
        self.assertIn(mypkt.network_hdr.get_frag_offset(), [8192, 8213, 42])
        mypkt = myts.getNextPacket()
        self.assertIn(mypkt.network_hdr.get_frag_offset(), [8192, 8213, 42])
        self.assertIn(mypkt.get_size(), [202, 218])
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.get_size(), 54)
        self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.ACK)

    def test_traffic_stream_ooo(self):

        myrpkt = RulePkt("to server", "/abcdef/i", 0, 5, 100, True, True)
        mytsrule = TrafficStreamRule('tcp', '1.1.1', '2.2.2', '[100:200]',
                                     '[10,20,30,40,50]', -1, 4, False, True,
                                     False, True)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(100)
        myConfig.setTCPACK(True)
        myConfig.setTCPHandshake(True)

        myts = rtgen.TrafficStream(mytsrule, myConfig)

        mypkt = myts.getNextPacket()
        myseq = mypkt.transport_hdr.get_seq_num()
        self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.SYN)
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_flags(),
                         (rtgen.SYN + rtgen.ACK))
        while myts.hasPackets():
            mypkt = myts.getNextPacket()
            if mypkt.get_content() is None or \
               mypkt.get_content().get_size() == 0:
                self.assertIn(mypkt.transport_hdr.get_ack_num(), [myseq + 1,
                                                                  myseq + 101,
                                                                  myseq + 201,
                                                                  myseq + 301,
                                                                  myseq + 401,
                                                                  myseq + 501])
            else:
                self.assertEqual(mypkt.get_content().get_size(), 100)

    def test_traffic_stream_loss(self):
        myrpkt = RulePkt("to server", "/abcdef/i", 0, 8, 10, False, False)
        mytsrule = TrafficStreamRule('tcp', '1.1.1', '2.2.2', '[100:200]',
                                     '[10,20,30,40,50]', -1, 4, False, True,
                                     False, False, 0, 50)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setPktLength(10)
        myConfig.setPktsPerStream(1)
        myConfig.setTCPACK(True)
        myConfig.setTCPHandshake(True)
        myConfig.setFullMatch(True)

        myts = rtgen.TrafficStream(mytsrule, myConfig)

        mypkt = myts.getNextPacket()
        myseq = mypkt.transport_hdr.get_seq_num()
        self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.SYN)
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_flags(),
                         (rtgen.SYN + rtgen.ACK))
        while myts.hasPackets():
            mypkt = myts.getNextPacket()
            if mypkt.get_content() is None or \
               mypkt.get_content().get_size() == 0:
                self.assertIn(mypkt.transport_hdr.get_ack_num(), [myseq + 1,
                                                                  myseq + 11,
                                                                  myseq + 21,
                                                                  myseq + 31,
                                                                  myseq + 41,
                                                                  myseq + 51,
                                                                  myseq + 61,
                                                                  myseq + 71,
                                                                  myseq + 81])
            else:
                self.assertEqual(mypkt.get_content().get_size(), 10)

    def test_traffic_stream_split(self):
        myrpkt = RulePkt("to server", "/abcdefghij/", 0, 1, -1, False, False,
                         2)
        mytsrule = TrafficStreamRule('tcp', '1.1.1', '2.2.2', '[100:200]',
                                     '[10,20,30,40,50]', -1, 4, False)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()
        myConfig.setFullMatch(True)

        myts = rtgen.TrafficStream(mytsrule, myConfig)

        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.ACK)
        self.assertEqual(mypkt.get_content().get_size(), 5)
        self.assertEqual(mypkt.get_content().get_data(), b'abcde')

        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.ACK)
        self.assertNotEqual(mypkt.get_content().get_data(), b'abcde')
        self.assertEqual(mypkt.get_content().get_data(), b'fghij')
        self.assertEqual(mypkt.get_content().get_size(), 5)

        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt, None)

    def test_traffic_stream_split_too_large(self):
        myrpkt = RulePkt("to server", "/12345/", 0, 1, -1, False, False, 200)
        mytsrule = TrafficStreamRule('tcp', '1.1.1', '2.2.2', '[100:200]',
                                     '[10,20,30,40,50]', -1, 4, False)
        mytsrule.addPktRule(myrpkt)

        myConfig = SnifflesConfig()

        myts = rtgen.TrafficStream(mytsrule, myConfig)

        for i in range(0, 5):
            mypkt = myts.getNextPacket()
            self.assertEqual(mypkt.transport_hdr.get_flags(), rtgen.ACK)
            self.assertEqual(mypkt.get_content().get_size(), 1)
            if i < 4:
                self.assertIn(mypkt.get_content().get_data(), [b'1', b'2',
                                                               b'3', b'4',
                                                               b'5'])
        mypkt = myts.getNextPacket()
        self.assertEqual(mypkt, None)

    def test_rule_no_content_options(self):
        myparser = SnortRuleParser()
        myparser.parseRule(r'alert tcp any any -> $HOME_NET any'
                           ' (msg:"TCP rtgen.SYN packet";sid:1000002)')
        myrule = myparser.getRules()[0]
        self.assertNotEqual(myrule, None)
        mytsrule = myrule.getTS()[0]
        mytsrule.setLen(100)
        myts = rtgen.TrafficStream(mytsrule, None, 1, 1)
        self.assertNotEqual(myts, None)
        self.assertEqual(myts.hasPackets(), True)
        mypkt = myts.getNextPacket()
        self.assertNotEqual(mypkt, None)
        self.assertGreater(mypkt.get_size(), 100)
        self.assertEqual(myts.hasPackets(), False)

    def test_snort_rule_w_pkt_p_stream_set(self):
        myparser = SnortRuleParser()
        myparser.parseRule(r'alert tcp $EXTERNAL_NET any -> '
                           r'$HOME_NET $rtgen.HTTP_PORTS (msg:"test1-1";'
                           r' flow:to_server,established; content:'
                           r'"work.Method.denyExecution"; nocase; '
                           r'http_uri; content:"u0023"; nocase; http_uri;'
                           r' sid:1;')
        sconf = SnifflesConfig()
        sconf.setPktsPerStream(7)
        self.assertEqual(7, sconf.getPktsPerStream())
        myrule = myparser.getRules()[0]
        myts = myrule.getTS()
        self.assertEqual(1, len(myts))
        self.assertTrue(myts[0].testTypeRule('Standard'))
        self.assertFalse(myts[0].testTypeRule('Background'))
        self.assertFalse(myts[0].testTypeRule('ScanAttack'))
        mycon = rtgen.Conversation(myrule, sconf)
        self.assertEqual(1, mycon.getNumberOfStreams())
        count = 0
        while mycon.getNextPacket():
            count += 1
        self.assertEqual(7, count)

    def test_snort_rule_w_pkt_p_stream_set_w_ack(self):
        myparser = SnortRuleParser()
        myparser.parseRule(r'alert tcp $EXTERNAL_NET any -> '
                           r'$HOME_NET $rtgen.HTTP_PORTS (msg:"test1-1";'
                           r' flow:to_server,established; content:'
                           r'"work.Method.denyExecution"; nocase; '
                           r'http_uri; content:"u0023"; nocase; http_uri;'
                           r' sid:1;')
        sconf = SnifflesConfig()
        sconf.setPktsPerStream(7)
        sconf.setTCPACK(True)
        self.assertEqual(7, sconf.getPktsPerStream())
        myrule = myparser.getRules()[0]
        mycon = rtgen.Conversation(myrule, sconf)
        self.assertEqual(1, mycon.getNumberOfStreams())
        count = 0
        while mycon.getNextPacket():
            count += 1
        self.assertEqual(14, count)
