from unittest import *
from sniffles.rulereader import *


class TestRuleReader(TestCase):

    def test_background_traffic_rule(self):

        myrule = BackgroundTrafficRule()
        protocols = ['http', 'ftp', 'pop', 'smtp', 'imap']

        # Asserts for rule settings
        self.assertEqual(myrule.getProto(), 'tcp')
        for protocolType in protocols:
            myrule = BackgroundTrafficRule(protocolType)
            self.assertEqual(myrule.getProtocolType(), protocolType)
            if myrule.getProtocolType() == 'http':
                self.assertEqual(myrule.getDport(), '80')
            elif myrule.getProtocolType() == 'ftp':
                self.assertEqual(myrule.getSport(), '21')
            elif myrule.getProtocolType() == 'pop':
                self.assertEqual(myrule.getSport(), '110')
            elif myrule.getProtocolType() == 'smtp':
                self.assertEqual(myrule.getSport(), '25')
            elif myrule.getProtocolType() == 'imap':
                self.assertEqual(myrule.getSport(), '143')

        # Asserts for rule contents
        myrule = BackgroundTrafficRule('ftp')
        content = myrule.getContent()
        contentString = myrule.getContentString()
        
        self.assertEqual(contentString, '220 FTP server ready\r\n')
        self.assertEqual(len(content), 1)
        self.assertEqual(content[0].getType(), 'content')
        self.assertEqual(content[0].getName(), 'Basic Regex Rule Content')

    def test_scan_attack_rule(self):
        myrule = ScanAttackRule(1, 2, 3, 4, 5, 6, 7, 8)

        self.assertEqual(myrule.getScanType(), 1)
        myrule.setScanType(-1)
        self.assertEqual(myrule.getScanType(), -1)

        self.assertEqual(myrule.getTarget(), 2)
        myrule.setTarget(-2)
        self.assertEqual(myrule.getTarget(), -2)

        self.assertEqual(myrule.getTargetPorts(), 3)
        myrule.setTargetPorts(-3)
        self.assertEqual(myrule.getTargetPorts(), -3)

        self.assertEqual(myrule.getSrcPort(), 4)
        myrule.setSrcPort(-4)
        self.assertEqual(myrule.getSrcPort(), -4)

        self.assertEqual(myrule.getDuration(), 5)
        myrule.setDuration(-5)
        self.assertEqual(myrule.getDuration(), -5)

        self.assertEqual(myrule.getIntensity(), 6)
        myrule.setIntensity(-6)
        self.assertEqual(myrule.getIntensity(), -6)

        self.assertEqual(myrule.getOffset(), 7)
        myrule.setOffset(-7)
        self.assertEqual(myrule.getOffset(), -7)

        self.assertEqual(myrule.getReplyChance(), 8)
        myrule.setReplyChance(-8)
        self.assertEqual(myrule.getReplyChance(), -8)

    def test_ttl_expiry_value(self):
        myprule = Rule('Petabi')
        mytsrule1 = TrafficStreamRule('udp')
        mytsrule1.addPktRule(RulePkt("to server", "/xyz/i", ttl_expiry=15))
        mytsrule1.addPktRule(RulePkt("to server", "/abc/i", ttl_expiry=23,
                                     ttl=9))
        mytsrule1.addPktRule(RulePkt("to server", "/def/i"))
        myprule.addTS(mytsrule1)
        self.assertEqual(myprule.getRuleName(), 'Petabi')
        mytslist = myprule.getTS()
        myp = mytslist[0].getPkts()
        self.assertEqual(len(myp), 3)
        self.assertEqual(myp[0].getContent()[0].getContentString(), "/xyz/i")
        self.assertEqual(myp[1].getContent()[0].getContentString(), "/abc/i")
        self.assertEqual(myp[2].getContent()[0].getContentString(), "/def/i")
        self.assertEqual(myp[0].getTTLExpiry(), 15)
        self.assertEqual(myp[1].getTTLExpiry(), 23)
        self.assertEqual(myp[1].getTTL(), 9)
        self.assertEqual(myp[2].getTTLExpiry(), 0)
        self.assertEqual(myp[2].getTTL(), 256)
        myp[2].setTTLExpiry(5)
        self.assertEqual(myp[2].getTTLExpiry(), 5)
        myp[2].setTTL(114)
        self.assertEqual(myp[2].getTTL(), 114)

    def test_parse_snort_rule_full(self):
        mysrp = SnortRuleParser()

        # test if snort rule recognize http_cookie
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"recognize http_cookie"; ' \
                   'content:"hello"; http_cookie; ' \
                   'classtype:protocol-command-decode; sid:3046; rev:5;)'
        mysrp.parseRule(textrule)

        # test if snort rule recognize http_raw_cookie
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"recognize http_cookie"; ' \
                   'content:"hello"; http_raw_cookie; ' \
                   'classtype:protocol-command-decode; sid:3046; rev:5;)'
        mysrp.parseRule(textrule)

        # test if snort rule recognize http_method and http_cookie
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"recognize http_cookie"; ' \
                   'content:"GET"; http_method; ' \
                   'content:"Cookie: PHPSESSIONID=3561"; http_cookie; ' \
                   'classtype:protocol-command-decode; sid:3046; rev:5;)'
        mysrp.parseRule(textrule)

        # test if snort rule recognize http_uri
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"recognize http_uri"; ' \
                   'content:"POST"; http_method; ' \
                   'content:"/tutorial/here"; http_uri; ' \
                   'classtype:protocol-command-decode; sid:3046; rev:5;)'
        mysrp.parseRule(textrule)

        # test if snort rule recognize http_stat_code
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"recognize http_stat_code"; ' \
                   'content:"301 Moved Permanently"; http_stat_code; ' \
                   'classtype:protocol-command-decode; sid:3046; rev:5;)'
        mysrp.parseRule(textrule)

        # test if snort rule recognize http_stat_code and http_stat_msg
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"recognize http_stat_code"; ' \
                   'content:"301"; http_stat_code; ' \
                   'content:"Moved Permanently"; http_stat_msg; ' \
                   'classtype:protocol-command-decode; sid:3046; rev:5;)'
        mysrp.parseRule(textrule)

        self.assertEqual(len(mysrp.getRules()), 6)

        # test if snort rule recognize http_cookie
        myrule = mysrp.getRules()[0]
        myts = myrule.getTS()[0]
        self.assertEqual('Snort', myrule.getRuleName())
        mycontent = myts.getPkts()[0].getContent()[0]
        self.assertEqual(mycontent.getName(), "Snort Rule Content")
        self.assertTrue(mycontent.getHttpCookie())

        # test if snort rule recognize http_raw_cookie
        myrule = mysrp.getRules()[1]
        myts = myrule.getTS()[0]
        self.assertEqual('Snort', myrule.getRuleName())
        mycontent = myts.getPkts()[0].getContent()[0]
        self.assertEqual(mycontent.getName(), "Snort Rule Content")
        self.assertTrue(mycontent.getHttpRawCookie())

        # test if snort rule recognize http_method and http_cookie
        myrule = mysrp.getRules()[2]
        myts = myrule.getTS()[0]
        self.assertEqual('Snort', myrule.getRuleName())
        mycontent = myts.getPkts()[0].getContent()[0]
        self.assertEqual(mycontent.getName(), "Snort Rule Content")
        self.assertTrue(mycontent.getHttpMethod())
        self.assertEqual(mycontent.getContentString(), "GET")
        mycontent = myts.getPkts()[0].getContent()[1]
        self.assertEqual(mycontent.getName(), "Snort Rule Content")
        self.assertTrue(mycontent.getHttpCookie())
        self.assertEqual(mycontent.getContentString(),
                         "Cookie: PHPSESSIONID=3561")

        # test if snort rule recognize http_uri
        myrule = mysrp.getRules()[3]
        myts = myrule.getTS()[0]
        self.assertEqual('Snort', myrule.getRuleName())
        mycontent = myts.getPkts()[0].getContent()[0]
        self.assertEqual(mycontent.getName(), "Snort Rule Content")
        self.assertTrue(mycontent.getHttpMethod())
        self.assertEqual(mycontent.getContentString(), "POST")
        mycontent = myts.getPkts()[0].getContent()[1]
        self.assertEqual(mycontent.getName(), "Snort Rule Content")
        self.assertTrue(mycontent.getHttpUri())
        self.assertEqual(mycontent.getContentString(), "/tutorial/here")

        # test if snort rule recognize http_stat_code
        myrule = mysrp.getRules()[4]
        myts = myrule.getTS()[0]
        self.assertEqual('Snort', myrule.getRuleName())
        mycontent = myts.getPkts()[0].getContent()[0]
        self.assertEqual(mycontent.getName(), "Snort Rule Content")
        self.assertTrue(mycontent.getHttpStatCode())
        self.assertEqual(mycontent.getContentString(), "301 Moved Permanently")

        # test if snort rule recognize http_stat_code and http_stat_msg
        myrule = mysrp.getRules()[5]
        myts = myrule.getTS()[0]
        self.assertEqual('Snort', myrule.getRuleName())
        mycontent = myts.getPkts()[0].getContent()

        self.assertEqual(mycontent[0].getName(), "Snort Rule Content")
        self.assertTrue(mycontent[0].getHttpStatCode())
        self.assertEqual(mycontent[0].getContentString(), "301")

        self.assertEqual(mycontent[1].getName(), "Snort Rule Content")
        self.assertTrue(mycontent[1].getHttpStatMsg())
        self.assertEqual(mycontent[1].getContentString(), "Moved Permanently")

    def test_parse_snort_rule(self):
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"NETBIOS SMB-DS NT Trans NT CREATE invalid SACL ' \
                   'ace size dos attempt"; flow:stateless; content:"|00|"; ' \
                   'depth:1; content:"|FF|SMB|A0|"; within:5; distance:3; ' \
                   'byte_test:1,!&,128,6,relative; pcre:"/^.{27}/R"; ' \
                   'content:"|01 00|"; within:2; distance:37; ' \
                   'byte_jump:4,-7,little,relative,from_beginning; ' \
                   'pcre:"/^.{4}/R"; content:!"|00 00 00 00|"; within:4; ' \
                   'distance:12; byte_jump:4,12,relative,little; ' \
                   'content:"|00 00|"; within:2; distance:-10; ' \
                   'metadata:ruleset community, service netbios-ssn; ' \
                   'classtype:protocol-command-decode; sid:3046; rev:5;)'
        mysrp = SnortRuleParser()
        mysrp.parseRule(textrule)
        myrule = mysrp.getRules()[0]
        self.assertEqual('Snort', myrule.getRuleName())
        myts = myrule.getTS()[0]
        self.assertEqual(4, myts.getIPV())
        self.assertEqual('tcp', myts.getProto())
        self.assertEqual('$EXTERNAL_NET', myts.getSrcIp())
        self.assertEqual('any', myts.getSport())
        self.assertEqual('$HOME_NET', myts.getDstIp())
        self.assertEqual('445', myts.getDport())
        self.assertEqual('to server', myts.getFlowOptions())
        mycontent = myts.getPkts()
        for p in mycontent:
            self.assertIn(p.getContent()[0].getType(), ['content', 'pcre'])

    def test_rule_normalization(self):
        textrule = 'alert udp $HOME_NET 1 -> $EXTERNAL_NET 2 ' \
                   '(msg:"test"; pcre:"abc\;\(\)def"; rev:1)'
        mysrp = SnortRuleParser()
        mysrp.parseRule(textrule)
        myrule = mysrp.getRules()[0]
        myts = myrule.getTS()[0]
        mycontent = myts.getPkts()[0].getContent()[0]
        self.assertEqual(mycontent.getContentString(), R"abc\x3b\x28\x29def")

        textrule = R"/abc\(xyz\)\\q/"
        myrp = RuleParser()
        myrp.parseRule(textrule)
        myrule = myrp.getRules()[0]
        myts = myrule.getTS()[0]
        mycontent = myts.getPkts()[0].getContent()[0]
        self.assertEqual(mycontent.getContentString(), R"/abc\x28xyz\x29\\q/")

    def test_parse_re_rule(self):
        textrule = 'abcdef'
        myrep = RuleParser()
        myrep.parseRule(textrule)
        myrule = myrep.getRules()[0]
        self.assertEqual(myrule.getRuleName(), 'basic')
        myts = myrule.getTS()[0]
        self.assertEqual(4, myts.getIPV())
        self.assertEqual('any', myts.getProto())
        self.assertEqual('$EXTERNAL_NET', myts.getSrcIp())
        self.assertEqual('any', myts.getSport())
        self.assertEqual('$HOME_NET', myts.getDstIp())
        self.assertEqual('any', myts.getDport())
        self.assertEqual("to server", myts.getFlowOptions())
        mycontent = myts.getPkts()
        for p in mycontent:
            self.assertIn(p.getContent()[0].getType(), ['pcre'])
        self.assertEqual(p.getContent()[0].getContentString(), 'abcdef')

    def test_rule_pkt(self):
        myrpkt = RulePkt("to client", "/abcdef/i", 3, 5, 500, True, True)
        self.assertEqual(myrpkt.ackThis(), True)
        self.assertEqual(myrpkt.getDir(), "to client")
        mycontent = myrpkt.getContent()[0]
        self.assertEqual(mycontent.getType(), "pcre")
        self.assertEqual(mycontent.getContentString(), "/abcdef/i")
        self.assertEqual(myrpkt.getFragment(), 3)
        self.assertEqual(myrpkt.getOutOfOrder(), True)
        self.assertEqual(myrpkt.getTimes(), 5)
        self.assertEqual(myrpkt.getLength(), 500)

    def test_traffic_stream_rule(self):
        mytsrule = TrafficStreamRule('tcp', '1100:0011', '2200:0022',
                                     '[100:200]', '[10,20,30,40,50]', -1, 6,
                                     False, True, True)
        mytsrule.addPktRule(RulePkt("to server", "/xyz/i"))
        mytsrule.addPktRule(RulePkt("to client", "/123/"))
        self.assertEqual(mytsrule.getSynch(), False)
        self.assertEqual(mytsrule.getTeardown(), True)
        self.assertEqual(mytsrule.getHandshake(), True)
        self.assertEqual(mytsrule.getIPV(), 6)
        mypkts = mytsrule.getPkts()
        self.assertEqual(len(mypkts), 2)
        self.assertEqual(mypkts[0].getDir(), "to server")
        self.assertEqual(mypkts[0].getContent()[0].getContentString(),
                         "/xyz/i")
        self.assertEqual(mypkts[1].getDir(), "to client")
        self.assertEqual(mypkts[1].getContent()[0].getContentString(), "/123/")

    def test_petabi_rule(self):
        myprule = Rule('Petabi')
        mytsrule1 = TrafficStreamRule('udp')
        mytsrule1.addPktRule(RulePkt("to server", "/xyz/i"))
        mytsrule1.addPktRule(RulePkt("to client", "/123/"))
        mytsrule2 = TrafficStreamRule('tcp')
        mytsrule2.addPktRule(RulePkt("to client", "/abc/i"))
        mytsrule2.addPktRule(RulePkt("to server", "/def/"))
        myprule.addTS(mytsrule1)
        myprule.addTS(mytsrule2)
        self.assertEqual(myprule.getRuleName(), 'Petabi')
        mytslist = myprule.getTS()
        self.assertEqual(len(mytslist), 2)
        self.assertEqual(mytslist[0].getProto(), 'udp')
        myp = mytslist[0].getPkts()
        self.assertEqual(len(myp), 2)
        self.assertEqual(myp[0].getContent()[0].getContentString(), "/xyz/i")
        self.assertEqual(myp[1].getContent()[0].getContentString(), "/123/")
        myp = mytslist[1].getPkts()
        self.assertEqual(len(myp), 2)
        self.assertEqual(myp[0].getContent()[0].getContentString(), "/abc/i")
        self.assertEqual(myp[1].getContent()[0].getContentString(), "/def/")

    def test_conversation_rule(self):
        myconrules = []
        textrule = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ' \
                   '(msg:"NETBIOS SMB-DS NT Trans NT CREATE invalid SACL ' \
                   'ace size dos attempt"; flow:stateless; pcre:"/abcdef/"; ' \
                   'metadata:ruleset community, service netbios-ssn; ' \
                   'classtype:protocol-command-decode; sid:3046; rev:5;)'
        mysrp = SnortRuleParser()
        mysrp.parseRule(textrule)
        myconrules.append(mysrp.getRules()[0])
        textrule = '/zyxwv/i'
        myrep = RuleParser()
        myrep.parseRule(textrule)
        myconrules.append(myrep.getRules()[0])
        mytsrule = TrafficStreamRule('tcp', '1.1.1', '2.2.2', '[100:200]',
                                     '[10,20,30,40,50]', False, True, True,
                                     6, True, 50)
        mytsrule.addPktRule(RulePkt("to server", "/xyz/i"))
        mytsrule.addPktRule(RulePkt("to client", "/123/"))
        myprule = Rule('Petabi')
        myprule.addTS(mytsrule)
        myconrules.append(myprule)
        self.assertEqual(len(myconrules), 3)
        myrule = myconrules.pop(0)
        self.assertEqual(myrule.getRuleName(), "Snort")
        myts = myrule.getTS()[0]
        self.assertEqual(
            myts.getPkts()[0].getContent()[0].getContentString(), '/abcdef/')
        myrule = myconrules.pop(0)
        self.assertEqual(myrule.getRuleName(), "basic")
        myts = myrule.getTS()[0]
        self.assertEqual(
            myts.getPkts()[0].getContent()[0].getContentString(), '/zyxwv/i')
        myrule = myconrules.pop(0)
        self.assertEqual(myrule.getRuleName(), "Petabi")
        self.assertEqual(len(myconrules), 0)
        myts = myrule.getTS()[0]
        self.assertEqual(
            myts.getPkts()[0].getContent()[0].getContentString(), '/xyz/i')
        self.assertEqual(
            myts.getPkts()[1].getContent()[0].getContentString(), '/123/')

    def test_read_single_file(self):
        myrulelist = RuleList()
        myrulelist.readRuleFile('sniffles/test/data_files/rules/test_rules2.rules')
        rules = myrulelist.getParsedRules()
        self.assertEqual(len(rules), 9)
        conrule1 = rules[0]
        self.assertEqual(conrule1.getRuleName(), "Snort")
        content0 = conrule1.getTS()[0].getPkts()[0].getContent()[0]
        self.assertEqual(content0.getType(), "content")
        self.assertEqual(content0.getContentString(),
                         "Cookie|3A| =|0D 0A 0D 0A|")
        conrule1 = rules[8]
        self.assertEqual(conrule1.getRuleName(), "Snort")
        self.assertEqual(conrule1.getTS()[0].getDport(), '8080')

    def test_read_multiple_files(self):
        myrulelist = RuleList()
        myrulelist.readRuleFiles('sniffles/test/data_files/rules/')
        rules = myrulelist.getParsedRules()
        self.assertEqual(len(rules), 19)
        conrule1 = rules[0]
        self.assertEqual(conrule1.getRuleName(), "Snort")
        content0 = conrule1.getTS()[0].getPkts()[0].getContent()[0]
        self.assertEqual(content0.getType(), "content")
        self.assertEqual(content0.getContentString(),
                         "work.Method.denyExecution")
        conrule1 = rules[18]
        self.assertEqual(conrule1.getRuleName(), "Snort")
        content0 = conrule1.getTS()[0].getPkts()[0].getContent()[0]
        self.assertEqual(content0.getType(), "content")
        self.assertEqual(content0.getContentString(),
                         "Cookie|3A| =|0D 0A 0D 0A|")
        content1 = conrule1.getTS()[0].getPkts()[0].getContent()[1]
        self.assertEqual(content1.getType(), "pcre")
        self.assertEqual(content1.getContentString(), "/abc(def|hij|klm)/")

    def test_read_petabi_rule_file(self):
        myrulelist = RuleList()
        myrulelist.readRuleFile('sniffles/test/data_files/test_all.xml')
        rules = myrulelist.getParsedRules()
        self.assertEqual(len(rules), 1)
        conrule = rules[0]
        self.assertEqual(conrule.getRuleName(), 'Petabi')
        tsrules = conrule.getTS()
        self.assertEqual(len(tsrules), 6)
        self.assertEqual(tsrules[0].getProto(), 'tcp')
        self.assertEqual(tsrules[0].getHandshake(), True)
        self.assertEqual(
            tsrules[0].getPkts()[0].getContent()[0].getContentString(),
            "/abc/i")
        self.assertEqual(tsrules[2].getProto(), 'udp')
        self.assertEqual(tsrules[3].getTeardown(), True)
        self.assertEqual(
            tsrules[3].getPkts()[0].getTimes(), 4)
        self.assertEqual(tsrules[4].getSrcIp(), '1.2.3.5')
        self.assertEqual(tsrules[4].getOutOfOrder(), True)
        self.assertEqual(tsrules[5].getSport(), '9005')
