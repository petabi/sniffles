from unittest import *
from sniffles.ruletrafficgenerator import *


class TestTTLExpiryAttack(TestCase):

    def ttl_expiry_scenario1(self):
      print("hello world")
      myrpkt = RulePkt("to server", "/my tcp2/", 4, 3, ttl=110)
      mytsrule = TrafficStreamRule('tcp', '1.2.3.4', '9.8.7.5', '9000',
                                     '101', -1, 4, False, False, False)
      mytsrule.addPktRule(myrpkt)
      myts = TrafficStream(mytsrule, 140, 0, len(mytsrule.getPkts()),
                             None, False, mytsrule.getHandshake(),
                             mytsrule.getTeardown(), False, True, False, False,
                             mytsrule.getOutOfOrder(), mytsrule.getSynch(),
                             mytsrule.getPkts())
      mycount = 0
      while myts.has_packets():
          mypkt = myts.getNextPacket()[0]
          self.assertEqual(mypkt.get_ttl(), 110)
          mycount += 1
      self.assertEqual(mycount, 1)
