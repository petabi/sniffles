import codecs
import copy
import getopt
import sys
import datetime
import re
import random


class RuleFormat(object):

    def __init__(self, rule=None):
        self.rule = rule
        print(self)

    def __str__(self):
        return self.toString()

    def toString(self):
        return self.rule


class SnortRuleFormat(RuleFormat):

    def __init__(self, rule=None, sid=None):
        self.rule = rule
        self.setSid(sid)

    def __str__(self):
        return self.toString()

    def setSid(self, sid=None):
        self.sid = sid

    def toString(self):
        my_snort_string = ""
        if self.rule is not None:
            myvals = str(self.rule).split(";")
            mymap = {}
            for v in myvals:
                v = v.strip()
                if len(v) > 0:
                    v_list = v.split("=")
                    mymap[v_list[0]] = v_list[1]
            alert = "alert"
            if "alert" in mymap:
                alert = mymap["alert"]
                del(mymap["alert"])
            proto = "IP"
            if "proto" in mymap:
                proto = mymap["proto"]
                del(mymap["proto"])
            sip = "$HOME_NET"
            if "sip" in mymap:
                sip = mymap["sip"]
                del(mymap["sip"])
            sport = "any"
            if "sport" in mymap:
                sport = mymap["sport"]
                del(mymap["sport"])
            dir = "->"
            if "dir" in mymap:
                dir = mymap["dir"]
                del(mymap["dir"])
            dip = "$EXTERNAL_NET"
            if "dip" in mymap:
                dip = mymap["dip"]
                del(mymap["dip"])
            dport = "any"
            if "dport" in mymap:
                dport = mymap["dport"]
                del(mymap["dport"])
            myheader = "{} {} {} {} {} {} {} ".format(
                alert, proto, sip, sport, dir, dip, dport)
            myopt = "("
            for o in mymap:
                quote = ""
                if o.lower().find("content") or o.lower().find("pcre"):
                    quote = "\""
                myopt += " " + o + ":" + quote + mymap[o] + quote + ";"
            if "sid" not in mymap and self.sid is not None:
                myopt += " sid:" + str(self.sid) + ";"
            myopt += ")"
            my_snort_string = myheader + myopt
        return my_snort_string
