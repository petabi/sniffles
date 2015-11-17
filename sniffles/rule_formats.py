class RuleFormat(object):

    def __init__(self, rule=None):
        self.rule = rule
        print(self)

    def __str__(self):
        return self.toString()

    def toString(self):
        return self.rule

class RegexFormat(RuleFormat):
    def __init__(self, rule=None):
        self.rule = rule

    def toString(self):
        if not self.rule:
            return ""

        myvals = str(self.rule).split(";")
        mymap = {}
        for v in myvals:
            v = v.strip()
            if len(v) > 0:
                v_list = v.split("=")
                mymap[v_list[0]] = v_list[1]
        content=""
        if "content" in mymap:
            content = mymap["content"]
        myrule = "{}".format(content)
        return myrule

class PetabiPacketClassifierFormat(RuleFormat):

    def __init__(self, rule=None):
        self.rule = rule

    def toString(self):
        if not self.rule:
            return ""

        myvals = str(self.rule).split(";")
        mymap = {}
        for v in myvals:
            v = v.strip()
            if len(v) > 0:
                v_list = v.split("=")
                mymap[v_list[0]] = v_list[1]
        dip = "*"
        sip = "*"
        sport = "*"
        dport = "*"
        proto = "*"
        action = "1"
        if "dip" in mymap:
            dip = mymap["dip"]
        if "sip" in mymap:
            sip = mymap["sip"]
        if "dport" in mymap:
            dport = mymap["dport"]
        if "sport" in mymap:
            sport = mymap["sport"]
        if "proto" in mymap:
            proto = mymap["proto"]
        if "action" in mymap:
            action = mymap["action"]
        myrule = "{}, {}, {}, {}, {}, {}".format(
            dip, sip, dport, sport, proto, action)
        return myrule

class SnortRuleFormat(RuleFormat):

    def __init__(self, rule=None, sid=None):
        self.rule = rule
        self.setSid(sid)

    def __str__(self):
        return self.toString()

    def setSid(self, sid=None):
        self.sid = sid

    def toString(self):
        if self.rule is None:
            return ""

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
        return myheader + myopt
