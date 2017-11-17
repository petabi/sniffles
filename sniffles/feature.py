import random
import sys

from sniffles.regex_generator import *


class AmbiguousNotation:

    def __init__(self, notation=None):
        self.notation = notation

    def __str__(self):
        return self.toString()

    def toString(self):
        return self.notation


class SetNotation(AmbiguousNotation):
    # Set notation should be expressed as {x1,x2,x3...}
    # toString will return a subset of x(i) with
    # the length of subset should be at least 1
    # requirement: length of set should be at least 1
    # for example: {5,6,9}
    # it can return [5,6] or [5,9] or [6,9]
    def __init__(self, notation):
        super().__init__(notation)
        mystr = notation[1:-1]
        self.values = mystr.split(",")
        self.max_list_size = len(self.values)

    def __str__(self):
        return self.toString()

    def toString(self):
        num_elements = random.randint(1, self.max_list_size)
        return '[' + ','.join(random.sample(self.values, num_elements)) + ']'


class RangeNotation(AmbiguousNotation):

    # Range notation should be expressed as [x:y] where
    # x is lower bound and y is upper bound.
    def __init__(self, notation):
        super().__init__(notation)
        self.prefix = notation[0:1]
        self.suffix = notation[-1:]
        myrange = notation[1:-1]
        self.separator = ":"
        bounds = myrange.split(self.separator)
        self.lower_bound = int(bounds[0])
        self.upper_bound = int(bounds[1])
        if self.upper_bound - self.lower_bound < 1:
            print("RangeNotation: Upper bound has to be greater than"
                  " the lower bound." + str(self.upper_bound) + " > "
                  + str(self.lower_bound))
            sys.exit(0)

    def __str__(self):
        return self.toString()

    def toString(self):
        mylower = random.randint(self.lower_bound, self.upper_bound - 1)
        myupper = random.randint(mylower + 1, self.upper_bound)
        mystring = self.prefix + str(mylower) + self.separator + \
            str(myupper) + self.suffix
        return mystring


class ListNotation(AmbiguousNotation):

    # list notation should be [x,y] where x is lower bound and
    # y is upper bound.
    # it will generate a random list of values falling between
    # lower bound and upper bound
    # for example: [5,10] can generate [5,7,9]
    # for [20,20], it will be converted into [19,20]

    def __init__(self, notation):
        super().__init__(notation)
        self.prefix = notation[0:1]
        self.suffix = notation[-1:]
        mylist = notation[1:-1]
        self.separator = ","
        bounds = mylist.split(self.separator)
        self.lower_bound = int(bounds[0])
        self.upper_bound = int(bounds[1])
        self.max_list_size = 100
        if self.upper_bound < 1:
            self.upper_bound = 1
        if self.lower_bound >= self.upper_bound:
            self.lower_bound = self.upper_bound - 1

    def __str__(self):
        return self.toString()

    def toString(self):
        num_elements = random.randint(2, self.max_list_size)
        num_elements = min(num_elements,
                           self.upper_bound - self.lower_bound + 1
                           )

        sample_size = int((self.upper_bound - self.lower_bound)
                          / num_elements) - 1

        myelements = []

        # if the width of range is not big enough
        if sample_size <= 20:
            for i in range(self.lower_bound, self.upper_bound + 1):
                myelements.append(i)
            random.shuffle(myelements)
            myelements = myelements[0:num_elements]
            myelements = sorted(myelements)
        else:
            boundarylist = []
            lower = self.lower_bound
            for i in range(1, num_elements):
                upper = lower + sample_size
                boundarylist.append([lower, upper])
                lower = upper + 1
            boundarylist.append([lower, self.upper_bound])

            for bounds in boundarylist:
                if bounds[0] - bounds[1] <= 1:
                    myelements.append(bounds[0])
                else:
                    myelements.append(random.randint(bounds[0], bounds[1]))

        mystring = self.prefix
        while myelements:
            myelement = myelements.pop(0)
            mystring += str(myelement)
            if len(myelements) > 0:
                mystring += self.separator
        mystring += self.suffix
        return mystring


class Feature:

    def __init__(self, name=None, lower_bound=0, upper_bound=0,
                 complexity_prob=0, ambiguity_list=None):
        self.feature_name = name
        self.lower_bound = lower_bound
        self.upper_bound = upper_bound
        self.complexity_prob = complexity_prob
        self.ambiguity_list = ambiguity_list
        if self.upper_bound < 1:
            self.upper_bound = 1
        if self.lower_bound > self.upper_bound:
            self.lower_bound = self.upper_bound - 1

    def __str__(self):
        return self.toString()

    def toString(self):
        complex = False
        mystring = self.feature_name + "="
        if self.complexity_prob > 0 and self.ambiguity_list is \
           not None and len(self.ambiguity_list) > 0:
            pick = random.randint(0, 100)
            if pick <= self.complexity_prob:
                complex = True
        if complex:
            pick = random.randint(0, len(self.ambiguity_list) - 1)
            mystring += str(self.ambiguity_list[pick])
        else:
            mystring += str(random.randint(self.lower_bound, self.upper_bound))
        return mystring

    def testValidFeature(self, line=0):
        valid = True

        if self.feature_name is None:
            valid = False
            print("Feature at line " + str(line) + " missing name parameter.")

        if self.complexity_prob > 0 and self.ambiguity_list is None:
            print("Feature at line " + str(line) + " having complexity")
            print("probability greater than 0 but there is no ambiguity_list.")
            valid = False

        return valid


class ContentFeature(Feature):
    def __init__(self, name="content", regex=True, complexity_prob=0, len=0,
                 min_regex_length=3):
        super().__init__(name, complexity_prob=complexity_prob)
        self.regex = regex
        self.length = len
        self.min_regex_length = min_regex_length

    def __str__(self):
        return self.toString()

    def toString(self):
        mystring = self.feature_name + "="
        complex = False
        if self.complexity_prob > 0:
            pick = random.randint(0, 100)
            if pick <= self.complexity_prob:
                complex = True
        if self.regex:
            mystring += "/"

        if complex:
            mystring += generate_regex(self.length, 0,
                                       [60, 30, 10],
                                       None, None,
                                       [20, 20, 40, 20],
                                       50, 30, self.min_regex_length)
        else:
            mystring += generate_regex(self.length, 0,
                                       [100, 0, 0],
                                       [20, 35, 20, 20, 0],
                                       None, None, 0, 0, self.min_regex_length)
        if self.regex:
            mystring += "/"
            if complex:
                pick = random.randint(0, 100)
                if pick > 50:
                    mystring += "i"
                if pick > 75:
                    mystring += "m"
                if pick > 85:
                    mystring += "s"
        return mystring

    def testValidFeature(self, line=0):
        valid = True

        if self.feature_name is None:
            valid = False
            print("Feature at line " + str(line) + " missing name parameter.")

        return valid


class ProtocolFeature(Feature):

    def __init__(self, name="proto", proto_list=None, complexity_prob=0,
                 ambiguity_list=None):
        super().__init__(name, complexity_prob=complexity_prob,
                         ambiguity_list=ambiguity_list)
        self.proto_list = proto_list

    def __str__(self):
        return self.toString()

    def toString(self):
        complex = False
        if self.complexity_prob > 0 and self.ambiguity_list is not None:
            pick = random.randint(0, 100)
            if pick <= self.complexity_prob:
                complex = True
        if complex:
            myproto = str(random.choice(self.ambiguity_list))
        else:
            myproto = random.choice(self.proto_list)
        mystring = self.feature_name + "=" + myproto
        return mystring

    def testValidFeature(self, line=0):
        valid = True

        if self.feature_name is None:
            valid = False
            print("Feature at line " + str(line) + " missing name parameter.")
        if self.proto_list is None:
            valid = False
            print("Feature at line " + str(line) +
                  " missing proto_list parameter.")
        if self.complexity_prob > 0 and self.ambiguity_list is None:
            print("Feature at line " + str(line) + " having complexity")
            print("probability greater than 0 but there is no ambiguity_list.")
            valid = False
        return valid


class IPFeature(Feature):

    def __init__(self, name="ip", version=4, complexity_prob=0):
        super().__init__(name, complexity_prob=complexity_prob)
        self.version = version

    def __str__(self):
        return self.toString()

    def toString(self):
        mystring = self.feature_name + "="
        myip = []
        complex = False
        if self.complexity_prob > 0:
            pick = random.randint(0, 100)
            if pick <= self.complexity_prob:
                complex = True
        if complex:
            totalbytes = 4
            if self.version == 6:
                totalbytes = 16
            mynetmask = random.randint(0, totalbytes * 8)

            myprefixbytes = int(mynetmask / 8)
            myremainder = mynetmask % 8

            mask = ((2**myremainder) - 1) << (8 - myremainder)

            index = 0

            while index < myprefixbytes:
                if self.version == 4:
                    myip.append(random.randint(0, 255))
                else:
                    if (myprefixbytes - index) > 1:
                        myip.append(random.randint(0, 65535))
                        index += 1
                    else:
                        break
                index += 1

            mypartialbyte = (random.randint(0, 255) & mask)
            last_bytes = totalbytes - myprefixbytes

            if (myprefixbytes - index) == 1:
                mypartialbyte += (random.randint(0, 255)) << 8

            elif self.version == 6:
                mypartialbyte = mypartialbyte << 8

            if mypartialbyte > 0:
                myip.append(mypartialbyte)
                last_bytes -= 1

            if self.version == 6:
                remain = 8 - len(myip)
                for _ in range(remain):
                    myip.append(0)
            else:
                while last_bytes > 0:
                    myip.append(0)
                    last_bytes -= 1
                    if self.version == 6:
                        last_bytes -= 1

            if self.version == 4:
                myipstring = '.'.join(['%d' % byte for byte in myip])
            else:
                myipstring = ':'.join(['%04x' % byte for byte in myip])
            myipstring += "/" + str(mynetmask)

        else:
            if self.version == 4:
                for _ in range(4):
                    myip.append(random.randint(0, 255))

            elif self.version == 6:
                myip.append(0x2001)
                myip.append(random.randint(0x0000, 0x01F8) + 0x400)
                for _ in range(0, 6):
                    myip.append(random.randint(0, 65535))
            else:
                print("Error, no IP version: ", self.version)
            if self.version == 4:
                myipstring = '.'.join(['%d' % byte for byte in myip])
            else:
                myipstring = ':'.join(['%04x' % byte for byte in myip])
        mystring += myipstring
        return mystring

    def testValidFeature(self, line=0):
        valid = True

        if self.feature_name is None:
            valid = False
            print("Feature at line " + str(line) + " missing name parameter.")
        if not (int(self.version) == 4 or int(self.version) == 6):
            print("Feature at line " + str(line) + " has invalid version.")
            valid = False
        return valid

# Features are defined in a semi-colon separated list one feature per line
#   type=feature; list of arguments in key=value pairs, lists using
#                 python formatting (i.e. [a, ..., z]
#   types are:
#     1. Feature -- generic feature
#     2. Content -- Content Feature
#     3. IP -- IP Feature
#     4. Protocol -- Protocol Feature
#
#     ambiguous features should be written as lists like [x:y]
#       for a range, [x,y] for a list with maximum of 10
#       or just * for a wildcard or similar single option.


class FeatureParser:

    def __init__(self, filename=None):
        self.features = []
        self.parseFile(filename)

    def parseFile(self, filename=None):
        if filename is not None:
            try:
                fd = open(filename, encoding='utf-8')
            except Exception as err:
                print("Could not read feature file.")
                print("FeatureParser-parseFile: " + str(err))
                raise Exception("The program will stop.")
            line = fd.readline()
            lineNumber = 1
            while line:
                try:
                    self.parseLine(line, lineNumber)
                except Exception as err:
                    print("FeatureParser-parseFile: " + str(err))
                    raise Exception("The program will stop.")
                line = fd.readline()
                lineNumber += 1
            fd.close()
            return True
        return False

    def getFeatures(self):
        return self.features

    def parseLine(self, line=None, lineNumber=0):
        if line:
            myelements = line.split(';')
            mypairs = {}
            while myelements:
                element = myelements.pop(0).strip()
                if element:
                    values = element.split('=')
                    mypairs[values[0].strip().lower()] = values[1].strip()
            myfeature = None
            name = None
            lower_bound = 0
            upper_bound = 0
            complexity_prob = 0
            ambiguity_list = None
            regex = False
            len = 0
            proto_list = None
            version = 4
            min_regex_length = 3
            if 'name' in mypairs:
                name = mypairs['name']
            if 'lower_bound' in mypairs:
                lower_bound = int(mypairs['lower_bound'])
            if 'upper_bound' in mypairs:
                upper_bound = int(mypairs['upper_bound'])
            if 'complexity_prob' in mypairs:
                complexity_prob = int(mypairs['complexity_prob'])
            if 'ambiguity_list' in mypairs:
                ambiguity_list = self.buildAmbiguityList(
                    mypairs['ambiguity_list'])
            if 'regex' in mypairs:
                if mypairs['regex'].lower() == 'true':
                    regex = True
            if 'len' in mypairs:
                len = int(mypairs['len'])
            if 'min_regex_length' in mypairs:
                min_regex_length = int(mypairs['min_regex_length'])
                if min_regex_length < 1:
                    min_regex_length = 1
            if 'proto_list' in mypairs:
                plist = mypairs['proto_list']
                plist = plist[1:-1]
                pvals = plist.split(",")
                proto_list = []
                for p in pvals:
                    proto_list.append(p)
            if 'version' in mypairs:
                version = int(mypairs['version'])
            if 'type' not in mypairs:
                raise Exception("Feature type Not specified:", line)
            if mypairs['type'].lower() == 'feature':
                myfeature = Feature(name, lower_bound, upper_bound,
                                    complexity_prob, ambiguity_list)
            elif mypairs['type'].lower() == 'content':
                myfeature = ContentFeature(name, regex, complexity_prob, len,
                                           min_regex_length)
            elif mypairs['type'].lower() == 'ip':
                myfeature = IPFeature(name, version, complexity_prob)
            elif mypairs['type'].lower() == 'protocol':
                myfeature = ProtocolFeature(name, proto_list, complexity_prob,
                                            ambiguity_list)
            else:
                raise Exception("Unrecognized feature type." + str(line))
            if not myfeature.testValidFeature(lineNumber):
                sys.exit()
            self.features.append(myfeature)

    def tokenizeAmbiguityList(self, list):
        listAsString = list[1:-1]
        parsedlist = ""
        # remove all space
        # currently, sniffles support no space
        for i in range(0, len(listAsString)):
            if listAsString[i] != " ":
                parsedlist += listAsString[i]
        values = []
        currentIndex = 0
        beginIndex = 0
        lastIndex = len(parsedlist) - 1
        while currentIndex <= lastIndex:
            if parsedlist[currentIndex] == ",":
                tmpStr = parsedlist[beginIndex: currentIndex]
                values.append(tmpStr)
                currentIndex += 1
                beginIndex = currentIndex
            elif parsedlist[currentIndex] == "[":
                beginIndex = currentIndex
                while parsedlist[currentIndex] != "]":
                    currentIndex += 1
                currentIndex += 1
                tmpStr = parsedlist[beginIndex: currentIndex]
                values.append(tmpStr)
                currentIndex += 1
                beginIndex = currentIndex
            elif parsedlist[currentIndex] == "{":
                beginIndex = currentIndex
                while parsedlist[currentIndex] != "}":
                    currentIndex += 1
                currentIndex += 1
                tmpStr = parsedlist[beginIndex: currentIndex]
                values.append(tmpStr)
                currentIndex += 1
                beginIndex = currentIndex
            else:
                currentIndex += 1
                if currentIndex > lastIndex and \
                   currentIndex > beginIndex:
                    tmpStr = parsedlist[beginIndex: currentIndex]
                    values.append(tmpStr)
        return values

    def buildAmbiguityList(self, list):
        mylist = []
        values = self.tokenizeAmbiguityList(list)
        myamb = None
        for val in values:
            if ',' in val:
                if "[" in val:
                    myamb = ListNotation(val)
                elif "{" in val:
                    myamb = SetNotation(val)
            elif ':' in val:
                myamb = RangeNotation(val)
            else:
                myamb = AmbiguousNotation(val)
            mylist.append(myamb)
        return mylist
