import sniffles.pcrecomp
from sniffles.pcreconf import *
WITH_STATS = False  # Compile nfa with stats or not.
E = 256  # epsilon
NSYMBOLS = 256
SELF = 0
NEXT = 1
PCRE_CASELESS = 'i'
PCRE_DOTALL = 's'
PCRE_MULTILINE = 'm'
PCRE_OPT = {PCRE_CASELESS: 0x01, PCRE_MULTILINE: 0x02, PCRE_DOTALL: 0x04}

LF = 10  # Line Feed
DIGIT = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57]
WHITESPACE = [0x09, 0x0a, 0x0c, 0x0d, 0x20]
WORDCHAR = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
    82, 83, 84, 85, 86, 87, 88, 89, 90,
    95,
    97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
    111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122
]
TOTAL_STATES = 0


class NFAState(object):
    def __init__(self):
        self.tx = [[] for i in range(NSYMBOLS + 1)]

    def __str__(self):
        return str(id(self))

    def add_tx(self, sym, state):
        if state not in self.tx[sym]:
            self.tx[sym].append(state)

    def add_txs(self, bitmap, state):
        for i in range(NSYMBOLS):
            if (bitmap[i // 8] & (1 << (i & 7))) > 0:
                self.add_tx(i, state)

    def compile_with_nfa_stats_error(self):
        print("This NFA was compiled without stats.")

    # Define interface to be used by subclasses
    def get_depth(self):
        self.compile_with_nfa_stats_error()

    def set_depth(self, depth=-1):
        return False

    def clear_tx(self):
        for i in range(0, NSYMBOLS):
            self.tx[i] = []


class NFAStateWithStats(NFAState):

    def __init__(self):
        super().__init__()
        self.depth = -1   # Shortest path distance from root to this state

    def get_depth(self):
        return self.depth

    def set_depth(self, depth=-1):
        """
        Set the depth for a given state.  Depth is calculated as the
        shortest path from root to a particular state.

        Return: True if the depth is updated, False otherwise.
        """
        # Depth should never be less than zero, and only zero for
        # the root node.
        if depth < 0:
            return False

        # If depth has yet to be set (i.e. still -1)
        # or the provided depth is less then the current depth
        # for this state, then set the new depth.
        if self.depth == -1 or depth < self.depth:
            self.depth = depth
            return True
        else:
            return False


class NFA:

    def __init__(self):
        self.start = get_nfa_state()
        self.accept = None
        self.options = []
        if WITH_STATS:
            self.max_depth = 0

    def __str__(self):
        dot = "digraph NFA {\n"
        dot += "graph[size=\"7.75,10.25\"]\n"
        dot += "  {} [shape=doublecircle]\n".format(self.accept)
        tovisit = [self.start]
        visited = []
        while tovisit:
            s = tovisit.pop()
            visited.append(s)
            targets = {}
            for i in range(NSYMBOLS + 1):
                if i == NSYMBOLS:
                    sym = 'e'
                else:
                    sym = i
                for t in s.tx[i]:
                    if t in targets:
                        targets[t].append(i)
                    else:
                        targets[t] = [i]
                    if t not in tovisit and t not in visited:
                        tovisit.append(t)
            for t in targets:
                dot += "  {} -> {} [label=\"".format(s, t)
                dot += "{}\"]\n".format(self.buildTXList(targets[t]))
        dot += "}\n"
        return dot

    def buildTXList(self, tx=None):
        myliststring = ""
        mylast = -1
        mycursor = -1
        mystart = -1
        myend = len(tx)
        mycount = 0
        for t in tx:
            mycursor = t
            if mystart == -1:
                mystart = mycursor
            if mylast != -1:
                if (mycursor - mylast) != 1:
                    if mylast == mystart:
                        if mylast == NSYMBOLS:
                            myliststring += "e"
                        else:
                            myliststring += "{}".format(mylast)
                    else:
                        if mylast == NSYMBOLS:
                            myliststring += "{}-e".format(mystart)
                        else:
                            myliststring += "{}-{}".format(mystart, mylast)
                    mystart = mycursor
                    if mycount < myend:
                        myliststring += ", "
            mylast = mycursor
            mycount += 1
        if mylast == mystart:
            if mylast >= NSYMBOLS:
                myliststring += "e"
            else:
                myliststring += "{}".format(mylast)
        else:
            if mylast >= NSYMBOLS:
                myliststring += "{}-e".format(mystart)
            else:
                myliststring += "{}-{}".format(mystart, mylast)
        return myliststring

    def calculate_depth(self, depth=0, state=None):
        """
        Recursively walk through the nfa from the root to all possible
        states.  Depth is shortest path from root to a given state.
        Base case is when depth for a given state is no longer set.
        This is valid because once the depth for a state is set, it requires
        a distance less than the current distance to be set again.
        If that does not occur the next time a state is provided here
        then it is not possible for any states reached through this state
        to provide a shorter path (since they all have been seen once already).
        However, if the depth is set, then this should cause all, or most
        states beneath this state to also have their depths set.

        Return: True if a depth is calculated, or False if no depth
        could be calculated due to lack of a root state.

        """
        if state is None:
            state = self.start

        if state is None or WITH_STATS is False:
            print("There is no NFA yet, or the NFA was compiled without Stats")
            return False

        states = [(state, depth)]

        while states:
            tuple = states.pop(0)
            current_state = tuple[0]
            current_depth = tuple[1]
            if current_state.set_depth(current_depth):
                if current_depth > self.max_depth:
                    self.max_depth = current_depth
                for sym in range(NSYMBOLS + 1):
                    for s in current_state.tx[sym]:
                        if not (s, current_depth + 1) in states:
                            states.append((s, current_depth + 1))
        return True

    def epsilon_closure(self, state):
        closure = []
        to_visit = [state]
        while to_visit:
            cur = to_visit.pop()
            if cur in closure:
                continue
            closure.append(cur)
            for e in cur.tx[E]:
                if e not in to_visit:
                    to_visit.append(e)
        return closure

    def get_states(self):
        tovisit = [self.start]
        visited = []
        while tovisit:
            s = tovisit.pop()
            visited.append(s)
            for i in range(NSYMBOLS + 1):
                for t in s.tx[i]:
                    if t not in tovisit and t not in visited:
                        tovisit.append(t)
        return visited

    def match(self, str, bin=False):
        active = self.epsilon_closure(self.start)
        for sym in str:
            if self.accept in active:
                return True
            if bin:
                next_active = self.next_states(active, sym)
            else:
                next_active = self.next_states(active, ord(sym))
            if not next_active:
                return False
            active = next_active
        return (self.accept in active)

    def next_states(self, active, sym):
        next_active = []
        for s in active:
            for ns in s.tx[sym]:
                for es in self.epsilon_closure(ns):
                    if es not in next_active:
                        next_active.append(es)
        return next_active

    def set_options(self, options):
        if options is None:
            raise ValueError("options must be a list")
        self.options = options


class NFABuilder:
    def __init__(self, nfa, is_search):
        self.nfa = nfa
        self.bra_state = []
        if is_search:
            for i in range(NSYMBOLS):
                self.nfa.start.add_tx(i, self.nfa.start)

    def build(self, code, options=[]):
        """Convert a PCRE encoding into an NFA.

        Arguments:
        - `code`: binary representation of a regular expression
        """
        self.code = code
        self.cp = 0
        self.options = options
        self.nfa.set_options(options)
        self.nfa.accept = self.op(self.nfa.start)

    def get2(self, offset=0):
        """Read two bytes in code as a 16-bit big-endian integer.
        """
        w = (self.code[self.cp + offset] << 8) | self.code[self.cp +
                                                           offset + 1]
        return w

    def op(self, sp):
        """Add states to convert the current instruction.
        """
        opcode = self.code[self.cp]
        if opcode == OP_ANY or opcode == OP_ALLANY:
            sp = self.op_any(sp)
        elif opcode == OP_BRA or opcode == OP_CBRA or opcode == OP_SCBRA:
            sp = self.op_bra(sp)
        elif opcode == OP_BRAZERO or opcode == OP_BRAMINZERO:
            sp = self.op_brazero(sp)
        elif opcode == OP_CHAR or opcode == OP_CHARI:
            sp = self.op_char(sp)
        elif opcode == OP_CIRC or opcode == OP_CIRCM:
            sp = self.op_circ(sp)
        elif opcode == OP_CLASS:
            sp = self.op_class(sp)
        elif opcode == OP_DIGIT:
            sp = self.op_digit(sp)
        elif opcode == OP_EXACT or opcode == OP_EXACTI:
            sp = self.op_exact(sp)
        elif opcode == OP_NCLASS:
            sp = self.op_class(sp)
        elif opcode == OP_NOT or opcode == OP_NOTI:
            sp = self.op_not(sp)
        elif opcode == OP_NOT_DIGIT:
            sp = self.op_not_digit(sp)
        elif opcode == OP_NOTEXACT or opcode == OP_NOTEXACTI:
            sp = self.op_notexact(sp)
        elif (
            opcode == OP_NOTPLUS or opcode == OP_NOTMINPLUS or
            opcode == OP_NOTPOSPLUS or opcode == OP_NOTPLUSI or
            opcode == OP_NOTMINPLUSI or opcode == OP_NOTPOSPLUSI
        ):
            sp = self.op_notplus(sp)
        elif (
            opcode == OP_NOTSTAR or opcode == OP_NOTMINSTAR or
            opcode == OP_NOTPOSSTAR or opcode == OP_NOTSTARI or
            opcode == OP_NOTMINSTARI or opcode == OP_NOTPOSSTARI
        ):
            sp = self.op_notstar(sp)
        elif (
            opcode == OP_NOTUPTO or opcode == OP_NOTMINUPTO or
            opcode == OP_NOTPOSUPTO or opcode == OP_NOTUPTOI or
            opcode == OP_NOTMINUPTOI or opcode == OP_NOTPOSUPTOI
        ):
            sp = self.op_notupto(sp)
        elif opcode == OP_NOT_WHITESPACE:
            sp = self.op_not_whitespace(sp)
        elif opcode == OP_NOT_WORDCHAR:
            sp = self.op_not_wordchar(sp)
        elif (
            opcode == OP_PLUS or opcode == OP_PLUSI or
            opcode == OP_POSPLUS or opcode == OP_POSPLUSI or
            opcode == OP_MINPLUSI or opcode == OP_MINPLUS
        ):
            sp = self.op_plus(sp)
        elif (
            opcode == OP_QUERY or opcode == OP_QUERYI or
            opcode == OP_POSQUERY or opcode == OP_POSQUERYI or
            opcode == OP_MINQUERYI or opcode == OP_MINQUERY
        ):
            sp = self.op_query(sp)
        elif (
            opcode == OP_NOTQUERY or opcode == OP_NOTQUERYI or
            opcode == OP_NOTPOSQUERY or opcode == OP_NOTPOSQUERYI or
            opcode == OP_NOTMINQUERYI or opcode == OP_NOTMINQUERY
        ):
            sp = self.op_not_query(sp)
        elif (
            opcode == OP_STAR or opcode == OP_STARI or
            opcode == OP_POSSTAR or opcode == OP_POSSTARI or
            opcode == OP_MINSTAR or opcode == OP_MINSTARI
        ):
            sp = self.op_star(sp)
        elif opcode == OP_TYPEEXACT:
            sp = self.op_typeexact(sp)
        elif (
            opcode == OP_TYPEMINPLUS or opcode == OP_TYPEPLUS or
            opcode == OP_TYPEPOSPLUS
        ):
            sp = self.op_typeplus(sp)
        elif (
            opcode == OP_TYPESTAR or opcode == OP_TYPEPOSSTAR or
            opcode == OP_TYPEMINSTAR
        ):
            sp = self.op_typestar(sp)
        elif opcode == OP_TYPEUPTO or opcode == OP_TYPEPOSUPTO:
            sp = self.op_typeupto(sp)
        elif opcode == OP_TYPEQUERY or opcode == OP_TYPEPOSQUERY:
            sp = self.op_typequery(sp)
        elif (
            opcode == OP_UPTO or opcode == OP_UPTOI or
            opcode == OP_POSUPTO or opcode == OP_POSUPTOI or
            opcode == OP_MINUPTOI or opcode == OP_MINUPTO
        ):
            sp = self.op_upto(sp)
        elif opcode == OP_WHITESPACE:
            sp = self.op_whitespace(sp)
        elif opcode == OP_WORDCHAR:
            sp = self.op_wordchar(sp)
        elif (
            opcode == OP_DOLL or opcode == OP_WORD_BOUNDARY or
            opcode == OP_DOLLM
        ):
            self.cp += 1
        else:
            raise Exception('Unknown opcode: {}'.format(opcode))
        return sp

    def op_any(self, sp):
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        for i in range(NSYMBOLS):
            if PCRE_DOTALL not in self.options and i == LF:
                continue
            prev.add_tx(i, sp)
        return sp

    def op_bra(self, sp):
        self.bra_state.append(sp)
        last_states = []
        while True:
            np = self.cp + self.get2(1)
            self.cp += PCRE_OPLEN[self.code[self.cp]]
            if self.cp < np:
                subsp = get_nfa_state()
                sp.add_tx(E, subsp)
                while self.cp < np:
                    subsp = self.op(subsp)
                last_states.append(subsp)
            if self.code[self.cp] != OP_ALT:
                break
        if self.code[self.cp] != OP_KET and self.code[self.cp] != OP_KETRMAX:
            raise Exception('Wrong OP_CODE: {}'.format(self.code[self.cp]))
        if last_states:
            sp = get_nfa_state()
            for s in last_states:
                s.add_tx(E, sp)
        if self.code[self.cp] == OP_KETRMAX:
            sp.add_tx(E, self.bra_state[-1])
        self.cp += PCRE_OPLEN[self.code[self.cp]]
        self.bra_state.pop()
        return sp

    def op_brazero(self, sp):
        self.bra_state.append(sp)
        self.cp += 1
        opcode = self.code[self.cp]
        if opcode == OP_BRA or opcode == OP_CBRA or opcode == OP_SCBRA:
            sp = self.op_bra(sp)
        else:
            raise Exception("Unknown opcode: {}".format(opcode))
        self.bra_state.pop().add_tx(E, sp)
        return sp

    def op_char(self, sp):
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        prev.add_tx(self.code[self.cp], sp)
        char = chr(self.code[self.cp])
        if (
            PCRE_CASELESS in self.options and char.isalpha() and
            ord(char) < 128
        ):
            prev.add_tx(ord(char.swapcase()), sp)
        self.cp += 1
        return sp

    def op_circ(self, sp):
        self.cp += 1
        self.nfa.start.clear_tx()
        return sp

    def op_class(self, sp):
        bmp = self.cp + 1
        self.cp += 33
        opcode = self.code[self.cp]
        if opcode == OP_CRMINPLUS or opcode == OP_CRPLUS or \
           opcode == OP_CRPOSPLUS:
            prev = sp
            sp = get_nfa_state()
            prev.add_txs(self.code[bmp: bmp + 32], sp)
            sp.add_txs(self.code[bmp: bmp + 32], sp)
            self.cp += PCRE_OPLEN[opcode]
        elif opcode == OP_CRQUERY or opcode == OP_CRPOSQUERY:
            prev = sp
            sp = get_nfa_state()
            prev.add_txs(self.code[bmp: bmp + 32], sp)
            prev.add_tx(E, sp)
            self.cp += PCRE_OPLEN[opcode]
        elif opcode == OP_CRRANGE or opcode == OP_CRPOSRANGE:
            prev = None
            min = self.get2(1)
            max = self.get2(3)
            for i in range(min):
                prev = sp
                sp = get_nfa_state()
                prev.add_txs(self.code[bmp: bmp + 32], sp)
            self.cp += PCRE_OPLEN[self.code[self.cp]]
            if not prev:
                prev = sp
                sp = get_nfa_state()
                prev.add_tx(E, sp)
                prev.add_txs(self.code[bmp: bmp + 32], sp)
                min += 1
            for i in range(max - min):
                mid = get_nfa_state()
                prev.add_txs(self.code[bmp: bmp + 32], mid)
                prev = mid
                prev.add_txs(self.code[bmp: bmp + 32], sp)
        elif (
            opcode == OP_CRSTAR or opcode == OP_CRMINSTAR or
            opcode == OP_CRPOSSTAR
        ):
            prev = sp
            sp = get_nfa_state()
            prev.add_tx(E, sp)
            sp.add_txs(self.code[bmp: bmp + 32], sp)
            self.cp += PCRE_OPLEN[opcode]
        else:
            prev = sp
            sp = get_nfa_state()
            prev.add_txs(self.code[bmp: bmp + 32], sp)
        return sp

    def op_digit(self, sp):
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        for i in DIGIT:
            prev.add_tx(i, sp)
        return sp

    def op_exact(self, sp):
        self.cp += 1
        n = self.get2()
        self.cp += 2
        sym = self.code[self.cp]
        self.cp += 1
        for i in range(n):
            prev = sp
            sp = get_nfa_state()
            prev.add_tx(sym, sp)
            if (
                PCRE_CASELESS in self.options and chr(sym).isalpha() and
                sym < 128
            ):
                prev.add_tx(ord(chr(sym).swapcase()), sp)
        return sp

    def op_not(self, sp):
        self.cp += 1
        sym = self.code[self.cp]
        prev = sp
        sp = get_nfa_state()
        char = chr(sym)
        if PCRE_CASELESS in self.options and char.isalpha():
            notsym = [sym, ord(char.swapcase())]
        else:
            notsym = [sym]
        for i in range(NSYMBOLS):
            if i in notsym:
                continue
            prev.add_tx(i, sp)
        self.cp += 1
        return sp

    def op_not_digit(self, sp):
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        for i in range(NSYMBOLS):
            if i not in DIGIT:
                prev.add_tx(i, sp)
        return sp

    def op_notexact(self, sp):
        self.cp += 1
        n = self.get2()
        self.cp += 2
        sym = self.code[self.cp]
        char = chr(sym)
        if PCRE_CASELESS in self.options and char.isalpha():
            notsym = [sym, ord(char.swapcase())]
        else:
            notsym = [sym]
        self.cp += 1
        for i in range(n):
            prev = sp
            sp = get_nfa_state()
            for j in range(NSYMBOLS):
                if j in notsym:
                    continue
                prev.add_tx(j, sp)
        return sp

    def op_notplus(self, sp):
        self.cp += 1
        sym = self.code[self.cp]
        prev = sp
        sp = get_nfa_state()
        char = chr(sym)
        if PCRE_CASELESS in self.options and char.isalpha():
            notsym = [sym, ord(char.swapcase())]
        else:
            notsym = [sym]
        for i in range(NSYMBOLS):
            if i in notsym:
                continue
            prev.add_tx(i, sp)
            sp.add_tx(i, sp)
        self.cp += 1
        return sp

    def op_notstar(self, sp):
        self.cp += 1
        sym = self.code[self.cp]
        prev = sp
        sp = get_nfa_state()
        prev.add_tx(E, sp)
        char = chr(sym)
        if PCRE_CASELESS in self.options and char.isalpha():
            notsym = [sym, ord(char.swapcase())]
        else:
            notsym = [sym]
        for i in range(NSYMBOLS):
            if i in notsym:
                continue
            sp.add_tx(i, sp)
        self.cp += 1
        return sp

    def op_notupto(self, sp):
        self.cp += 1
        ubound = self.get2()
        self.cp += 2
        sym = self.code[self.cp]
        self.cp += 1
        if ubound < 1:
            return sp
        prev = sp
        sp = get_nfa_state()
        prev.add_tx(E, sp)
        char = chr(sym)
        if PCRE_CASELESS in self.options and char.isalpha():
            notsym = [sym, ord(char.swapcase())]
        else:
            notsym = [sym]

        for i in range(ubound):
            mid = get_nfa_state()
            for j in range(NSYMBOLS):
                if j in notsym:
                    continue
                prev.add_tx(j, mid)
            mid.add_tx(E, sp)
            prev = mid
        return sp

    def op_not_whitespace(self, sp):
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        for i in range(NSYMBOLS):
            if i not in WHITESPACE:
                prev.add_tx(i, sp)
        return sp

    def op_not_wordchar(self, sp):
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        for i in range(NSYMBOLS):
            if i not in WORDCHAR:
                prev.add_tx(i, sp)
        return sp

    def op_plus(self, sp):
        self.cp += 1
        sym = self.code[self.cp]
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        prev.add_tx(sym, sp)
        sp.add_tx(sym, sp)
        if PCRE_CASELESS in self.options and chr(sym).isalpha() and sym < 128:
            prev.add_tx(ord(chr(sym).swapcase()), sp)
            sp.add_tx(ord(chr(sym).swapcase()), sp)
        return sp

    def op_query(self, sp):
        self.cp += 1
        sym = self.code[self.cp]
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        prev.add_tx(E, sp)
        prev.add_tx(sym, sp)
        if PCRE_CASELESS in self.options and chr(sym).isalpha() and sym < 128:
            prev.add_tx(ord(chr(sym).swapcase()), sp)
        return sp

    def op_not_query(self, sp):
        self.cp += 1
        sym = self.code[self.cp]
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        prev.add_tx(E, sp)
        char = chr(sym)
        if PCRE_CASELESS in self.options and char.isalpha():
            notsym = [sym, ord(char.swapcase())]
        else:
            notsym = [sym]
        for j in range(NSYMBOLS):
            if j in notsym:
                continue
            prev.add_tx(j, sp)
        return sp

    def op_star(self, sp):
        self.cp += 1
        sym = self.code[self.cp]
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        prev.add_tx(E, sp)
        sp.add_tx(sym, sp)
        if PCRE_CASELESS in self.options and chr(sym).isalpha() and sym < 128:
            prev.add_tx(ord(chr(sym).swapcase()), sp)
        return sp

    def op_typeexact(self, sp):
        self.cp += 1
        num = self.get2()
        self.cp += 2
        opcode = self.code[self.cp]
        for i in range(num):
            prev = sp
            sp = get_nfa_state()
            if opcode == OP_ANY or opcode == OP_ALLANY:
                for j in range(NSYMBOLS):
                    if PCRE_DOTALL not in self.options and j == LF:
                        continue
                    prev.add_tx(j, sp)
            elif opcode == OP_DIGIT:
                for j in DIGIT:
                    prev.add_tx(j, sp)
            elif opcode == OP_NOT_DIGIT:
                for j in range(NSYMBOLS):
                    if j in DIGIT:
                        continue
                    prev.add_tx(j, sp)
            elif opcode == OP_WHITESPACE:
                for j in WHITESPACE:
                    prev.add_tx(j, sp)
            elif opcode == OP_NOT_WHITESPACE:
                for j in range(NSYMBOLS):
                    if j in WHITESPACE:
                        continue
                    prev.add_tx(j, sp)
            elif opcode == OP_WORDCHAR:
                for j in WORDCHAR:
                    prev.add_tx(j, sp)
            elif opcode == OP_NOT_WORDCHAR:
                for j in range(NSYMBOLS):
                    if j in WORDCHAR:
                        continue
                    prev.add_tx(j, sp)
            else:
                raise Exception("Unknown opcode: {}".format(opcode))
        self.cp += 1
        return sp

    def op_typeplus(self, sp):
        self.cp += 1
        opcode = self.code[self.cp]
        prev = sp
        sp = get_nfa_state()
        if opcode == OP_ANY or opcode == OP_ALLANY:
            for i in range(NSYMBOLS):
                if PCRE_DOTALL not in self.options and i == LF:
                    continue
                prev.add_tx(i, sp)
                sp.add_tx(i, sp)
        elif opcode == OP_DIGIT:
            for i in DIGIT:
                prev.add_tx(i, sp)
                sp.add_tx(i, sp)
        elif opcode == OP_NOT_DIGIT:
            for i in range(NSYMBOLS):
                if i in DIGIT:
                    continue
                prev.add_tx(i, sp)
                sp.add_tx(i, sp)
        elif opcode == OP_WHITESPACE:
            for i in WHITESPACE:
                prev.add_tx(i, sp)
                sp.add_tx(i, sp)
        elif opcode == OP_NOT_WHITESPACE:
            for i in range(NSYMBOLS):
                if i in WHITESPACE:
                    continue
                prev.add_tx(i, sp)
                sp.add_tx(i, sp)
        elif opcode == OP_WORDCHAR:
            for i in WORDCHAR:
                prev.add_tx(i, sp)
                sp.add_tx(i, sp)
        elif opcode == OP_NOT_WORDCHAR:
            for i in range(NSYMBOLS):
                if i in WORDCHAR:
                    continue
                prev.add_tx(i, sp)
                sp.add_tx(i, sp)
        else:
            raise Exception("Unknown opcode: {}".format(opcode))
        self.cp += 1
        return sp

    def op_typequery(self, sp):
        self.cp += 1
        opcode = self.code[self.cp]
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        prev.add_tx(E, sp)
        if opcode == OP_ANY or opcode == OP_ALLANY:
            for i in range(NSYMBOLS):
                if PCRE_DOTALL not in self.options and i == LF:
                    continue
                prev.add_tx(i, sp)
        elif opcode == OP_DIGIT:
            for i in DIGIT:
                prev.add_tx(i, sp)
        elif opcode == OP_NOT_DIGIT:
            for i in range(NSYMBOLS):
                if i in DIGIT:
                    continue
                prev.add_tx(i, sp)
        elif opcode == OP_WHITESPACE:
            for i in WHITESPACE:
                prev.add_tx(i, sp)
        elif opcode == OP_NOT_WHITESPACE:
            for i in range(NSYMBOLS):
                if i in WHITESPACE:
                    continue
                prev.add_tx(i, sp)
        elif opcode == OP_WORDCHAR:
            for i in WORDCHAR:
                prev.add_tx(i, sp)
        elif opcode == OP_NOT_WORDCHAR:
            for i in range(NSYMBOLS):
                if i in WORDCHAR:
                    continue
                prev.add_tx(i, sp)
        else:
            raise Exception("Unknown opcode: {}".format(opcode))
        return sp

    def op_typestar(self, sp):
        self.cp += 1
        opcode = self.code[self.cp]
        prev = sp
        sp = get_nfa_state()
        if opcode == OP_ANY or opcode == OP_ALLANY:
            for i in range(NSYMBOLS):
                if PCRE_DOTALL not in self.options and i == LF:
                    continue
                prev.add_tx(E, sp)
                sp.add_tx(i, sp)
        elif opcode == OP_DIGIT:
            for i in DIGIT:
                prev.add_tx(E, sp)
                sp.add_tx(i, sp)
        elif opcode == OP_NOT_DIGIT:
            for i in range(NSYMBOLS):
                if i in DIGIT:
                    continue
                prev.add_tx(E, sp)
                sp.add_tx(i, sp)
        elif opcode == OP_WHITESPACE:
            for i in WHITESPACE:
                prev.add_tx(E, sp)
                sp.add_tx(i, sp)
        elif opcode == OP_NOT_WHITESPACE:
            for i in range(NSYMBOLS):
                if i in WHITESPACE:
                    continue
                prev.add_tx(E, sp)
                sp.add_tx(i, sp)
        elif opcode == OP_WORDCHAR:
            for i in WORDCHAR:
                prev.add_tx(E, sp)
                sp.add_tx(i, sp)
        elif opcode == OP_NOT_WORDCHAR:
            for i in range(NSYMBOLS):
                if i in WORDCHAR:
                    continue
                prev.add_tx(E, sp)
                sp.add_tx(i, sp)
        else:
            raise Exception("Unknown opcode: {}".format(opcode))
        self.cp += 1
        return sp

    def op_typeupto(self, sp):
        self.cp += 1
        ubound = self.get2()
        self.cp += 2
        opcode = self.code[self.cp]
        self.cp += 1
        if ubound < 1:
            return sp
        prev = sp
        sp = get_nfa_state()
        prev.add_tx(E, sp)
        for i in range(ubound):
            mid = get_nfa_state()
            if opcode == OP_ANY or opcode == OP_ALLANY:
                for j in range(NSYMBOLS):
                    if PCRE_DOTALL not in self.options and j == LF:
                        continue
                    prev.add_tx(j, mid)
            elif opcode == OP_DIGIT:
                for j in DIGIT:
                    prev.add_tx(j, mid)
            elif opcode == OP_NOT_DIGIT:
                for j in range(NSYMBOLS):
                    if j in DIGIT:
                        continue
                    prev.add_tx(j, mid)
            elif opcode == OP_WHITESPACE:
                for j in WHITESPACE:
                    prev.add_tx(j, mid)
            elif opcode == OP_NOT_WHITESPACE:
                for j in range(NSYMBOLS):
                    if j in WHITESPACE:
                        continue
                    prev.add_tx(j, mid)
            elif opcode == OP_WORDCHAR:
                for j in WORDCHAR:
                    prev.add_tx(j, mid)
            elif opcode == OP_NOT_WORDCHAR:
                for j in range(NSYMBOLS):
                    if j in WORDCHAR:
                        continue
                    prev.add_tx(j, mid)
            else:
                raise Exception("Unknown opcode: {}".format(opcode))
            mid.add_tx(E, sp)
            prev = mid
        return sp

    def op_upto(self, sp):
        self.cp += 1
        ubound = self.get2()
        self.cp += 2
        if ubound < 1:
            return sp
        prev = sp
        sp = get_nfa_state()
        prev.add_tx(self.code[self.cp], sp)
        prev.add_tx(E, sp)
        for i in range(ubound):
            mid = get_nfa_state()
            prev.add_tx(self.code[self.cp], mid)
            char = chr(self.code[self.cp])
            if PCRE_CASELESS in self.options and char.isalpha():
                prev.add_tx(ord(char.swapcase()), mid)
            mid.add_tx(E, sp)
            prev = mid
        self.cp += 1
        return sp

    def op_whitespace(self, sp):
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        for i in WHITESPACE:
            prev.add_tx(i, sp)
        return sp

    def op_wordchar(self, sp):
        self.cp += 1
        prev = sp
        sp = get_nfa_state()
        for i in WORDCHAR:
            prev.add_tx(i, sp)
        return sp


# Module functions
def get_nfa_state():
    """
    " Factory for creating NFA states.  If called when WITH_STATS == true
    " then the NFA_State objects will be created with statistics.
    " Otherwise, they will be called with the basic nfa_state functionality.
    "
    " Returns an NFA_State (with or without stats).
    """
    s = None
    global TOTAL_STATES
    TOTAL_STATES += 1
    if WITH_STATS is True:
        s = NFAStateWithStats()
    else:
        s = NFAState()
    return s


def reset_state_counter():
    global TOTAL_STATES
    TOTAL_STATES = 0


def get_state_count():
    global TOTAL_STATES
    return TOTAL_STATES


def pcre2nfa(re, turn_on_stats=False):
    """Convert a regular expression into an NFA.

    Arguments:
    - `re`: a string containing a regular expression
    - `turn_on_stats`: Add statistics to NFA States
    - `nfa`: a current nfa to append this re to. If not provided, a new nfa
            is created.

    Returns: newly created nfa.
    """
    options = []
    global WITH_STATS
    WITH_STATS = turn_on_stats
    if len(re) and re[0] == '/':
        optp = re.rfind('/')
        if optp > 0:
            options = list(re[optp + 1:])
            re = re[1:optp]
    opts = 0
    for opt in options:
        if opt in PCRE_OPT:
            opts |= PCRE_OPT[opt]
    code = sniffles.pcrecomp.compile(re, opts)
    nfa = NFA()
    builder = NFABuilder(nfa, True)
    builder.build(code, options)
    return nfa
