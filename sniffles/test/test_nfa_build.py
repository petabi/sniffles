from unittest import *
from sniffles.nfa import *

class TestNFABuild(TestCase):
    def test_arg_type(self):
        self.assertRaises(TypeError, pcre2nfa, None)
        a = pcre2nfa('')
        self.assertEqual(NFA, type(a))

class TestOpAny(TestCase):
    def test_any(self):
        a = pcre2nfa('.')
        self.assertTrue(a.match("\x01"))
        self.assertTrue(a.match("a"))
        self.assertFalse(a.match("\n"))

    def test_dotall(self):
        a = pcre2nfa('/./s')
        self.assertTrue(a.match("\n"))

class TestOpBra(TestCase):
    def test_empty(self):
        a = pcre2nfa('')
        self.assertTrue(a.match(''))
        self.assertTrue(a.match('a'))

    def test_or(self):
        a = pcre2nfa('a|b')
        self.assertTrue(a.match('a'))
        self.assertTrue(a.match('b'))
        self.assertFalse(a.match('c'))

class TestOpBraZero(TestCase):
    def test_brazero(self):
        a = pcre2nfa('x(0|1){0,2}y')
        self.assertTrue(a.match('xy'))

    def test_braminzero(self):
        a = pcre2nfa('x(0|1){0,2}?y')
        self.assertTrue(a.match('xy'))
        self.assertTrue(a.match('x10y'))
        self.assertFalse(a.match('x110y'))

    def test_brazero_any(self):
        a = pcre2nfa('a(b|c)*d');
        self.assertTrue(a.match('abd'))
        self.assertTrue(a.match('ad'))
        self.assertTrue(a.match('acd'))
        self.assertTrue(a.match('abbbbd'))
        self.assertFalse(a.match('aed'))

        a = pcre2nfa('a(b*|cd)*e');
        self.assertTrue(a.match('abe'))
        self.assertTrue(a.match('ae'))
        self.assertTrue(a.match('acde'))
        self.assertTrue(a.match('abcde'))
        self.assertTrue(a.match('abbbbe'))
        self.assertTrue(a.match('acdbcde'))
        self.assertFalse(a.match('abcbde'))

class TestOpCbra(TestCase):
    def test_cbra(self):
        a = pcre2nfa('a(b|c)z')
        self.assertTrue(a.match('abz'))
        self.assertTrue(a.match('acz'))
        self.assertFalse(a.match('adz'))

class TestOpChar(TestCase):
    def test_char(self):
        a = pcre2nfa('a')
        self.assertTrue(a.match('a'))
        self.assertFalse(a.match('A'))
        self.assertTrue(a.match('ab'))
        self.assertTrue(a.match('ba'))
        self.assertFalse(a.match('b'))

    def test_char_nocase(self):
        a = pcre2nfa('/a/i')
        self.assertTrue(a.match('a'))
        self.assertTrue(a.match('A'))
        self.assertTrue(a.match('ab'))
        self.assertTrue(a.match('bA'))
        self.assertFalse(a.match('b'))

    def test_str(self):
        a = pcre2nfa('hello')
        self.assertTrue(a.match('hello'))
        self.assertTrue(a.match('nohelloworld'))
        self.assertFalse(a.match('helium'))

class TestOpCirc(TestCase):
    def test_circ(self):
        a = pcre2nfa('^a')
        self.assertTrue(a.match('a'))
        self.assertTrue(a.match('ab'))
        self.assertFalse(a.match('ba'))

        a = pcre2nfa('^\s*abc')
        self.assertTrue(a.match('abc'))
        self.assertTrue(a.match(' abc'))
        self.assertTrue(a.match('       abcxyz'))
        self.assertFalse(a.match('ababc'))

class TestOpClass(TestCase):
    def test_crminplus(self):
        # OP_CRPOSPLUS in pcre >= 8.34
        a = pcre2nfa('a[0-1]+?a')
        self.assertTrue(a.match('a0a'))
        self.assertTrue(a.match('a10a'))
        self.assertTrue(a.match('a111000a'))
        self.assertFalse(a.match('aa'))
        self.assertFalse(a.match('a0012100a'))

    def test_crplus(self):
        # OP_CRPOSPLUS in pcre >= 8.34
        a = pcre2nfa('a[0-1]+a')
        self.assertTrue(a.match('a0a'))
        self.assertTrue(a.match('a10a'))
        self.assertTrue(a.match('a111000a'))
        self.assertFalse(a.match('aa'))
        self.assertFalse(a.match('a0012100a'))

    def test_crquery(self):
        a = pcre2nfa('a[0-1]?a')
        self.assertTrue(a.match('aa'))
        self.assertTrue(a.match('a0a'))
        self.assertTrue(a.match('a1a'))
        self.assertFalse(a.match('a10a'))
        self.assertFalse(a.match('a9a'))

    def test_crrange_exact(self):
        a = pcre2nfa('[abc]{2}')
        self.assertTrue(a.match('ac'))
        self.assertTrue(a.match('dabc'))
        self.assertFalse(a.match('dad'))

    def test_crrange_range(self):
        a = pcre2nfa('^[abc]{2,4}x')
        self.assertFalse(a.match('bx'))
        self.assertTrue(a.match('acx'))
        self.assertTrue(a.match('abcx'))
        self.assertTrue(a.match('bbbbx'))
        self.assertFalse(a.match('bbbbbx'))
        self.assertFalse(a.match('abca'))

        a = pcre2nfa('^[abc]{0,2}x')
        self.assertTrue(a.match('x'))
        self.assertTrue(a.match('bx'))
        self.assertTrue(a.match('acx'))
        self.assertFalse(a.match('bbbx'))
        self.assertFalse(a.match('bbbbx'))
        self.assertFalse(a.match('abca'))

    def test_crstar(self):
        a = pcre2nfa('a[0-1]*a')
        self.assertTrue(a.match('aa'))
        self.assertTrue(a.match('a0a'))
        self.assertTrue(a.match('a10a'))
        self.assertTrue(a.match('a111000a'))
        self.assertFalse(a.match('a0012100a'))

    def test_else(self):
        a = pcre2nfa('[bc]')
        self.assertFalse(a.match('a'))
        self.assertTrue(a.match('b'))
        self.assertTrue(a.match('c'))

    def test_class_range(self):
        a = pcre2nfa('a[b-f]g')
        self.assertFalse(a.match('aag'))
        self.assertFalse(a.match('agg'))
        for c in range(ord('b'), ord('f')):
            self.assertTrue(a.match('a' + chr(c) + 'g'))

    def test_nclass(self):
        a = pcre2nfa('[^bc]')
        self.assertTrue(a.match('a'))
        self.assertFalse(a.match('b'))
        self.assertFalse(a.match('c'))

    def test_crminstar(self):
        a = pcre2nfa('[x]*?')
        self.assertTrue(a.match('abc'))
        self.assertTrue(a.match('bc'))


class TestOpDigit(TestCase):
    def test_digit(self):
        a = pcre2nfa('a\da')
        self.assertTrue(a.match('a2a'))
        self.assertFalse(a.match('a09a'))

class TestOpExact(TestCase):
    def test_exact(self):
        a = pcre2nfa('a0{2}a')
        self.assertFalse(a.match('a0a'))
        self.assertTrue(a.match('a00a'))
        self.assertFalse(a.match('a000a'))
        self.assertFalse(a.match('a00b'))

class TestOpKetRMax(TestCase):
    def test_nonzero_ketrmax(self):
        a = pcre2nfa('/(0*|E)+/s')
        self.assertTrue(a.match(' a?.d!A]_X:E>'))

class TestOpNot(TestCase):
    def test_not(self):
        a = pcre2nfa('a[^0]a')
        self.assertFalse(a.match('a0a'))
        self.assertTrue(a.match('a1a'))
        self.assertFalse(a.match('a01a'))
        self.assertFalse(a.match('ab'))

    def test_not_case(self):
        a = pcre2nfa('/a[^z]a/i')
        self.assertFalse(a.match('aza'))
        self.assertFalse(a.match('aZa'))

    def test_not_class_range(self):
        a = pcre2nfa('/a[^a-z]b/')
        for c in range(ord('a'), ord('z')):
            self.assertFalse(a.match('a' + chr(c) + 'b'))
        for c in range(32, 60):
            self.assertTrue(a.match('a' + chr(c) + 'b'))

        a = pcre2nfa('/a[^a-z]b/i')
        for c in range(ord('A'), ord('Z')):
            self.assertFalse(a.match('a' + chr(c) + 'b'))
        for c in range(ord('a'), ord('z')):
            self.assertFalse(a.match('a' + chr(c) + 'b'))
        for c in range(32, 57):
            self.assertTrue(a.match('a' + chr(c) + 'b'))

class TestOpNotDigit(TestCase):
    def test_not_digit(self):
        a = pcre2nfa('a\Db')
        self.assertTrue(a.match('acb'))
        self.assertFalse(a.match('a1b'))
        self.assertFalse(a.match('a123b'))
        self.assertTrue(a.match('a ba:b'))

class TestOpNotExact(TestCase):
    def test_notexact(self):
        a = pcre2nfa('a[^x]{2}b')
        self.assertTrue(a.match('accb'))
        self.assertFalse(a.match('acb'))
        self.assertFalse(a.match('acccb'))

class TestOpNotPlus(TestCase):
    def test_notplus(self):
        a = pcre2nfa('a[^x]+a')
        self.assertTrue(a.match('aaa'))
        self.assertTrue(a.match('aba'))
        self.assertTrue(a.match('acdefa'))
        self.assertFalse(a.match('axa'))
        self.assertFalse(a.match('acdexsda'))
        self.assertFalse(a.match('aa'))

    def test_notposplus(self):
        a = pcre2nfa('a[^x]+x')
        self.assertTrue(a.match('aax'))
        self.assertTrue(a.match('abx'))
        self.assertTrue(a.match('acdefx'))
        self.assertFalse(a.match('axx'))
        self.assertFalse(a.match('ax'))

class TestOpNotStar(TestCase):
    def test_notminstar(self):
        a = pcre2nfa('a[^x]*?b')
        self.assertTrue(a.match('ab'))
        self.assertTrue(a.match('acb'))
        self.assertTrue(a.match('acdb'))
        self.assertFalse(a.match('axb'))

    def test_notposstar(self):
        a = pcre2nfa('a[^a]*a')
        self.assertTrue(a.match('aa'))
        self.assertTrue(a.match('aba'))
        self.assertTrue(a.match('abca'))
        self.assertFalse(a.match('abb'))

    def test_notstar(self):
        a = pcre2nfa('a[^x]*b')
        self.assertTrue(a.match('ab'))
        self.assertTrue(a.match('acb'))
        self.assertTrue(a.match('acdb'))
        self.assertFalse(a.match('axb'))

class TestOpNotUpTo(TestCase):
    def test_notposupto(self):
        a = pcre2nfa('a[^x]{1,2}x')
        self.assertFalse(a.match('ax'))
        self.assertTrue(a.match('ayx'))
        self.assertTrue(a.match('ayyx'))
        self.assertFalse(a.match('ayyyx'))

    def test_notupto(self):
        a = pcre2nfa('x[^0]{1,2}x')
        self.assertFalse(a.match('xx'))
        self.assertTrue(a.match('x1x'))
        self.assertTrue(a.match('x12x'))
        self.assertFalse(a.match('x123x'))

    def test_notminupto(self):
        a = pcre2nfa('x[^y]{1,2}?z')
        self.assertTrue(a.match('xaz'))
        self.assertTrue(a.match('xabz'))
        self.assertFalse(a.match('xabcz'))
        self.assertFalse(a.match('xyz'))

    def test_notminuptoi(self):
        a = pcre2nfa('/x[^y]{1,2}?z/i')
        self.assertTrue(a.match('XaZ'))
        self.assertTrue(a.match('xABz'))
        self.assertFalse(a.match('XabCZ'))
        self.assertFalse(a.match('xYz'))

class TestOpNotWhitespace(TestCase):
    def test_notwhitespace(self):
        a = pcre2nfa('\S')
        self.assertFalse(a.match('\x0c'))
        self.assertFalse(a.match(' '))
        self.assertFalse(a.match('\n'))
        self.assertFalse(a.match('\t'))
        self.assertTrue(a.match('a'))

        a = pcre2nfa('a\Sb')
        self.assertTrue(a.match('aab'))
        self.assertFalse(a.match('\t\n'))
        self.assertFalse(a.match('a b'))

class TestOpNotWordchar(TestCase):
    def test_notwordchar(self):
        a = pcre2nfa('\W')
        self.assertTrue(a.match('\x0c'))
        self.assertFalse(a.match('A'))
        self.assertFalse(a.match('Z'))
        self.assertFalse(a.match('_'))
        self.assertFalse(a.match('a'))
        self.assertFalse(a.match('z'))
        self.assertTrue(a.match('\n'))

        a = pcre2nfa('a\Wb')
        self.assertFalse(a.match('aab'))
        self.assertFalse(a.match('  '))
        self.assertTrue(a.match('a b'))

class TestOpPlus(TestCase):
    def test_plus(self):
        a = pcre2nfa('a0+0')
        self.assertFalse(a.match('a0'))
        self.assertTrue(a.match('a00'))
        self.assertTrue(a.match('a000'))
        self.assertTrue(a.match('a0000'))
        self.assertFalse(a.match('a01'))

    def test_posplus(self):
        a = pcre2nfa('a0+a')
        self.assertFalse(a.match('aa'))
        self.assertTrue(a.match('a0a'))
        self.assertTrue(a.match('a00a'))
        self.assertTrue(a.match('a000a'))
        self.assertFalse(a.match('a00b'))

    def test_notminplus(self):
        a = pcre2nfa('a[^x]+?b')
        self.assertTrue(a.match('ayb'))
        self.assertTrue(a.match('ayzb'))
        self.assertFalse(a.match('axb'))
        self.assertFalse(a.match('ab'))
        self.assertFalse(a.match('axxxxxb'))

class TestOpQuery(TestCase):
    def test_query(self):
        a = pcre2nfa('xa?x')
        self.assertTrue(a.match('xx'))
        self.assertTrue(a.match('xax'))
        self.assertFalse(a.match('xaax'))

    def test_op_not_query(self):
        a = pcre2nfa('a[^b]?cd')
        self.assertTrue(a.match('acd'))
        self.assertTrue(a.match('accd'))
        self.assertFalse(a.match('abcd'))

    def test_op_not_queryi(self):
        a = pcre2nfa('/a[^b]?cd/i')
        self.assertTrue(a.match('ACd'))
        self.assertTrue(a.match('aCcD'))
        self.assertFalse(a.match('aBcd'))

class TestOpStar(TestCase):
    def test_posstar(self):
        a = pcre2nfa('a0*a')
        self.assertTrue(a.match('aa'))
        self.assertTrue(a.match('a0a'))
        self.assertTrue(a.match('a00a'))
        self.assertTrue(a.match('a000a'))
        self.assertFalse(a.match('a00b'))

    def test_star(self):
        a = pcre2nfa('a0{2,}(a|b)')
        self.assertFalse(a.match('aa'))
        self.assertFalse(a.match('a0a'))
        self.assertTrue(a.match('a00a'))
        self.assertTrue(a.match('a000a'))
        self.assertFalse(a.match('a00x'))

    def test_optypeminstar(self):
        a = pcre2nfa('a.*?b')
        self.assertTrue(a.match('aaaaab'))
        self.assertTrue(a.match('a123ab'))
        self.assertFalse(a.match('bbbb'))
        self.assertTrue(a.match('aaabaab'))

    def test_opminstar(self):
        a = pcre2nfa('a*?b')
        self.assertTrue(a.match('xb'))
        self.assertTrue(a.match('ab'))
        self.assertTrue(a.match('aaaaaaaabaaaabaaaab'))
        self.assertFalse(a.match('xx'))

class TestOpTypeExact(TestCase):
    def test_any(self):
        a = pcre2nfa('a.{2}a')
        self.assertTrue(a.match('axxa'))
        self.assertFalse(a.match('axa'))
        self.assertFalse(a.match('axxxa'))

    def test_digit(self):
        a = pcre2nfa('a\d{2}a')
        self.assertTrue(a.match('a09a'))
        self.assertFalse(a.match('a1xa'))
        self.assertFalse(a.match('a2a'))
        self.assertFalse(a.match('a323a'))

    def test_not_digit(self):
        a = pcre2nfa('a\D{2}a')
        self.assertFalse(a.match('a09a'))
        self.assertTrue(a.match('aaaa'))

    def test_whitespace(self):
        a = pcre2nfa('a\s{2}b')
        self.assertFalse(a.match('ab'))
        self.assertFalse(a.match('a b'))
        self.assertTrue(a.match('a  b'))
        self.assertFalse(a.match('a   b'))

    def test_not_whitespace(self):
        a = pcre2nfa('a\S{2}b')
        self.assertFalse(a.match('a  b'))
        self.assertTrue(a.match('aaab'))
        self.assertFalse(a.match('a ab'))
        self.assertFalse(a.match('abaabaab'))

    def test_wordchar(self):
        a = pcre2nfa(':\w{2}:')
        self.assertFalse(a.match(':%%:'))
        self.assertTrue(a.match(':aA:'))
        self.assertTrue(a.match(':zZ:'))
        self.assertTrue(a.match(':_a:'))
        self.assertFalse(a.match(':aaa:'))

    def test_notwordchar(self):
        a = pcre2nfa(':\W{2}:')
        self.assertTrue(a.match(':%%:'))
        self.assertFalse(a.match(':aA:'))
        self.assertFalse(a.match(':zZ:'))
        self.assertFalse(a.match(':_a:'))
        self.assertFalse(a.match('::'))
        self.assertFalse(a.match(':   :'))


class TestOpTypePlus(TestCase):
    def test_any(self):
        a = pcre2nfa('a.+a')
        self.assertTrue(a.match('aaa'))
        self.assertTrue(a.match('aba'))
        self.assertTrue(a.match('acdefa'))
        self.assertFalse(a.match('aa'))

    def test_minplus(self):
        a = pcre2nfa('a.+?a')
        self.assertFalse(a.match('aa'))
        self.assertTrue(a.match('a0a'))
        self.assertTrue(a.match('a9999a'))
        self.assertFalse(a.match('a123'))

    def test_posplus(self):
        a = pcre2nfa('a\d+a')
        self.assertFalse(a.match('aa'))
        self.assertTrue(a.match('a0a'))
        self.assertTrue(a.match('a9999a'))
        self.assertFalse(a.match('a123'))

    def test_notdigitplus(self):
        a = pcre2nfa('a\D+b')
        self.assertTrue(a.match('axxb'))
        self.assertTrue(a.match('axb'))
        self.assertFalse(a.match('ab'))
        self.assertFalse(a.match('a1234567b'))

    def test_whitespace(self):
        a = pcre2nfa('a\s+a')
        self.assertTrue(a.match('a a'))
        self.assertTrue(a.match('a \t a'))
        self.assertFalse(a.match('aa'))

    def test_notwhitespace(self):
        a = pcre2nfa('a\S+b')
        self.assertTrue(a.match('axxb'))
        self.assertTrue(a.match('axb'))
        self.assertFalse(a.match('a b'))
        self.assertFalse(a.match('ab'))
        self.assertFalse(a.match('a    b'))

    def test_wordchar(self):
        a = pcre2nfa(':\w+:')
        self.assertTrue(a.match(':a:'))
        self.assertTrue(a.match(':z0z:'))
        self.assertFalse(a.match('::'))

    def test_not_wordchar(self):
        a = pcre2nfa(':\W+:')
        self.assertTrue(a.match(':  :'))
        self.assertTrue(a.match(':#$%:'))
        self.assertFalse(a.match(':abc:'))

class TestOpTypeQuery(TestCase):
    def test_digit(self):
        a = pcre2nfa('a\d{2,3}b')
        self.assertTrue(a.match('a12b'))
        self.assertTrue(a.match('a123b'))
        self.assertFalse(a.match('a1b'))
        self.assertFalse(a.match('ab'))
        self.assertFalse(a.match('a1234b'))

class TestOpTypeStar(TestCase):
    def test_any(self):
        a = pcre2nfa('a.*a')
        self.assertTrue(a.match('aa'))
        self.assertTrue(a.match('aaa'))
        self.assertTrue(a.match('aba'))
        self.assertTrue(a.match('acdefa'))
        self.assertFalse(a.match('axxxxxx'))

    def test_posstar(self):
        a = pcre2nfa('a\d*a')
        self.assertTrue(a.match('aa'))
        self.assertTrue(a.match('a0a'))
        self.assertTrue(a.match('a9999a'))
        self.assertFalse(a.match('a123'))

    def test_notdigit(self):
        a = pcre2nfa('a\D*b')
        self.assertTrue(a.match('ab'))
        self.assertFalse(a.match('a0b'))
        self.assertFalse(a.match('a9999b'))
        self.assertTrue(a.match('axyzb'))

    def test_whitespace(self):
        a = pcre2nfa('a\s*a')
        self.assertTrue(a.match('aa'))
        self.assertTrue(a.match('a a'))
        self.assertTrue(a.match('a\t \t a'))
        self.assertFalse(a.match('a   '))

    def test_not_whitespace(self):
        a = pcre2nfa('a\S*b')
        self.assertTrue(a.match('ab'))
        self.assertTrue(a.match('axyzb'))
        self.assertFalse(a.match('a   b'))

    def test_wordchar(self):
        a = pcre2nfa('a\w*b')
        self.assertTrue(a.match('ab'))
        self.assertTrue(a.match('axyzb'))
        self.assertFalse(a.match('a!@#b'))

    def test_not_wordchar(self):
        a = pcre2nfa('a\W*b')
        self.assertTrue(a.match('ab'))
        self.assertTrue(a.match('a*#@b'))
        self.assertFalse(a.match('axyzb'))

class TestOpTypeUpTo(TestCase):
    def test_any(self):
        a = pcre2nfa('a.{2,4}a')
        self.assertFalse(a.match('aaa'))
        self.assertTrue(a.match('abba'))
        self.assertTrue(a.match('ababaa'))
        self.assertTrue(a.match('axxxxa'))
        self.assertFalse(a.match('axxxxxa'))

    def test_digit(self):
        a = pcre2nfa('a\d{2,4}a')
        self.assertFalse(a.match('a0a'))
        self.assertTrue(a.match('a99a'))
        self.assertTrue(a.match('a1234a'))
        self.assertFalse(a.match('a11111a'))

    def test_not_digit(self):
        a = pcre2nfa('1\D{2,4}2')
        self.assertFalse(a.match('1002'))
        self.assertTrue(a.match('1bb2'))
        self.assertTrue(a.match('1aaaa2'))
        self.assertFalse(a.match('1aaaaa2'))

    def test_whitespace(self):
        a = pcre2nfa('\s{1,3}')
        self.assertTrue(a.match('\x0c'))
        self.assertTrue(a.match(' '))
        self.assertTrue(a.match('\n'))
        self.assertTrue(a.match('\t'))
        self.assertFalse(a.match('a'))
        self.assertTrue(a.match('  '))
        self.assertTrue(a.match('   '))

    def test_notwhitespace(self):
        a = pcre2nfa('\S{1,3}')
        self.assertFalse(a.match('\x0c'))
        self.assertFalse(a.match(' '))
        self.assertFalse(a.match('\n'))
        self.assertFalse(a.match('\t'))
        self.assertTrue(a.match('a'))

        a = pcre2nfa('a\S{1,3}b')
        self.assertFalse(a.match('ab'))
        self.assertFalse(a.match('a\tb'))
        self.assertTrue(a.match('axxb'))
        self.assertTrue(a.match('axyzb'))
        self.assertFalse(a.match('attttb'))

    def test_wordchar(self):
        a = pcre2nfa(':\w{2,4}:')
        self.assertFalse(a.match('%%%'))
        self.assertTrue(a.match(':aA:'))
        self.assertTrue(a.match(':zZxX:'))
        self.assertTrue(a.match(':_a0:'))

    def test_not_wordchar(self):
        a = pcre2nfa(':\W{2,4}:')
        self.assertTrue(a.match(':$#@:'))
        self.assertTrue(a.match(':$#@!:'))
        self.assertFalse(a.match(':xyz:'))
        self.assertFalse(a.match(':$%^&*:'))

    def test_char(self):
        a = pcre2nfa('ab{2,5}c')
        self.assertTrue(a.match('abbc'))
        self.assertTrue(a.match('abbbc'))
        self.assertTrue(a.match('abbbbc'))
        self.assertTrue(a.match('abbbbbc'))
        self.assertFalse(a.match('abc'))
        self.assertFalse(a.match('ac'))
        self.assertFalse(a.match('abbbbbbc'))

class TestOpUpTo(TestCase):
    def test_upto(self):
        a = pcre2nfa('/a{1,2}b/i')
        self.assertTrue(a.match('ab'))
        self.assertTrue(a.match('aab'))
        self.assertFalse(a.match('aaa'))
        a = pcre2nfa('/a{4,5}b/i')
        self.assertTrue(a.match('aaaab'))
        self.assertTrue(a.match('aaaaab'))
        self.assertFalse(a.match('aaaaaa'))

class TestOpWhitespace(TestCase):
    def test_whitespace(self):
        a = pcre2nfa('\s')
        self.assertTrue(a.match('\x0c'))
        self.assertTrue(a.match(' '))
        self.assertTrue(a.match('\n'))
        self.assertTrue(a.match('\t'))
        self.assertFalse(a.match('a'))

class TestOpWordchar(TestCase):
    def test_wordchar(self):
        a = pcre2nfa('\w')
        self.assertFalse(a.match('\x0c'))
        self.assertTrue(a.match('A'))
        self.assertTrue(a.match('Z'))
        self.assertTrue(a.match('_'))
        self.assertTrue(a.match('a'))
        self.assertTrue(a.match('z'))
        self.assertFalse(a.match('\n'))

class TestOpNotStarI(TestCase):
    def test_op_star_not_i(self):
        a = pcre2nfa('/ab[^c]*d/i')
        self.assertTrue(a.match('abd'))
        self.assertTrue(a.match('ABxxXXD'))
        self.assertTrue(a.match('AbXyZd'))
        self.assertFalse(a.match('abcD'))

class TestRegexOptions(TestCase):
    def test_case_insensitive(self):
        a = pcre2nfa('/abcde/i')
        self.assertTrue(a.match('ABCDEFGHI'))
        self.assertTrue(a.match('abcdefghi'))
        self.assertTrue(a.match('aBcDeFgHi'))
        self.assertFalse(a.match('afBgChDiE'))
        a = pcre2nfa('/abcde/')
        self.assertFalse(a.match('ABCDEFGHI'))
        self.assertTrue(a.match('abcdefghi'))
        self.assertFalse(a.match('aBcDeFgHi'))
        self.assertFalse(a.match('afBgChDiE'))

    def test_dotall(self):
        a = pcre2nfa('/abc.def/s')
        self.assertTrue(a.match('abcxdef'))
        self.assertTrue(a.match('abc\ndef'))
        self.assertFalse(a.match('abcdef'))
        a = pcre2nfa('/abc.def/')
        self.assertTrue(a.match('abcxdef'))
        self.assertFalse(a.match('abc\ndef'))

    def test_dotall_n_caseless(self):
        a = pcre2nfa('/abc.ef/is')
        self.assertTrue(a.match('abcdef'))
        self.assertTrue(a.match('ABCDEF'))
        self.assertTrue(a.match('aBcDeF'))
        self.assertTrue(a.match('abC%ef'))
        self.assertTrue(a.match('abc\nef'))

    def test_actual(self):
        a = pcre2nfa('/clsid\s*\x3a\s*\x7B?\s*EC5D5118-9FDE-4A3E-84F3-C2B711740E70(\x22)?.*DownloadCertificateExt\(/is')
        self.assertTrue(a.match('clsid:EC5D5118-9FDE-4A3E-84F3-C2B711740E70DownloadCertificateExt('))
        self.assertTrue(a.match('CLSID : { EC5D5118-9FDE-4A3E-84F3-C2B711740E70xxxxxxDownloadCertificateExt('))
