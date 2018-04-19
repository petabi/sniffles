import unittest

import sniffles.nfa
import sniffles.pcrecomp


class TestPcreComp(unittest.TestCase):
    def test_args(self):
        try:
            sniffles.pcrecomp.compile()
        except TypeError:
            pass
        sniffles.pcrecomp.compile('pattern')

    def test_empty(self):
        sniffles.pcrecomp.compile('')

    def test_delimiter(self):
        a = sniffles.nfa.pcre2nfa('/hello/')
        self.assertTrue(a.match('zzhellozz'))

    def test_option(self):
        sniffles.nfa.pcre2nfa('/hello/i')
