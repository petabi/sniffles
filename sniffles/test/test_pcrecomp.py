import unittest


class TestPcreComp(unittest.TestCase):
    def test_args(self):
        import sniffles.pcrecomp
        try:
            sniffles.pcrecomp.compile()
        except TypeError:
            pass
        sniffles.pcrecomp.compile('pattern')

    def test_empty(self):
        import sniffles.pcrecomp
        a = sniffles.pcrecomp.compile('')

    def test_delimiter(self):
        import sniffles.nfa
        a = sniffles.nfa.pcre2nfa('/hello/')
        self.assertTrue(a.match('zzhellozz'))

    def test_option(self):
        import sniffles.nfa
        a = sniffles.nfa.pcre2nfa('/hello/i')
