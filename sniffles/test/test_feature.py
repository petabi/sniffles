from unittest import *
from sniffles.feature import *


class TestFeature(TestCase):

    def test_ipv6(self):
        ip = IPFeature("i1", 6, 100)
        self.assertEqual(7, str(ip).count(':'))
