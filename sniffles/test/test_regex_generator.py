from unittest import *
from sniffles.regex_generator import *
import random


class TestRegexGenerator(TestCase):

    def test_get_index(self):
        test = get_index(1)
        self.assertEqual(test, 0)

        test = get_index(3)
        self.assertTrue(test >= 0)
        self.assertTrue(test <= 2)

        test = get_index(3, [0, 100, 0])
        self.assertEqual(test, 1)

        test = get_index(3, [0, 0, 100])
        self.assertEqual(test, 2)

        test = get_index(3, [100, 0, 0])
        self.assertEqual(test, 0)

    def test_get_char(self):
        pass

    def test_get_ascii_char(self):
        bad_chars = [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                     45, 46, 47, 58, 59, 60, 61, 62, 63, 64, 91, 92, 93,
                     94, 96, 123, 124, 125, 126, 127]
        for i in range(0, 100):
            test = get_ascii_char()
            if "x" in test:
                cVal = int("0x" + test[2:], 16)
                self.assertTrue(cVal >= 32)
                self.assertTrue(cVal <= 127)
                self.assertTrue(cVal in bad_chars)
            else:
                cVal = ord(test)
                self.assertTrue(cVal >= 32)
                self.assertTrue(cVal <= 127)
