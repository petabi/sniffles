import random
import unittest

import sniffles.regex_generator as regen


class TestRegexGenerator(unittest.TestCase):

    def test_get_index(self):
        test = regen.get_index(1, None)
        self.assertEqual(test, 0)

        test = regen.get_index(3, None)
        self.assertTrue(test >= 0)
        self.assertTrue(test <= 2)

        test = regen.get_index(3, [0, 100, 0])
        self.assertEqual(test, 1)

        test = regen.get_index(3, [0, 0, 100])
        self.assertEqual(test, 2)

        test = regen.get_index(3, [100, 0, 0])
        self.assertEqual(test, 0)

    def test_get_ascii_char(self):
        bad_chars = [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                     45, 46, 47, 58, 59, 60, 61, 62, 63, 64, 91, 92, 93,
                     94, 96, 123, 124, 125, 126, 127]
        for i in range(0, 100):
            test = regen.get_ascii_char()
            if "\\" in test:
                cVal = int(test[2:], 16)
                self.assertTrue(cVal >= 32)
                self.assertTrue(cVal <= 127)
                self.assertTrue(cVal in bad_chars)
            else:
                cVal = ord(test)
                self.assertTrue(cVal >= 32)
                self.assertTrue(cVal <= 127)

    def test_get_bin_char(self):
        for i in range(0, 255):
            test = regen.get_bin_char()
            cVal = int(test[2:], 16)
            self.assertTrue(cVal >= 0)
            self.assertTrue(cVal <= 255)

    def test_get_letter(self):
        testStr = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
        for i in range(0, 100):
            self.assertTrue(regen.get_letter() in testStr)

    def test_get_digit(self):
        testStr = "0123456789"
        for i in range(0, 100):
            self.assertTrue(regen.get_digit() in testStr)

    def test_get_substitution_class(self):
        testStr = "\d\s\w\D\S\W."
        for i in range(0, 100):
            self.assertTrue(regen.get_substitution_class() in testStr)

    def test_get_class(self):
        for i in range(0, 100):
            test = regen.get_class([0, 100], 0, None)
            test = test[1:-1]
            values = test.split("-")
            if values[0].islower():
                self.assertTrue(values[1].islower())
            else:
                self.assertTrue(not values[1].islower())
            self.assertTrue(ord(values[0]) < ord(values[1]))

        for i in range(0, 100):
            test = regen.get_class([0, 100], 100, None)
            self.assertEqual(test[1], "^")

    def test_get_repetition(self):
        for i in range(0, 100):
            test = regen.get_repetition([100, 0, 0, 0], 0)
            self.assertEqual(test, "?")

        for i in range(0, 100):
            test = regen.get_repetition([0, 100, 0, 0], 0)
            self.assertEqual(test, "*")

        for i in range(0, 100):
            test = regen.get_repetition([0, 0, 100, 0], 0)
            self.assertEqual(test, "+")

        for i in range(0, 100):
            test = regen.get_repetition([0, 0, 0, 100], 0)
            self.assertEqual(test[0], "{")
            self.assertEqual(test[-1], "}")
            values = test[1:-1].split(",")
            lower = int(values[0])
            upper = int(values[1])
            self.assertTrue(lower <= upper)

    def test_min_regex(self):
        for i in range(0, 100):
            myre = regen.generate_regex(1, 1, [100, 0, 0], [
                0, 0, 100, 0, 0], None, None, 0, 0, 1)
            self.assertTrue(len(myre) == 1)
            myre = regen.generate_regex(1, 10, [100, 0, 0], [
                0, 0, 100, 0, 0], None, None, 0, 0, 2)
            self.assertTrue(len(myre) >= 2)
            self.assertTrue(len(myre) <= 10)
