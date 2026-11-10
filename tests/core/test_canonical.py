import json
import struct
import unittest

from aepm.model import AepmError, canonical, loads

# RFC 8785 Appendix B: IEEE 754 binary64 bit patterns and their canonical text.
APPENDIX_B = [
    ("0000000000000000", "0"), ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"), ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"), ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"), ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"), ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"), ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"), ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"), ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"), ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"), ("43143ff3c1cb0959", "1424953923781206.2"),
]
APPENDIX_B_INVALID = ["7fffffffffffffff", "7ff0000000000000"]


def double(bits):
    return struct.unpack(">d", bytes.fromhex(bits))[0]


class CanonicalTests(unittest.TestCase):
    def test_appendix_b_numbers(self):
        for bits, expected in APPENDIX_B:
            with self.subTest(bits=bits):
                self.assertEqual(canonical(double(bits)), expected.encode())

    def test_appendix_b_nan_and_infinity_refused(self):
        for bits in APPENDIX_B_INVALID:
            with self.subTest(bits=bits), self.assertRaises(AepmError):
                canonical(double(bits))

    def test_section_3_2_2_example(self):
        source = ('{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
                  ' "string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
                  ' "literals": [null, true, false]}')
        expected = ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
                    '"string":"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
        self.assertEqual(canonical(json.loads(source)), expected.encode())

    def test_section_3_2_3_sorting_by_utf16_code_units(self):
        value = {"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh",
                 "1": "One", "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control",
                 "\u00f6": "Latin Small Letter O With Diaeresis"}
        order = [key for key in json.loads(canonical(value))]
        self.assertEqual(order, ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001f600", "\ufb33"])
        self.assertEqual(canonical({"\ue000": 1, "\U0001f600": 2}), '{"\U0001f600":2,"\ue000":1}'.encode())

    def test_ecmascript_number_forms(self):
        for value, expected in ((1.0, "1"), (1e-7, "1e-7"), (1e16, "10000000000000000"), (-0.0, "0"),
                                (0.1 + 0.2, "0.30000000000000004"), (1e21, "1e+21"), (1e20, "100000000000000000000")):
            with self.subTest(value=value):
                self.assertEqual(canonical(value), expected.encode())

    def test_safe_integer_range(self):
        self.assertEqual(canonical([2 ** 53 - 1, -(2 ** 53 - 1)]), b"[9007199254740991,-9007199254740991]")
        for value in (2 ** 53, -(2 ** 53), 10 ** 20):
            with self.subTest(value=value), self.assertRaises(AepmError) as caught:
                canonical({"n": value})
            self.assertEqual(caught.exception.code, "invalid-number")
        with self.assertRaises(AepmError):
            loads(b'{"n":9007199254740992}')

    def test_strings_and_refusals(self):
        self.assertEqual(canonical("\u2028\x7f\x1f"), '"\u2028\x7f\\u001f"'.encode())
        for value in ("\ud800", {1: "key"}, (1, 2), b"bytes"):
            with self.subTest(value=value), self.assertRaises(AepmError):
                canonical(value)


if __name__ == "__main__":
    unittest.main()
