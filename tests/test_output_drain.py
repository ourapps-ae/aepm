"""Output draining under slow private scans; real reader threads, fake process, no launches."""

from contextlib import ExitStack
import ctypes
import io
import os
import subprocess
import time
import unittest
from unittest.mock import Mock, patch

from aepm import process


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


class OutputDrainTests(unittest.TestCase):
    def setUp(self):
        guards = ExitStack()
        self.addCleanup(guards.close)
        guards.enter_context(patch.object(ctypes, "CDLL", side_effect=AssertionError("native library forbidden")))
        guards.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess forbidden")))
        guards.enter_context(patch.object(os, "kill", side_effect=AssertionError("signal forbidden")))
        guards.enter_context(patch.object(os, "killpg", side_effect=AssertionError("group signal forbidden")))

    def run_fake(self, stdout, stderr=b"", exits=False, limit=8 * 1024 * 1024, timeout=10, stdout_only=False):
        clock = FakeClock()
        instance = Mock(scope=None, stdout=io.BytesIO(stdout), stderr=io.BytesIO(stderr))

        def sample():
            clock.now += .19
            time.sleep(.005)

        instance.sample_private.side_effect = sample
        instance.observe_exit.side_effect = lambda: 0 if exits else None
        instance.terminate_tree.return_value = True
        instance.reap.return_value = 0
        with patch("aepm.posix_process.ContainedProcess", return_value=instance), \
                patch("aepm.process.time", clock):
            result = process.run(["fixture"], ".", {}, timeout, limit, stdout_only=stdout_only)
        return result, instance.sample_private.call_count

    def test_slow_scan_flood_reaches_output_limit_before_timeout(self):
        data = bytes(range(256)) * (8 * 1024 * 1024 // 256 + 1)
        (code, _, reason, output), samples = self.run_fake(data)
        self.assertEqual(reason, "output-limit")
        self.assertLessEqual(len(output), 8 * 1024 * 1024)
        self.assertEqual(output, data[:len(output)])
        self.assertLess(samples * .19, 10)

    def test_complete_in_order_delivery_after_exit(self):
        data = os.urandom(3 * 1024 * 1024 + 123)
        (code, _, reason, output), _ = self.run_fake(data, b"diagnostic text", exits=True, stdout_only=True)
        self.assertEqual((code, reason), (0, ""))
        self.assertEqual(output, data)

    def test_combined_streams_are_complete(self):
        data, errors = os.urandom(2 * 1024 * 1024), os.urandom(70000)
        (code, _, reason, output), _ = self.run_fake(data, errors, exits=True)
        self.assertEqual((code, reason), (0, ""))
        self.assertEqual(len(output), len(data) + len(errors))
        self.assertEqual(sorted(output), sorted(data + errors))


if __name__ == "__main__":
    unittest.main()
