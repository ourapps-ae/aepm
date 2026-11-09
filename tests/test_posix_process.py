"""Actual owned-group checks; deliberate session escape remains unsupported."""

from concurrent.futures import ThreadPoolExecutor
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from aepm.model import AepmError
from aepm.posix_process import ContainedProcess, ExitObserver
from aepm.process import run


@unittest.skipUnless(sys.platform == "darwin" or sys.platform.startswith("linux"), "Requires supported non-reaping Unix observation")
class OwnedGroupTests(unittest.TestCase):
    def test_immediate_exit_remains_waitable_until_final_reap(self):
        process = ContainedProcess([sys.executable, "-c", "raise SystemExit(7)"], tempfile.gettempdir(), {"PATH": os.defpath})
        try:
            with patch.object(process.popen, "poll", side_effect=AssertionError("premature poll")), patch.object(process.popen, "wait", side_effect=AssertionError("premature wait")):
                deadline = time.monotonic() + 3
                while process.observe_exit() is None and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertEqual(process.observe_exit(), 7)
                self.assertEqual(process.observe_exit(), 7)
                self.assertIsNone(process.popen.returncode)
                self.assertTrue(process.terminate_tree())
                self.assertEqual(process.reap(), 7)
                with patch("aepm.posix_process.os.killpg", side_effect=AssertionError("signal after reap")):
                    self.assertTrue(process.terminate_tree())
                    with self.assertRaises(AepmError):
                        process.signal_group()
        finally:
            if not process.signaling_finished:
                process.terminate_tree()
            if not process.reaped:
                process.reap()
            process.close()

    def test_lost_child_ownership_forbids_later_group_signal(self):
        process = ContainedProcess([sys.executable, "-c", "pass"], tempfile.gettempdir(), {"PATH": os.defpath})
        os.waitpid(process.pid, 0)
        try:
            with patch("aepm.posix_process.os.killpg", side_effect=AssertionError("signal after ownership loss")):
                self.assertFalse(process.terminate_tree())
                self.assertTrue(process.ownership_lost)
                with self.assertRaises(AepmError):
                    process.signal_group()
                with self.assertRaises(AepmError):
                    process.reap()
        finally:
            process.close()

    def test_automatic_reaping_rejected_before_launch(self):
        original = signal.getsignal(signal.SIGCHLD)
        try:
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            with patch("aepm.posix_process.subprocess.Popen", side_effect=AssertionError("command launched")), self.assertRaises(AepmError):
                ContainedProcess([sys.executable, "-c", "pass"], tempfile.gettempdir(), {})
        finally:
            signal.signal(signal.SIGCHLD, original)

    def test_kernel_auto_reap_flag_rejected_even_with_python_default_handler(self):
        observer = ExitObserver()
        original = observer.action_type()
        self.assertEqual(observer.sigaction(signal.SIGCHLD, None, ctypes.byref(original)), 0)
        altered = observer.action_type.from_buffer_copy(original)
        altered.flags |= observer.no_wait_flag
        try:
            self.assertEqual(observer.sigaction(signal.SIGCHLD, ctypes.byref(altered), None), 0)
            self.assertEqual(signal.getsignal(signal.SIGCHLD), signal.SIG_DFL)
            with patch("aepm.posix_process.subprocess.Popen", side_effect=AssertionError("command launched")), self.assertRaises(AepmError):
                ContainedProcess([sys.executable, "-c", "pass"], tempfile.gettempdir(), {})
        finally:
            self.assertEqual(observer.sigaction(signal.SIGCHLD, ctypes.byref(original), None), 0)

    def test_concurrent_commands_leave_unrelated_sentinel_alive(self):
        sentinel = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                outcomes = list(pool.map(lambda value: run([sys.executable, "-c", f"print({value})"], tempfile.gettempdir(), {"PATH": os.defpath}, 5), range(8)))
            self.assertTrue(all(code == 0 and reason == "" for code, _, reason, _ in outcomes), outcomes)
            self.assertIsNone(sentinel.poll())
        finally:
            if sentinel.poll() is None:
                sentinel.terminate()
            sentinel.wait(timeout=5)

    def test_cancellation_cleans_group_before_propagating(self):
        from aepm import process as module
        created = []
        original = ContainedProcess.__init__

        def remember(instance, *args):
            original(instance, *args)
            created.append(instance)

        with patch.object(ContainedProcess, "__init__", remember), patch.object(module.queue.Queue, "get", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
            run([sys.executable, "-c", "import time; time.sleep(30)"], tempfile.gettempdir(), {"PATH": os.defpath}, 5)
        self.assertEqual(len(created), 1)
        self.assertTrue(created[0].cleaned)
        self.assertTrue(created[0].reaped)
