"""Private-namespace ownership tests, separate from arbitrary session escape."""

from copy import deepcopy
import ctypes
import errno
import os
from pathlib import Path
import shutil
import signal
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from aepm.model import AepmError
from aepm.private_process import AuditToken, DarwinBackend, LinuxBackend, Identity, PrivateScope, enroll_root
from aepm.process import run


class FakeBackend:
    def __init__(self, records):
        self.records = records
        self.signals = []
        self.denied = False

    def pids(self):
        return list(self.records)

    def capture(self, pid, *, paths=True, allow_missing_executable=False):
        record = deepcopy(self.records.get(pid))
        if record and paths and record.executable_missing and not allow_missing_executable:
            raise AepmError("cleanup-failed", "private-process-path")
        return record

    def refresh(self, record):
        current = self.records.get(record.pid)
        return record if current and current.key == record.key and current.status != 5 else None

    def terminate(self, record, number):
        if self.denied:
            raise AepmError("cleanup-failed", "simulated-signal-denial")
        self.signals.append((record.key, number))
        self.records[record.pid].status = 5

    def close(self, record):
        pass


class SimulatedPrivateScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def scope(self, backend, root=None):
        with patch("aepm.private_process.DarwinBackend", return_value=backend), patch("aepm.private_process.LinuxBackend", return_value=backend):
            scope = PrivateScope(root or self.root)
        self.addCleanup(scope.close)
        return scope

    def test_baseline_and_later_baseline_entry_are_conflicts(self):
        record = Identity(100, 100, os.geteuid(), 1, 100, 2, "/outside/program", str(self.root))
        with self.assertRaises(AepmError):
            self.scope(FakeBackend({100: record}))
        record.cwd = "/outside"
        backend = FakeBackend({100: record})
        scope = self.scope(backend)
        backend.records[100].cwd = str(self.root)
        with self.assertRaises(AepmError):
            scope.bind(200)
        self.assertFalse(backend.signals)

    def test_replaced_identity_is_never_signaled(self):
        backend = DarwinBackend.__new__(DarwinBackend)
        old = Identity(123, 1, os.geteuid(), 1, 123, 2, token=AuditToken())
        backend.capture = Mock(return_value=Identity(123, 2, os.geteuid(), 1, 123, 2, token=AuditToken()))
        backend.send = Mock(side_effect=AssertionError("Replacement must not be signaled"))
        backend.terminate(old, signal.SIGKILL)
        backend.send.assert_not_called()

    def test_discovery_and_signal_failures_prevent_success(self):
        for fault in ("truncated", "unreadable", "denied"):
            with self.subTest(fault=fault):
                root = self.root / fault
                root.mkdir(mode=0o700)
                backend = FakeBackend({})
                scope = self.scope(backend, root)
                backend.records[200] = Identity(200, 200, os.geteuid(), 1, 999, 2, str(root / "private-executable"), "/outside")
                scope.bind(300)
                if fault == "truncated":
                    backend.pids = Mock(side_effect=AepmError("cleanup-failed", "truncated"))
                elif fault == "unreadable":
                    backend.capture = Mock(side_effect=AepmError("cleanup-failed", "unreadable"))
                else:
                    backend.denied = True
                self.assertFalse(scope.finish(time.monotonic() + .15))
                self.assertTrue(scope.failed)

    def test_fixed_initial_missing_path_exclusion_is_not_renewed(self):
        record = Identity(100, 100, os.geteuid(), 1, 100, 2, None, "/outside", generation=7, executable_missing=True)
        backend = FakeBackend({100: record})
        enroll_root(self.root, before_work=True, backend=backend)
        first = self.scope(backend)
        first.bind(300)
        self.assertTrue(first.finish(time.monotonic() + .2))
        first.close()
        backend.records[100].generation = 8
        with self.assertRaises(AepmError):
            self.scope(backend)
        self.assertFalse(backend.signals)

    def test_prior_step_unnameable_survivor_is_not_a_new_exemption(self):
        backend = FakeBackend({})
        enroll_root(self.root, before_work=True, backend=backend)
        first = self.scope(backend)
        first.bind(300)
        self.assertTrue(first.finish(time.monotonic() + .2))
        first.close()
        backend.records[200] = Identity(200, 200, os.geteuid(), 1, 999, 2, None, "/outside", generation=1, executable_missing=True)
        with self.assertRaises(AepmError):
            self.scope(backend)
        self.assertFalse(backend.signals)

    def test_external_unknown_birth_and_root_replacement_fail(self):
        backend = FakeBackend({100: Identity(100, 100, os.geteuid(), 1, 100, 2, None, "/outside", executable_missing=True)})
        with self.assertRaisesRegex(AepmError, "baseline-age"):
            self.scope(backend)
        backend.records.clear()
        scope = self.scope(backend)
        scope.bind(300)
        self.root.rmdir()
        self.root.mkdir(mode=0o700)
        with self.assertRaisesRegex(AepmError, "private-process-root"):
            scope.scan(force=True)
        self.assertFalse(backend.signals)

    def test_baseline_cap_does_not_discard_live_entries(self):
        entries = {(index, index): SimpleNamespace(active=1) for index in range(512)}
        with patch("aepm.private_process._BASELINES", entries), self.assertRaisesRegex(AepmError, "baseline-limit"):
            enroll_root(self.root, before_work=True, backend=FakeBackend({}))

    def test_simulated_linux_missing_path_requires_descriptor_exit(self):
        for exited in (False, True):
            with self.subTest(exited=exited):
                backend = LinuxBackend.__new__(LinuxBackend)
                backend.exited = Mock(return_value=exited)
                backend.open_descriptor = Mock(return_value=123)
                with patch.object(Path, "read_text", side_effect=FileNotFoundError), patch("aepm.private_process.os.close") as close:
                    if exited:
                        self.assertIsNone(backend.capture(456))
                    else:
                        with self.assertRaisesRegex(AepmError, "private-process-discovery"):
                            backend.capture(456)
                    backend.exited.assert_called_once_with(123)
                    close.assert_called_once_with(123)


@unittest.skipUnless(sys.platform == "darwin", "Actual macOS identity tests; Linux acceptance is separate")
class ActualPrivateScopeTests(unittest.TestCase):
    def environment(self, root):
        return {"PATH": os.defpath, "AEPM_PRIVATE_ROOT": str(root), "HOME": str(root), "TMPDIR": str(root)}

    def test_detached_private_directory_child_stops_on_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            marker = root / "marker"
            child = f"import time; from pathlib import Path; p=Path({str(marker)!r}); end=time.monotonic()+8;\nwhile time.monotonic()<end: p.write_text(str(time.monotonic())); time.sleep(.02)"
            parent = f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child!r}],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(10)"
            try:
                result = run([sys.executable, "-c", parent], root, self.environment(root), .7)
                self.assertEqual(result[2], "timeout", result)
                self.assertTrue(marker.exists())
                previous = marker.read_bytes()
                time.sleep(.15)
                self.assertEqual(marker.read_bytes(), previous)
            finally:
                # If supervision fails, this fixture still has a bounded lifetime.
                if not marker.exists():
                    time.sleep(.1)

    def test_private_executable_survives_reparenting_then_is_stopped(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as other:
            root, unrelated = Path(directory).resolve(), Path(other).resolve()
            binary, sentinel_binary = root / "same-name", unrelated / "same-name"
            compiler = shutil.which("cc")
            if compiler is None:
                self.skipTest("A compiler is required for the owned native fixture")
            build_environment = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(root), "TMPDIR": str(root)}
            subprocess.run([compiler, str(Path(__file__).with_name("fixtures") / "private_hold.c"), "-o", str(binary)],
                           cwd=root, env=build_environment, capture_output=True, check=True, timeout=30)
            shutil.copyfile(binary, sentinel_binary)
            sentinel_binary.chmod(0o755)
            sentinel = subprocess.Popen([str(sentinel_binary), "8"], cwd="/", start_new_session=True, stdout=subprocess.PIPE)
            backend = DarwinBackend()
            self.assertTrue(select.select([sentinel.stdout], [], [], 3)[0])
            self.assertEqual(sentinel.stdout.readline(64), b"ready\n")
            sentinel_identity = backend.capture(sentinel.pid, paths=False)
            script = f"import subprocess; subprocess.Popen([{str(binary)!r},'8'],cwd='/',start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
            try:
                time.sleep(.05)
                self.assertIsNone(sentinel.poll(), "Sentinel exited before supervision began")
                result = run([sys.executable, "-c", script], root, self.environment(root), 5)
                self.assertEqual((result[0], result[2]), (0, ""), result)
                scope = PrivateScope(root)
                scope.close()
                self.assertIsNotNone(backend.refresh(sentinel_identity))
            finally:
                backend.terminate(sentinel_identity, signal.SIGTERM)
                sentinel.wait(timeout=5)
                sentinel.stdout.close()

    def test_wrong_generation_token_cannot_signal_controlled_child(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"], start_new_session=True)
        backend = DarwinBackend()
        identity = backend.capture(child.pid, paths=False)
        try:
            token = AuditToken(*identity.token)
            token[7] = (token[7] + 1) & 0xffffffff
            self.assertEqual(backend.send(ctypes.byref(token), signal.SIGCONT), errno.ESRCH)
            self.assertIsNotNone(backend.refresh(identity))
        finally:
            backend.terminate(identity, signal.SIGTERM)
            child.wait(timeout=5)

    def test_same_root_sequential_steps_do_not_adopt_prior_survivors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for step in ("tool", "prepare", "check"):
                result = run([sys.executable, "-c", f"print({step!r})"], root, self.environment(root), 5)
                self.assertEqual((result[0], result[2]), (0, ""), result)
            prior = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(8)"], cwd=root, start_new_session=True)
            backend = DarwinBackend()
            identity = backend.capture(prior.pid, paths=False)
            try:
                result = run([sys.executable, "-c", "raise AssertionError('must not run')"], root, self.environment(root), 5)
                self.assertEqual(result[2], "cleanup-failed")
                self.assertIsNotNone(backend.refresh(identity))
            finally:
                backend.terminate(identity, signal.SIGTERM)
                prior.wait(timeout=5)

    def test_actual_older_deleted_executable_stays_unowned(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            compiler = shutil.which("cc")
            if compiler is None:
                self.skipTest("A compiler is required for the owned native fixture")
            binary = parent / "older-fixture"
            subprocess.run([compiler, str(Path(__file__).with_name("fixtures") / "private_hold.c"), "-o", str(binary)],
                           cwd=parent, env={"PATH": os.environ.get("PATH", os.defpath), "HOME": str(parent), "TMPDIR": str(parent)},
                           capture_output=True, check=True, timeout=30)
            child = subprocess.Popen([str(binary)], cwd="/", start_new_session=True, stdout=subprocess.PIPE)
            backend = DarwinBackend()
            self.assertTrue(select.select([child.stdout], [], [], 3)[0])
            self.assertEqual(child.stdout.readline(64), b"ready\n")
            identity = backend.capture(child.pid, paths=False)
            try:
                time.sleep(.05)
                self.assertIsNone(child.poll())
                binary.unlink()
                observed = backend.capture(child.pid, paths=True, allow_missing_executable=True)
                self.assertTrue(observed.executable_missing)
                root = parent / "suite"
                root.mkdir(mode=0o700)
                for step in ("first", "second"):
                    result = run([sys.executable, "-c", f"print({step!r})"], root, self.environment(root), 5)
                    self.assertEqual((result[0], result[2]), (0, ""), result)
                    self.assertIsNotNone(backend.refresh(identity))
            finally:
                backend.terminate(identity, signal.SIGTERM)
                child.wait(timeout=5)
                child.stdout.close()


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                     "Actual Linux process-descriptor host unavailable")
class ActualLinuxDescriptorTests(unittest.TestCase):
    def test_stale_descriptor_never_targets_another_process(self):
        from aepm.private_process import LinuxBackend
        backend = LinuxBackend()
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"], start_new_session=True)
        identity = backend.capture(child.pid, paths=False)
        sentinel = None
        try:
            backend.terminate(identity, signal.SIGTERM)
            child.wait(timeout=5)
            sentinel = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"], start_new_session=True)
            with self.assertRaises(ProcessLookupError):
                signal.pidfd_send_signal(identity.handle, 0, None, 0)
            backend.terminate(identity, signal.SIGKILL)
            self.assertIsNone(sentinel.poll())
        finally:
            backend.terminate(identity, signal.SIGKILL)
            child.wait(timeout=5)
            backend.close(identity)
            if sentinel is not None:
                sentinel_identity = backend.capture(sentinel.pid, paths=False)
                backend.terminate(sentinel_identity, signal.SIGTERM)
                sentinel.wait(timeout=5)
                backend.close(sentinel_identity)
