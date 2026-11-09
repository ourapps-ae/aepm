"""Confirmed exit must not relax incomplete live-process discovery."""

import ctypes as c
import errno
import os
import time
import unittest
from unittest.mock import Mock

from aepm.model import AepmError
from aepm.private_process import CaptureRace, CombinedInfo, DarwinBackend, Identity
from tests import test_private_process as fixtures


class DarwinExitQueryTests(unittest.TestCase):
    def backend(self, status=5, failure=None):
        backend = DarwinBackend.__new__(DarwinBackend)

        def info(pid, flavor, argument, pointer, size):
            self.assertEqual((flavor, argument, size), (18, 1, 192))
            if failure:
                length, error = failure
                c.set_errno(error)
                return length
            data = c.cast(pointer, c.POINTER(CombinedInfo)).contents
            data.basic.pid, data.basic.uid = pid, os.geteuid()
            data.basic.status, data.basic.parent, data.basic.group = status, 1, pid
            data.unique.unique, data.unique.generation = 701, 9
            return size

        backend.info = Mock(side_effect=info)
        backend.path = Mock(side_effect=AssertionError("exited process path queried"))
        backend.extended = Mock(side_effect=AssertionError("exited process directory queried"))
        backend.send = Mock(side_effect=AssertionError("unexpected signal"))
        return backend

    def test_complete_exited_identity_needs_no_paths_or_signal(self):
        backend = self.backend()
        record = backend.capture(100)
        self.assertEqual((record.key, record.generation, record.status), (701, 9, 5))
        self.assertIsNone(backend.refresh(record))
        backend.terminate(record, 15)
        backend.path.assert_not_called()
        backend.extended.assert_not_called()
        backend.send.assert_not_called()

    def test_missing_identity_remains_missing(self):
        self.assertIsNone(self.backend(failure=(0, errno.ESRCH)).capture(100))

    def test_partial_and_denied_records_fail(self):
        for failure in ((191, 0), (0, errno.EPERM), (0, errno.EACCES), (0, errno.EINVAL)):
            with self.subTest(failure=failure), self.assertRaises(AepmError):
                self.backend(failure=failure).capture(100)

    def test_live_unreadable_path_fails(self):
        backend = self.backend(status=2)

        def denied(*_args):
            c.set_errno(errno.EACCES)
            return 0

        backend.path.side_effect = denied
        with self.assertRaisesRegex(AepmError, "private-process-path"):
            backend.capture(100)
        backend.send.assert_not_called()

    def test_live_to_exited_during_path_retry(self):
        backend = self.backend(status=2)
        first = backend.info.side_effect
        count = 0

        def info(*args):
            nonlocal count
            result = first(*args)
            count += 1
            if count > 1:
                c.cast(args[3], c.POINTER(CombinedInfo)).contents.basic.status = 5
            return result

        def vanished(*_args):
            c.set_errno(errno.ESRCH)
            return 0

        backend.info.side_effect = info
        backend.path.side_effect = vanished
        self.assertEqual(backend.capture(100).status, 5)
        backend.extended.assert_not_called()

    def test_unresolved_live_path_retries_fail(self):
        backend = self.backend(status=2)

        def vanished(*_args):
            c.set_errno(errno.ESRCH)
            return 0

        backend.path.side_effect = vanished
        with self.assertRaisesRegex(AepmError, "private-process-discovery") as caught:
            backend.capture(100)
        self.assertIsInstance(caught.exception, CaptureRace)
        self.assertEqual(backend.info.call_count, 4)

    def test_generation_change_during_path_capture_is_not_accepted(self):
        backend = self.backend(status=2)
        original = backend.info.side_effect
        count = 0

        def info(*args):
            nonlocal count
            size = original(*args)
            count += 1
            c.cast(args[3], c.POINTER(CombinedInfo)).contents.unique.generation = count
            return size

        def path(_token, buffer, _size):
            buffer.value = b"/outside/program"
            return len(buffer.value)

        def directory(_call, _pid, _flavor, _flags, _identity, _argument, buffer, size):
            c.memmove(c.addressof(buffer) + 152, b"/outside\0", 9)
            return size

        backend.info.side_effect = info
        backend.path.side_effect = path
        backend.extended.side_effect = directory
        with self.assertRaisesRegex(AepmError, "private-process-discovery"):
            backend.capture(100)
        backend.send.assert_not_called()


class ConfirmedExitScopeTests(fixtures.SimulatedPrivateScopeTests):
    def test_foreign_exited_identity_does_not_block_cleanup(self):
        backend = fixtures.FakeBackend({})
        scope = self.scope(backend)
        scope.bind(300)
        backend.records[200] = Identity(200, 701, os.geteuid(), 1, 999, 5, generation=9)
        self.assertTrue(scope.finish(time.monotonic() + .2))
        self.assertFalse(scope.unresolved)
        self.assertFalse(backend.signals)

    def test_new_unknown_missing_candidate_blocks_cleanup(self):
        backend = fixtures.FakeBackend({})
        scope = self.scope(backend)
        scope.bind(300)
        backend.records[200] = None
        self.assertFalse(scope.finish(time.monotonic() + .15))
        self.assertTrue(scope.unresolved)
        self.assertTrue(self.root.exists())
        self.assertFalse(backend.signals)

    def test_exited_number_reused_by_live_private_identity_is_discovered(self):
        backend = fixtures.FakeBackend({})
        scope = self.scope(backend)
        scope.bind(300)
        backend.records[200] = Identity(200, 701, os.geteuid(), 1, 999, 5, generation=9)
        scope.scan(force=True)
        backend.records[200] = Identity(200, 702, os.geteuid(), 1, 999, 2,
                                        "/outside/program", str(self.root), generation=10)
        scope.scan(force=True)
        self.assertIn(702, scope.owned)
        self.assertNotIn(701, scope.owned)
        self.assertFalse(backend.signals)


if __name__ == "__main__":
    unittest.main()
