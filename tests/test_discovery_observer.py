"""Fake-binding equivalence checks; native backend construction is forbidden."""

from contextlib import ExitStack
import ctypes as c
import errno
import unittest
from unittest.mock import Mock, patch

from aepm.model import canonical
from aepm.private_process import AuditToken, CombinedInfo, DarwinBackend
from tests.discovery_observer import DiscoveryObserver


class FakeBindings:
    def __init__(self, modes=("success",), listing=None):
        self.modes = modes
        self.list_result = listing
        self.calls = []
        self.attempt = 0
        self.confirmation = False
        self.backend = DarwinBackend.__new__(DarwinBackend)
        self.backend.info = self.info
        self.backend.path = self.path
        self.backend.extended = self.extended
        self.backend.listing = self.listing
        self.backend.send = Mock(side_effect=AssertionError("signal forbidden"))

    @property
    def mode(self):
        return self.modes[min(self.attempt - 1, len(self.modes) - 1)]

    def info(self, pid, flavor, argument, buffer, size):
        confirming, self.confirmation = self.confirmation, False
        self.calls.append(("confirmation" if confirming else "identity", pid, flavor, argument, size, c.get_errno()))
        if not confirming:
            self.attempt += 1
        mode = self.mode
        if mode == "gone" or confirming and mode == "confirmation-gone":
            c.set_errno(errno.ESRCH)
            return 0
        if mode == "info-denied" or confirming and mode == "confirmation-denied":
            c.set_errno(errno.EACCES)
            return 0
        if mode == "partial":
            c.set_errno(errno.EIO)
            return size - 1
        if mode == "binding-exception":
            c.set_errno(errno.EINTR)
            raise OSError(errno.EPERM, "SYNTHETIC_SECRET_EXCEPTION")
        data = c.cast(buffer, c.POINTER(CombinedInfo)).contents
        data.basic.pid, data.basic.uid, data.basic.ruid = pid, 501, 501
        data.basic.parent, data.basic.group = 1, pid
        data.basic.status = 5 if mode == "exited" else 2
        data.unique.unique = 900000000 + (1 if confirming and mode == "identity-change" else 0)
        data.unique.generation = 123456789 + (1 if confirming and mode == "generation-change" else 0)
        c.set_errno(errno.EBUSY)
        return size

    def path(self, token, buffer, size):
        actual = tuple(c.cast(token, c.POINTER(AuditToken)).contents)
        self.calls.append(("executable-path", actual, size, c.get_errno()))
        if self.mode in ("path-race", "path-denied"):
            c.set_errno(errno.ESRCH if self.mode == "path-race" else errno.EACCES)
            return 0
        buffer.value = b"/SYNTHETIC_SECRET_PATH/executable"
        c.set_errno(errno.EBUSY)
        return len(buffer.value)

    def extended(self, call, pid, flavor, flags, identity, argument, buffer, size):
        self.calls.append(("working-directory", call, pid, flavor, flags, identity, argument, size, c.get_errno()))
        if self.mode in ("directory-race", "directory-denied"):
            c.set_errno(errno.ESRCH if self.mode == "directory-race" else errno.EACCES)
            return -1
        c.memmove(c.addressof(buffer) + 152, b"/SYNTHETIC_SECRET_PATH/cwd\0", 27)
        self.confirmation = True
        c.set_errno(errno.EBUSY)
        return size

    def listing(self, kind, uid, buffer, size):
        self.calls.append(("list", kind, uid, size, c.get_errno()))
        buffer[0] = 424242
        c.set_errno(errno.EAGAIN)
        return c.sizeof(c.c_int) if self.list_result is None else self.list_result


class DiscoveryObserverTests(unittest.TestCase):
    def setUp(self):
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        self.guards.enter_context(patch("ctypes.CDLL", side_effect=AssertionError("native library forbidden")))
        self.guards.enter_context(patch.object(DarwinBackend, "__init__", side_effect=AssertionError("backend construction forbidden")))

    def exercise(self, modes=("success",), listing=None, operation="capture", observed=True, observer_fault=False):
        fake = FakeBindings(modes, listing)
        observer = DiscoveryObserver(fake.backend)
        with ExitStack() as stack:
            if observed:
                stack.enter_context(observer)
            if observer_fault:
                def broken(*_args):
                    c.set_errno(errno.EFAULT)
                    raise RuntimeError("SYNTHETIC_SECRET_OBSERVER")
                stack.enter_context(patch.object(observer, "record", side_effect=broken))
            c.set_errno(errno.ENOENT)
            try:
                value = fake.backend.pids() if operation == "list" else fake.backend.capture(424242)
                immediate = c.get_errno()
                if value is not None and operation == "capture":
                    value = (value.pid, value.key, value.uid, value.parent, value.group, value.status,
                             value.executable, value.cwd, value.generation, tuple(value.token))
                outcome = ("returned", value)
            except Exception as error:
                immediate = c.get_errno()
                outcome = ("raised", type(error).__name__, error.args,
                           getattr(error, "code", None), getattr(error, "path", None))
        fake.backend.send.assert_not_called()
        return outcome, immediate, fake.calls, observer.document()

    def equivalent(self, **kwargs):
        plain = self.exercise(observed=False, **kwargs)
        recorded = self.exercise(observed=True, **kwargs)
        self.assertEqual(recorded[:3], plain[:3])
        self.assertLessEqual(len(canonical(recorded[3])), 8192)
        return recorded

    def test_list_rejection_categories_and_success(self):
        capacity = 65536 * c.sizeof(c.c_int)
        for count, category in ((0, "nonpositive"), (-1, "nonpositive"), (capacity, "capacity"),
                                (capacity + 4, "capacity"), (3, "misaligned")):
            with self.subTest(count=count):
                result = self.equivalent(operation="list", listing=count)
                failure = result[3]["firstFailure"]
                self.assertEqual(failure["location"], "private-process-discovery")
                self.assertEqual(failure["stages"][0]["category"], category)
                self.assertEqual(failure["stages"][0]["error"], errno.EAGAIN)
                self.assertEqual(failure["attempts"], 0)
        self.assertIsNone(self.equivalent(operation="list")[3]["firstFailure"])

    def test_homogeneous_retry_exhaustion(self):
        # Exhaustion ends with one nested identity-only query; the observer labels every nested query "confirmation".
        for mode, stages, nested, truncated in (("path-race", 7, 1, False), ("directory-race", 10, 1, False),
                                                ("identity-change", 12, 4, True), ("generation-change", 12, 4, True)):
            with self.subTest(mode=mode):
                outcome, _, _, document = self.equivalent(modes=(mode,))
                self.assertEqual(outcome[3:], ("cleanup-failed", "private-process-discovery"))
                failure = document["firstFailure"]
                self.assertEqual(failure["attempts"], 3)
                self.assertEqual(len(failure["stages"]), stages)
                self.assertEqual(document["counts"]["nestedCaptures"], nested)
                self.assertEqual(failure["truncated"], truncated)
                self.assertFalse(failure["unavailable"])
                last = failure["stages"][-1]
                self.assertEqual((last["stage"], last["attempt"]), ("confirmation", 3))
                if truncated:
                    self.assertTrue(last["identityChanged" if mode == "identity-change" else "generationChanged"])
                else:
                    self.assertEqual((last["identityChanged"], last["generationChanged"], last["status"]), (False, False, 2))

    def test_mixed_retries_keep_outer_attempt_and_confirmation_separate(self):
        result = self.equivalent(modes=("path-race", "directory-race", "generation-change"))
        stages = result[3]["firstFailure"]["stages"]
        self.assertEqual([(s["attempt"], s["stage"]) for s in stages],
                         [(1, "identity"), (1, "executable-path"),
                          (2, "identity"), (2, "executable-path"), (2, "working-directory"),
                          (3, "identity"), (3, "executable-path"), (3, "working-directory"), (3, "confirmation"),
                          (3, "confirmation")])
        self.assertEqual([s["confirmation"] for s in stages], [False] * 8 + [True, True])
        self.assertTrue(stages[-2]["generationChanged"])
        self.assertFalse(stages[-1]["generationChanged"])

    def test_normal_missing_partial_permission_and_exception_outcomes(self):
        for mode in ("success", "exited", "gone", "confirmation-gone", "partial", "info-denied",
                     "path-denied", "directory-denied", "confirmation-denied", "binding-exception"):
            with self.subTest(mode=mode):
                result = self.equivalent(modes=(mode,))
                if mode in ("success", "exited", "gone", "confirmation-gone"):
                    self.assertIsNone(result[3]["firstFailure"])
                if mode == "confirmation-denied":
                    failure = result[3]["firstFailure"]
                    self.assertEqual(failure["failureDepth"], 1)
                    self.assertEqual(failure["attempts"], 1)

    def test_observer_failure_preserves_errno_and_call_equivalence(self):
        for mode in ("success", "path-race", "binding-exception"):
            with self.subTest(mode=mode):
                plain = self.exercise(modes=(mode,), observed=False)
                broken = self.exercise(modes=(mode,), observer_fault=True)
                self.assertEqual(broken[:3], plain[:3])
                self.assertTrue(broken[3]["unavailable"])

    def test_first_failure_redaction_and_bounded_saturation(self):
        fake = FakeBindings(("generation-change",))
        observer = DiscoveryObserver(fake.backend)
        with observer:
            for _ in range(50):
                with self.assertRaises(Exception):
                    fake.backend.capture(424242)
        document = observer.document()
        raw = canonical(document)
        self.assertLessEqual(len(raw), 8192)
        self.assertEqual(len(document["firstFailure"]["stages"]), 12)
        for secret in (b"SYNTHETIC_SECRET", b"424242", b"900000000", b"123456789"):
            self.assertNotIn(secret, raw)
        original = document["firstFailure"]
        with observer:
            fake.list_result = 0
            with self.assertRaises(Exception):
                fake.backend.pids()
        self.assertEqual(observer.document()["firstFailure"], original)
        observer.counts["captureCalls"] = 2147483647
        observer.increment("captureCalls")
        self.assertTrue(observer.document()["countsCapped"])


if __name__ == "__main__":
    unittest.main()
