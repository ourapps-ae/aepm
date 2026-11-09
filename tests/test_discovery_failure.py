"""Rejected process listing: fails closed and names errno and counts; fake listing, no launches or signals."""

import ctypes as c
import errno
import json
import os
import stat

from aepm.model import AepmError
from aepm.private_process import DarwinBackend, DiscoveryFailure, enroll_root
from aepm.supervision import Recorder
from tests.test_capture_race import Guarded
from tests.test_conflict_record import process
from tests.test_private_process import FakeBackend


CAPACITY = 65536 * c.sizeof(c.c_int)


def listing_backend(count, number=0):
    """A DarwinBackend whose only native call is a fake proc_listpids."""
    backend = DarwinBackend.__new__(DarwinBackend)

    def listing(kind, user, values, size):
        if count > 0:
            values[0] = 4242
        c.set_errno(number)
        return count

    backend.listing = listing
    return backend


class FailingListing(FakeBackend):
    """Lists normally until armed, then rejects like the native count check."""

    def __init__(self, records):
        super().__init__(records)
        self.failure = None

    def pids(self):
        if self.failure:
            raise DiscoveryFailure(*self.failure)
        return super().pids()


class DiscoveryFailureTests(Guarded):
    def records(self):
        return sorted(path.name for path in self.root.glob("discovery-*.json"))

    def load(self, name="discovery-1.json"):
        path = self.root / name
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        return json.loads(path.read_text())

    def test_each_rejected_count_carries_errno_and_counts(self):
        for count, number in ((0, errno.ENOMEM), (-1, errno.EPERM), (CAPACITY, 0), (CAPACITY + 4, 0), (6, 0)):
            with self.subTest(count=count), self.assertRaises(DiscoveryFailure) as caught:
                listing_backend(count, number).pids()
            error = caught.exception
            self.assertIsInstance(error, AepmError)
            self.assertEqual((error.code, error.path, error.errno, error.returned, error.capacity),
                             ("cleanup-failed", "private-process-discovery", number, count, CAPACITY))

    def test_accepted_count_unchanged(self):
        self.assertEqual(listing_backend(8).pids(), [4242])

    def test_scan_rejection_fails_closed_with_record_and_supervision_errno(self):
        recorder = Recorder()
        backend = FailingListing({200: process(200)})
        scope = self.scope(backend, recorder)
        backend.failure = (errno.ENOMEM, 0, CAPACITY)
        with self.assertRaises(DiscoveryFailure):
            scope.scan(force=True)
        self.assertTrue(scope.failed)
        self.assertEqual(self.records(), ["discovery-1.json"])
        self.assertEqual(self.load(), {"format": 1, "site": "scan", "errno": errno.ENOMEM, "returnedBytes": 0,
                                       "capacityBytes": CAPACITY, "entryBytes": 4})
        error = recorder.failure["observation"]["error"]
        self.assertEqual((error["location"], error["number"]), ("private-process-discovery", errno.ENOMEM))

    def test_enroll_and_constructor_rejections_named(self):
        backend = FailingListing({})
        backend.failure = (0, CAPACITY, CAPACITY)
        with self.assertRaises(DiscoveryFailure):
            enroll_root(self.root, before_work=False, backend=backend)
        self.assertEqual(self.load()["site"], "enroll")
        enroll_root(self.root, before_work=False, backend=FakeBackend({}))
        backend.failure = (errno.EINVAL, 6, CAPACITY)
        with self.assertRaises(DiscoveryFailure):
            self.scope(backend)
        self.assertEqual((self.load("discovery-2.json")["site"], self.load("discovery-2.json")["returnedBytes"]),
                         ("constructor", 6))

    def test_record_cap_link_and_write_failure_leave_outcome_unchanged(self):
        target = self.root.parent / (self.root.name + "-outside-target")
        target.write_text("untouched")
        self.addCleanup(target.unlink)
        (self.root / "discovery-1.json").symlink_to(target)
        backend = FailingListing({})
        backend.failure = (0, 0, CAPACITY)
        with self.assertRaises(DiscoveryFailure):
            enroll_root(self.root, before_work=False, backend=backend)
        self.assertEqual(target.read_text(), "untouched")
        self.assertEqual(self.load("discovery-2.json")["site"], "enroll")
        for number in (3, 4):
            (self.root / ("discovery-%d.json" % number)).write_text("full")
        with self.assertRaises(DiscoveryFailure):
            enroll_root(self.root, before_work=False, backend=backend)
        self.assertFalse((self.root / "discovery-5.json").exists())
        for number in (2, 3, 4):
            (self.root / ("discovery-%d.json" % number)).unlink()
        os.chmod(self.root, 0o500)
        self.addCleanup(os.chmod, self.root, 0o700)
        with self.assertRaises(DiscoveryFailure):
            enroll_root(self.root, before_work=False, backend=backend)
        self.assertEqual(self.records(), ["discovery-1.json"])
