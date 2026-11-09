"""Simulated handle failures; these do not establish native Windows execution."""

from collections import Counter
import ctypes
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aepm import windows
from aepm.model import AepmError


class KernelFixture:
    def __init__(self, failure=None):
        self.failure, self.next = failure, 100
        self.allocated, self.closed = [], []
        self.created = self.resumed = False
        self.inheritance_calls = 0

    def handle(self):
        self.next += 1
        self.allocated.append(self.next)
        return self.next

    def CreateJobObjectW(self, *_):
        return self.handle()

    def SetInformationJobObject(self, *_):
        return 1

    def CreatePipe(self, read, write, *_):
        read._obj.value, write._obj.value = self.handle(), self.handle()
        return 1

    def SetHandleInformation(self, *_):
        self.inheritance_calls += 1
        return 0 if self.failure == "inheritance" or self.failure == "inheritance-second" and self.inheritance_calls == 2 else 1

    def CreateFileW(self, *_):
        return ctypes.c_void_p(-1).value if self.failure == "stdin" else self.handle()

    def InitializeProcThreadAttributeList(self, buffer, _count, _flags, size):
        size._obj.value = 32
        return int(buffer is not None)

    def UpdateProcThreadAttribute(self, *_):
        return 1

    def DeleteProcThreadAttributeList(self, *_):
        pass

    def CreateProcessW(self, *args):
        self.created = True
        info = args[-1]._obj
        info.process, info.thread, info.pid = self.handle(), self.handle(), 1234
        return 1

    def AssignProcessToJobObject(self, *_):
        return 1

    def ResumeThread(self, *_):
        self.resumed = True
        return 1

    def TerminateJobObject(self, *_):
        return 1

    def QueryInformationJobObject(self, _job, _kind, data, *_):
        data._obj.active = 0
        return 1

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return 1


class SimulatedWindowsSetupTests(unittest.TestCase):
    def test_handle_setup_failure_prevents_child_creation(self):
        for failure in ("inheritance", "inheritance-second", "stdin"):
            with self.subTest(failure=failure):
                kernel = KernelFixture(failure)
                with patch.object(windows, "api", return_value=kernel), patch.dict(sys.modules, {"msvcrt": SimpleNamespace()}), self.assertRaisesRegex(AepmError, "windows-containment-unavailable"):
                    windows.ContainedProcess(["fixture.exe"], ".", {})
                self.assertFalse(kernel.created)
                self.assertEqual(Counter(kernel.closed), Counter(kernel.allocated))
                self.assertNotIn(ctypes.c_void_p(-1).value, kernel.closed)

    def test_each_descriptor_or_stream_conversion_failure_closes_once(self):
        for phase in ("descriptor", "stream"):
            for failing_index in (1, 2):
                with self.subTest(phase=phase, index=failing_index):
                    kernel = KernelFixture()
                    descriptors, calls = {}, {"descriptor": 0, "stream": 0}

                    def open_descriptor(handle, _flags):
                        calls["descriptor"] += 1
                        if phase == "descriptor" and calls["descriptor"] == failing_index:
                            raise OSError("simulated descriptor failure")
                        descriptor = 200 + calls["descriptor"]
                        descriptors[descriptor] = handle
                        return descriptor

                    def close_descriptor(descriptor):
                        kernel.CloseHandle(descriptors.pop(descriptor))

                    def open_stream(_descriptor, _mode, *, buffering, closefd):
                        self.assertFalse(closefd)
                        self.assertEqual(buffering, 0)
                        calls["stream"] += 1
                        if phase == "stream" and calls["stream"] == failing_index:
                            raise OSError("simulated stream failure")
                        return SimpleNamespace(close=lambda: None)

                    with patch.object(windows, "api", return_value=kernel), patch.dict(sys.modules, {"msvcrt": SimpleNamespace(open_osfhandle=open_descriptor)}), patch.object(windows.os, "fdopen", open_stream), patch.object(windows.os, "close", close_descriptor), self.assertRaises(AepmError):
                        windows.ContainedProcess(["fixture.exe"], ".", {})
                    self.assertTrue(kernel.created)
                    self.assertFalse(kernel.resumed)
                    self.assertFalse(descriptors)
                    self.assertEqual(Counter(kernel.closed), Counter(kernel.allocated))
