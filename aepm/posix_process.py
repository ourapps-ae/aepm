"""Keep a cooperating command's group identifier reserved until signaling ends."""

import ctypes
import errno
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from .io import fail
from .model import AepmError
from .supervision import observe


class DarwinSignalInfo(ctypes.Structure):
    _fields_ = [("signo", ctypes.c_int), ("error", ctypes.c_int), ("code", ctypes.c_int),
                ("pid", ctypes.c_int), ("uid", ctypes.c_uint32), ("status", ctypes.c_int),
                ("address", ctypes.c_void_p), ("value", ctypes.c_void_p), ("band", ctypes.c_long),
                ("reserved", ctypes.c_ulong * 7)]


class DarwinProcessInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in
                ("flags", "status", "exit_status", "pid", "parent", "uid", "gid", "ruid", "rgid", "saved_uid", "saved_gid", "reserved")]
    _fields_ += [("command", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in ("files", "group", "job_count", "terminal", "terminal_group")]
    _fields_ += [("nice", ctypes.c_int32), ("started_seconds", ctypes.c_uint64), ("started_microseconds", ctypes.c_uint64)]


class DarwinSignalAction(ctypes.Structure):
    _fields_ = [("handler", ctypes.c_void_p), ("mask", ctypes.c_uint32), ("flags", ctypes.c_int)]


class LinuxSignalAction(ctypes.Structure):
    _fields_ = [("handler", ctypes.c_void_p), ("mask", ctypes.c_ulong * 16),
                ("flags", ctypes.c_int), ("restorer", ctypes.c_void_p)]


class ExitObserver:
    def __init__(self):
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            fail("cleanup-failed", "child-signal-disposition")
        if sys.platform == "darwin":
            if ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(DarwinSignalInfo) != 104 or ctypes.sizeof(DarwinProcessInfo) != 136:
                fail("cleanup-failed", "process-observer")
            self.library = ctypes.CDLL(None, use_errno=True)
            self.action_type, self.no_wait_flag = DarwinSignalAction, 0x20
            try:
                self.waitid = self.library.waitid
            except AttributeError:
                fail("cleanup-failed", "process-observer")
            self.waitid.argtypes = [ctypes.c_int, ctypes.c_uint32, ctypes.POINTER(DarwinSignalInfo), ctypes.c_int]
            self.waitid.restype = ctypes.c_int
            self.proc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            self.proc.proc_listpgrppids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
            self.proc.proc_listpgrppids.restype = ctypes.c_int
            self.proc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
            self.proc.proc_pidinfo.restype = ctypes.c_int
        elif sys.platform.startswith("linux") and hasattr(os, "waitid") and hasattr(os, "WNOWAIT"):
            try:
                library_name = os.confstr("CS_GNU_LIBC_VERSION") or ""
            except (ValueError, OSError):
                library_name = ""
            if ctypes.sizeof(ctypes.c_void_p) != 8 or not library_name.startswith("glibc ") or ctypes.sizeof(LinuxSignalAction) != 152:
                fail("cleanup-failed", "process-observer")
            self.library = ctypes.CDLL(None, use_errno=True)
            self.action_type, self.no_wait_flag = LinuxSignalAction, 2
            self.proc = None
        else:
            fail("cleanup-failed", "process-observer")
        self.sigaction = self.library.sigaction
        self.sigaction.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        self.sigaction.restype = ctypes.c_int
        self.check_disposition()

    def check_disposition(self):
        action = self.action_type()
        if (signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
                or self.sigaction(signal.SIGCHLD, None, ctypes.byref(action)) != 0
                or action.handler or action.flags & self.no_wait_flag):
            fail("cleanup-failed", "child-signal-disposition")

    def observe(self, pid):
        self.check_disposition()
        while True:
            if sys.platform == "darwin":
                result = DarwinSignalInfo()
                ctypes.set_errno(0)
                value = self.waitid(1, pid, ctypes.byref(result), 0x25)
                if value:
                    error = ctypes.get_errno()
                    if error == errno.EINTR:
                        continue
                    if error == errno.ECHILD:
                        raise ChildProcessError(error, "Child ownership lost")
                    fail("cleanup-failed", "process-observer")
                if result.pid == 0:
                    return None
                if result.pid != pid:
                    fail("cleanup-failed", "process-observer")
                code, status = result.code, result.status
            else:
                try:
                    result = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except InterruptedError:
                    continue
                if result is None:
                    return None
                if result.si_pid != pid:
                    fail("cleanup-failed", "process-observer")
                code, status = result.si_code, result.si_status
            if code == 1:
                return status
            if code in (2, 3):
                return -status
            fail("cleanup-failed", "process-observer")

    def live_members(self, group):
        if sys.platform == "darwin":
            capacity = 64
            while capacity <= 65536:
                values = (ctypes.c_int * capacity)()
                ctypes.set_errno(0)
                count = self.proc.proc_listpgrppids(group, values, ctypes.sizeof(values))
                if count < 0 or count == 0 and ctypes.get_errno() not in (0, errno.ESRCH):
                    fail("cleanup-failed", "group-census")
                if count < capacity:
                    break
                capacity *= 2
            else:
                fail("cleanup-failed", "group-census")
            members = []
            for pid in values[:count]:
                info = DarwinProcessInfo()
                ctypes.set_errno(0)
                size = self.proc.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
                if size == 0 and ctypes.get_errno() == errno.ESRCH:
                    continue
                if size != ctypes.sizeof(info) or info.pid != pid:
                    fail("cleanup-failed", "group-census")
                if info.group == group and info.status != 5:
                    members.append(pid)
            return members
        members = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                data = (entry / "stat").read_text()
            except FileNotFoundError:
                continue
            except OSError:
                fail("cleanup-failed", "group-census")
            _, separator, fields = data.rpartition(") ")
            values = fields.split()
            if not separator or len(values) < 3:
                fail("cleanup-failed", "group-census")
            if int(values[2]) == group and values[0] not in ("Z", "X"):
                members.append(int(entry.name))
        return members


class ContainedProcess:
    def __init__(self, argv, cwd, environment, *, diagnostics=None, adoption_root=None):
        self.diagnostics = diagnostics
        self.observer = ExitObserver()
        self.scope = None
        if environment.get("AEPM_PRIVATE_ROOT"):
            from .private_process import PrivateScope
            options = {key: value for key, value in (("diagnostics", diagnostics), ("adoption_root", adoption_root))
                       if value is not None}
            self.scope = PrivateScope(environment["AEPM_PRIVATE_ROOT"], **options)
        try:
            self.popen = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
        except BaseException:
            if self.scope:
                self.scope.close()
            raise
        self.pid, self.stdout, self.stderr = self.popen.pid, self.popen.stdout, self.popen.stderr
        self.signaling_finished = self.reaped = self.ownership_lost = False
        self.cleaned = False
        try:
            if self.scope:
                self.scope.bind(self.pid)
        except BaseException:
            try:
                self.terminate_tree()
                self.reap()
            finally:
                self.close()
            raise

    def observe_exit(self):
        if self.ownership_lost:
            fail("cleanup-failed", "child-ownership")
        if self.reaped:
            return self.popen.returncode
        try:
            return self.observer.observe(self.pid)
        except ChildProcessError:
            self.ownership_lost = True
            self.signaling_finished = True
            # Disable Popen's deferred wait on an identifier it no longer owns.
            self.popen.returncode = 255
            fail("cleanup-failed", "child-ownership")

    def sample_private(self):
        if self.scope and not self.signaling_finished:
            self.scope.scan()

    def signal_group(self):
        if self.signaling_finished or self.reaped:
            fail("cleanup-failed", "child-ownership")
        self.observe_exit()
        target = {"kind": "reserved-group", "number": self.pid, "uniqueIdentity": None, "generation": None}
        observe(getattr(self, "diagnostics", None), "event", "group-cleanup", "signal", "attempted", target)
        try:
            os.killpg(self.pid, signal.SIGKILL)
            observe(getattr(self, "diagnostics", None), "event", "group-cleanup", "signal", "succeeded", target)
        except ProcessLookupError:
            observe(getattr(self, "diagnostics", None), "event", "group-cleanup", "signal", "unavailable", target)
            pass
        except PermissionError:
            observe(getattr(self, "diagnostics", None), "event", "group-cleanup", "signal", "failed", target)
            # Darwin may reject a group containing only an unreaped zombie.
            if self.observe_exit() is None or self.observer.live_members(self.pid):
                raise

    def terminate_tree(self):
        if self.signaling_finished:
            return self.cleaned
        deadline = time.monotonic() + 5
        diagnostics = getattr(self, "diagnostics", None)
        observe(diagnostics, "event", "group-cleanup", "enter", "attempted")
        try:
            while time.monotonic() < deadline:
                if self.observe_exit() is not None and not self.observer.live_members(self.pid):
                    self.cleaned = self.scope.finish(deadline) if self.scope else True
                    break
                self.signal_group()
                if not self.observer.live_members(self.pid) and self.observe_exit() is not None:
                    self.cleaned = self.scope.finish(deadline) if self.scope else True
                    break
                time.sleep(.01)
            else:
                observe(diagnostics, "fault", "group-cleanup", "cleanup-deadline")
        except (AepmError, OSError, RuntimeError) as error:
            observe(diagnostics, "fault", "group-cleanup", error=error)
            self.cleaned = False
        finally:
            self.signaling_finished = True
            observe(diagnostics, "event", "group-cleanup", "return", "succeeded" if self.cleaned else "failed")
        return self.cleaned

    def reap(self):
        if not self.signaling_finished or self.ownership_lost:
            fail("cleanup-failed", "child-ownership")
        if self.reaped:
            return self.popen.returncode
        if self.observe_exit() is None:
            return None
        try:
            pid, status = os.waitpid(self.pid, 0)
        except ChildProcessError:
            self.ownership_lost = True
            self.popen.returncode = 255
            fail("cleanup-failed", "child-ownership")
        if pid != self.pid:
            fail("cleanup-failed", "child-ownership")
        self.popen.returncode = os.waitstatus_to_exitcode(status)
        self.reaped = True
        return self.popen.returncode

    def close(self):
        for stream in (self.stdout, self.stderr):
            if stream is not None:
                stream.close()
        if self.scope:
            self.scope.close()
