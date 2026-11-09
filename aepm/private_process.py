"""Generation-bound supervision of an exclusive verification-private namespace."""

import ctypes as c
from dataclasses import dataclass, field
import errno
import json
import os
from pathlib import Path
import select
import signal
import sys
import threading
import time
import math
from typing import cast

from .io import fail
from .model import AepmError
from .posix_process import DarwinProcessInfo
from .supervision import observe


class UniqueInfo(c.Structure):
    _fields_ = [("uuid", c.c_ubyte * 16), ("unique", c.c_uint64), ("parent_unique", c.c_uint64),
                ("generation", c.c_int32), ("original_parent_generation", c.c_int32), ("reserved", c.c_uint64 * 2)]


class CombinedInfo(c.Structure):
    _fields_ = [("basic", DarwinProcessInfo), ("unique", UniqueInfo)]


AuditToken = c.c_uint32 * 8


class CaptureRace(AepmError):
    """A live process changed during every capture attempt; the scan treats it as unresolved."""

    def __init__(self):
        super().__init__("cleanup-failed", "private-process-discovery")


class SignalRace(AepmError):
    """A live owned identity refused three signals with ESRCH; finish keeps it live-listed."""

    def __init__(self):
        super().__init__("cleanup-failed", "private-process-signal")
        self.errno = errno.ESRCH


class DiscoveryFailure(AepmError):
    """The process listing returned an unusable byte count; carries the call's errno and counts."""

    def __init__(self, number, returned, capacity):
        super().__init__("cleanup-failed", "private-process-discovery")
        self.errno = number
        self.returned = returned
        self.capacity = capacity


class SignalFailure(AepmError):
    """The kernel refused a signal with an error other than ESRCH."""

    def __init__(self, number):
        super().__init__("cleanup-failed", "private-process-signal")
        self.errno = number


@dataclass
class Identity:
    pid: int
    key: object
    uid: int
    parent: int
    group: int
    status: object
    executable: str | None = None
    cwd: str | None = None
    token: object = None
    handle: int | None = None
    generation: int = 0
    started_ns: int | None = None
    executable_missing: bool = False
    signals_sent: list = field(default_factory=list)


class DarwinBackend:
    diagnostics: object = None

    def __init__(self):
        if c.sizeof(CombinedInfo) != 192 or c.sizeof(UniqueInfo) != 56:
            fail("cleanup-failed", "private-process-layout")
        self.library = c.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        try:
            self.info = self.library.proc_pidinfo
            self.listing = self.library.proc_listpids
            self.path = self.library.proc_pidpath_audittoken
            self.send = self.library.proc_signal_with_audittoken
            self.extended = getattr(self.library, "__proc_info_extended_id")
        except AttributeError:
            fail("cleanup-failed", "private-process-capability")
        self.info.argtypes = [c.c_int, c.c_int, c.c_uint64, c.c_void_p, c.c_int]
        self.info.restype = c.c_int
        self.listing.argtypes = [c.c_uint32, c.c_uint32, c.c_void_p, c.c_int]
        self.listing.restype = c.c_int
        self.path.argtypes = [c.POINTER(AuditToken), c.c_void_p, c.c_uint32]
        self.path.restype = c.c_int
        self.send.argtypes = [c.POINTER(AuditToken), c.c_int]
        self.send.restype = c.c_int
        self.extended.argtypes = [c.c_int32, c.c_int32, c.c_uint32, c.c_uint32, c.c_uint64, c.c_uint64, c.c_void_p, c.c_int32]
        self.extended.restype = c.c_int
        if self.capture(os.getpid(), paths=True, allow_missing_executable=True) is None:
            fail("cleanup-failed", "private-process-capability")

    def pids(self):
        capacity = 65536
        values = (c.c_int * capacity)()
        c.set_errno(0)
        count = self.listing(4, os.geteuid(), values, c.sizeof(values))
        if count <= 0 or count >= c.sizeof(values) or count % c.sizeof(c.c_int):
            raise DiscoveryFailure(c.get_errno(), count, c.sizeof(values))
        return [pid for pid in values[:count // c.sizeof(c.c_int)] if pid > 0]

    def capture(self, pid, *, paths=True, allow_missing_executable=False):
        for _ in range(3):
            data = CombinedInfo()
            c.set_errno(0)
            size = self.info(pid, 18, 1, c.byref(data), c.sizeof(data))
            if size == 0 and c.get_errno() == errno.ESRCH:
                return None
            if size != c.sizeof(data) or data.basic.pid != pid:
                fail("cleanup-failed", "private-process-identity")
            b = data.basic
            token = AuditToken(b.ruid, b.uid, b.gid, b.ruid, b.rgid, pid, 0, data.unique.generation & 0xffffffff)
            result = Identity(pid, data.unique.unique, b.uid, b.parent, b.group, b.status, token=token,
                              generation=token[7], started_ns=b.started_seconds * 1_000_000_000 + b.started_microseconds * 1000)
            if not paths or b.status == 5:
                return result
            executable, directories = c.create_string_buffer(4096), c.create_string_buffer(2352)
            c.set_errno(0)
            length = self.path(c.byref(token), executable, len(executable))
            error = c.get_errno()
            if length <= 0 or length >= len(executable):
                if error == errno.ESRCH:
                    continue
                if length == 0 and error == errno.ENOENT and allow_missing_executable:
                    result.executable_missing = True
                else:
                    fail("cleanup-failed", "private-process-path")
            c.set_errno(0)
            size = self.extended(2, pid, 9, 2, data.unique.unique, 0, directories, len(directories))
            if size == -1 and c.get_errno() == errno.ESRCH:
                continue
            if size != len(directories):
                fail("cleanup-failed", "private-process-directory")
            confirmation = self.capture(pid, paths=False)
            if confirmation is None:
                return None
            if confirmation.key != result.key or confirmation.token[7] != token[7]:
                continue
            try:
                result.executable = None if result.executable_missing else executable.value.decode("utf-8")
                cwd_bytes = directories.raw[152:1176]
                if b"\0" not in cwd_bytes:
                    fail("cleanup-failed", "private-process-directory")
                result.cwd = cwd_bytes.split(b"\0", 1)[0].decode("utf-8")
            except UnicodeError:
                fail("cleanup-failed", "private-process-path")
            if not result.cwd or not result.executable and not result.executable_missing:
                fail("cleanup-failed", "private-process-path")
            return result
        final = self.capture(pid, paths=False)
        if final is None or final.status == 5:
            return final
        raise CaptureRace()

    def refresh(self, owned):
        value = self.capture(owned.pid, paths=False)
        if value is None or value.key != owned.key or value.status == 5:
            return None
        if value.uid != owned.uid or value.uid != os.geteuid():
            fail("cleanup-failed", "private-process-user")
        owned.token, owned.status, owned.group = value.token, value.status, value.group
        return owned

    def terminate(self, owned, number):
        for _ in range(3):
            if self.refresh(owned) is None:
                return
            diagnostics = getattr(self, "diagnostics", None)
            target = {"kind": "owned-process", "number": owned.pid, "uniqueIdentity": owned.key,
                      "generation": int(owned.token[7])}
            observe(diagnostics, "event", "private-signal", "signal", "attempted", target)
            result = self.send(c.byref(owned.token), number)
            observe(diagnostics, "event", "private-signal", "signal", "succeeded" if result == 0 else "failed", target)
            if result == 0:
                owned.signals_sent.append({"signal": number, "generation": int(owned.token[7])})
                return
            if result != errno.ESRCH:
                raise SignalFailure(result)
        if self.refresh(owned) is not None:
            raise SignalRace()

    def close(self, _record):
        pass


class LinuxBackend:
    diagnostics: object = None

    def __init__(self):
        opener = getattr(os, "pidfd_open", None)
        sender = getattr(signal, "pidfd_send_signal", None)
        if not callable(opener) or not callable(sender):
            fail("cleanup-failed", "private-process-capability")
        self.open_descriptor = opener
        self.send_descriptor = sender

    def pids(self):
        result = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                if entry.stat().st_uid == os.geteuid():
                    result.append(int(entry.name))
            except FileNotFoundError:
                continue
        if len(result) >= 65536:
            fail("cleanup-failed", "private-process-discovery")
        return result

    def exited(self, descriptor):
        poll = select.poll()
        poll.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
        return bool(poll.poll(0))

    def capture(self, pid, *, paths=True, allow_missing_executable=False):
        try:
            descriptor = self.open_descriptor(pid)
        except ProcessLookupError:
            return None
        if type(descriptor) is not int or descriptor < 0:
            fail("cleanup-failed", "private-process-capability")
        try:
            root = Path("/proc") / str(pid)
            status = (root / "stat").read_text()
            _, separator, body = status.rpartition(") ")
            values = body.split()
            if not separator or len(values) < 20:
                fail("cleanup-failed", "private-process-identity")
            uid = None
            for line in (root / "status").read_text().splitlines():
                if line.startswith("Uid:"):
                    uid = int(line.split()[2])
                    break
            if uid is None:
                fail("cleanup-failed", "private-process-user")
            result = Identity(pid, (pid, int(values[19])), uid, int(values[1]), int(values[2]), values[0], handle=descriptor,
                              generation=int(values[19]))
            if paths:
                result.executable, result.cwd = os.readlink(root / "exe"), os.readlink(root / "cwd")
            if self.exited(descriptor):
                os.close(descriptor)
                return None
            return result
        except FileNotFoundError:
            try:
                gone = self.exited(descriptor)
            finally:
                os.close(descriptor)
            if gone:
                return None
            fail("cleanup-failed", "private-process-discovery")
        except BaseException:
            os.close(descriptor)
            raise

    def refresh(self, owned):
        if owned.handle is None or self.exited(owned.handle):
            return None
        current = self.capture(owned.pid, paths=False)
        try:
            if self.exited(owned.handle):
                return None
            if current is None or current.key != owned.key or current.uid != owned.uid or current.uid != os.geteuid():
                fail("cleanup-failed", "private-process-identity")
            owned.status, owned.group = current.status, current.group
            return owned
        finally:
            if current is not None:
                self.close(current)

    def terminate(self, owned, number):
        if self.refresh(owned) is None:
            return
        diagnostics = getattr(self, "diagnostics", None)
        target = {"kind": "owned-process", "number": owned.pid, "uniqueIdentity": None, "generation": None}
        observe(diagnostics, "event", "private-signal", "signal", "attempted", target)
        try:
            self.send_descriptor(owned.handle, number, None, 0)
            observe(diagnostics, "event", "private-signal", "signal", "succeeded", target)
            owned.signals_sent.append({"signal": number})
        except ProcessLookupError:
            observe(diagnostics, "event", "private-signal", "signal", "unavailable", target)
            return
        except OSError:
            observe(diagnostics, "event", "private-signal", "signal", "failed", target)
            fail("cleanup-failed", "private-process-signal")

    def close(self, record):
        if record.handle is not None:
            descriptor, record.handle = record.handle, None
            os.close(descriptor)


_BASELINES = {}
_BASELINE_LOCK = threading.RLock()


@dataclass
class RootBaseline:
    path: Path
    descriptor: int
    identity: tuple
    owner: int
    generations: dict
    active: int = 0
    poisoned: bool = False


CONFLICT_RECORDS = 16
DISCOVERY_RECORDS = 4
STEP_WINDOWS = 4096
ADOPTIONS_PER_STEP = 8
_WINDOWS = []
_WINDOWS_FULL = False


def adoption_root(value):
    """Validate the proof-supplied adoption root once; None keeps adoption disabled."""
    if value is None:
        return None
    from .bundle import ordinary_path
    try:
        path = Path(value)
        if not path.is_absolute():
            fail("adoption-root-invalid", "adoptionRoot")
        ordinary_path(path)
        if not path.is_dir():
            fail("adoption-root-invalid", "adoptionRoot")
        return path.resolve()
    except AepmError as error:
        if error.code == "adoption-root-invalid":
            raise
        fail("adoption-root-invalid", "adoptionRoot")
    except (OSError, TypeError, ValueError):
        fail("adoption-root-invalid", "adoptionRoot")


def _open_window(start):
    global _WINDOWS_FULL
    with _BASELINE_LOCK:
        if len(_WINDOWS) >= STEP_WINDOWS:
            _WINDOWS_FULL = True
            return None
        window = [start, None]
        _WINDOWS.append(window)
        return window


def _close_window(window):
    if window is not None:
        with _BASELINE_LOCK:
            if window[1] is None:
                window[1] = time.time_ns()


def _window_index(started_ns):
    """Index of this run's recorded step window containing the start time, or None."""
    if not started_ns or started_ns <= 0:
        return None
    now = time.time_ns()
    with _BASELINE_LOCK:
        if _WINDOWS_FULL:
            return None
        return next((index for index, (start, end) in enumerate(_WINDOWS)
                     if start <= started_ns <= (now if end is None else end)), None)


def _record_conflict(root, site, record, origin, *, scope=None, adopted_root=None, window=None):
    """Name a conflicting process beside the copied tree; never affects the outcome."""
    try:
        from .bundle import ordinary_path
        root = Path(root)
        ordinary_path(root)
        resolved = root.resolve()

        def inside(value):
            return bool(value) and Path(value).is_absolute() and Path(value).resolve().is_relative_to(resolved)

        wall, monotonic = origin
        cwd_inside = inside(record.cwd)
        value = {"format": 1, "site": site, "atSeconds": round(time.monotonic() - monotonic, 3),
                 "pid": record.pid, "uniqueIdentity": record.key, "generation": record.generation,
                 "executableBasename": Path(record.executable).name[:128] if record.executable else None,
                 "executableInsideRoot": inside(record.executable), "cwdInsideRoot": cwd_inside,
                 "cwdRelative": Path(record.cwd).resolve().relative_to(resolved).as_posix()[:512] if cwd_inside else None,
                 "parentPid": record.parent, "launchdParent": record.parent == 1,
                 "group": record.group, "scopeGroup": getattr(scope, "group", None),
                 "startedBeforeScopeSeconds": None if not record.started_ns else round((wall - record.started_ns) / 1e9, 3)}
        if adopted_root is not None:
            value.update(adopted=True, adoptionRoot=str(adopted_root)[:512], windowIndex=window)
            value["executableRelative"] = Path(record.executable).resolve().relative_to(adopted_root).as_posix()[:512]
        data = json.dumps(value, sort_keys=True).encode()
        if len(data) > 4096:
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        for number in range(1, CONFLICT_RECORDS + 1):
            try:
                descriptor = os.open(root / ("conflict-%d.json" % number), flags, 0o600)
            except FileExistsError:
                continue
            try:
                os.write(descriptor, data)
            finally:
                os.close(descriptor)
            return
    except Exception:
        pass


def _listed(backend, root, site):
    """List pids; a rejected listing is named beside the copied tree, then fails closed."""
    try:
        return backend.pids()
    except DiscoveryFailure as error:
        try:
            value = {"format": 1, "site": site, "errno": error.errno, "returnedBytes": error.returned,
                     "capacityBytes": error.capacity, "entryBytes": c.sizeof(c.c_int)}
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            for number in range(1, DISCOVERY_RECORDS + 1):
                try:
                    descriptor = os.open(Path(root) / ("discovery-%d.json" % number), flags, 0o600)
                except FileExistsError:
                    continue
                try:
                    os.write(descriptor, json.dumps(value, sort_keys=True).encode())
                finally:
                    os.close(descriptor)
                break
        except Exception:
            pass
        raise


def _matches(root, record):
    for value in (record.executable, record.cwd):
        if value:
            if sys.platform.startswith("linux") and value.endswith(" (deleted)"):
                value = value[:-10]
            if Path(value).is_absolute() and Path(value).resolve().is_relative_to(root):
                return True
    return False


def _ancestors(backend, initial):
    result, current = set(), os.getpid()
    while current > 1 and current in initial:
        record = backend.capture(current, paths=False)
        if record is None:
            break
        if record.uid != os.geteuid():
            backend.close(record)
            break
        result.add(record.key)
        parent = record.parent
        backend.close(record)
        if current == parent:
            break
        current = parent
    return result


RECHECK_INTERVAL, RECHECK_BOUND = .05, 2.0


def _resolve_all(pids, examine):
    """Examine every pid; recheck only racing pids, spaced, and fail closed if any stays unresolved."""
    pending = []
    for pid in pids:
        try:
            examine(pid)
        except CaptureRace:
            pending.append(pid)
    deadline = time.monotonic() + RECHECK_BOUND
    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CaptureRace()
        time.sleep(min(RECHECK_INTERVAL, remaining))
        unresolved = []
        for pid in pending:
            try:
                examine(pid)
            except CaptureRace:
                unresolved.append(pid)
        pending = unresolved


def enroll_root(root, *, before_work=False, backend=None):
    from .bundle import ordinary_path
    origin = (time.time_ns(), time.monotonic())
    root = Path(root)
    ordinary_path(root)
    info = root.stat()
    if not root.is_absolute() or not root.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        fail("cleanup-failed", "private-process-root")
    root = root.resolve()
    identity = (info.st_dev, info.st_ino)
    with _BASELINE_LOCK:
        for key, entry in list(_BASELINES.items()):
            if entry.active:
                continue
            try:
                present = entry.path.lstat()
                valid = (present.st_dev, present.st_ino) == entry.identity and not entry.path.is_symlink()
            except FileNotFoundError:
                valid = False
            if not valid:
                os.close(entry.descriptor)
                del _BASELINES[key]
        existing = _BASELINES.get(identity)
        if existing:
            held = os.fstat(existing.descriptor)
            if existing.owner != os.getpid() or existing.path != root or existing.poisoned or (held.st_dev, held.st_ino) != identity:
                fail("cleanup-failed", "private-process-baseline")
            return existing
        if len(_BASELINES) >= 512:
            fail("cleanup-failed", "private-process-baseline-limit")
        if before_work and any(root.iterdir()):
            fail("cleanup-failed", "private-process-enrollment")
        descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            held = os.fstat(descriptor)
            if (held.st_dev, held.st_ino) != identity:
                fail("cleanup-failed", "private-process-root")
            backend = backend or (DarwinBackend() if sys.platform == "darwin" else LinuxBackend())
            initial = _listed(backend, root, "enroll")
            ancestors = _ancestors(backend, initial)
            birth = getattr(info, "st_birthtime_ns", None)
            if birth is None:
                value = getattr(info, "st_birthtime", None)
                if isinstance(value, (int, float)) and math.isfinite(value) and value > 0:
                    birth = math.floor(value * 1_000_000_000) - math.ceil(math.ulp(value) * 1_000_000_000)
            generations = {}

            def examine(pid):
                record = backend.capture(pid, paths=False)
                if record is None:
                    return
                try:
                    if record.key in ancestors:
                        generations[record.key] = record.generation
                        return
                    backend.close(record)
                    record = None
                    record = backend.capture(pid, paths=True, allow_missing_executable=True)
                    if record is None:
                        return
                    if record.uid != os.geteuid():
                        fail("cleanup-failed", "private-process-user")
                    if _matches(root, record):
                        _record_conflict(root, "enroll", record, origin)
                        fail("cleanup-failed", "private-process-conflict")
                    if record.executable_missing and not before_work:
                        if birth is None or record.started_ns is None or record.started_ns <= 0 or record.started_ns + 1_001_000 >= birth:
                            fail("cleanup-failed", "private-process-baseline-age")
                    generations[record.key] = record.generation
                finally:
                    if record is not None:
                        backend.close(record)

            _resolve_all(initial, examine)
            if before_work and any(root.iterdir()):
                fail("cleanup-failed", "private-process-enrollment")
            entry = RootBaseline(root, descriptor, identity, os.getpid(), generations)
            _BASELINES[identity] = entry
            return entry
        except BaseException:
            os.close(descriptor)
            raise


class PrivateScope:
    def __init__(self, root, *, diagnostics=None, adoption_root=None):
        self.origin = (time.time_ns(), time.monotonic())
        self.adoption_root = adoption_root
        self.adopted = []
        self.window = _open_window(self.origin[0])
        self.diagnostics = diagnostics
        self.last_live_count = None
        self.backend = DarwinBackend() if sys.platform == "darwin" else LinuxBackend()
        self.backend.diagnostics = diagnostics
        self.registration = enroll_root(root, backend=self.backend)
        self.root, self.directory_identity = self.registration.path, self.registration.identity
        self.closed = self.completed = False
        self.owned, self.baseline, self.ancestors = {}, set(), set()
        self.initial_gone = set()
        self.group = None
        self.root_exited = False
        self.next_scan = 0.0
        self.unresolved = False
        self.failed = False
        with _BASELINE_LOCK:
            if self.registration.active:
                fail("cleanup-failed", "private-process-conflict")
            self.registration.active += 1
        try:
            initial = _listed(self.backend, self.root, "constructor")
            self.ancestors = _ancestors(self.backend, initial)

            def examine(pid):
                record = self._capture(pid)
                if record is None:
                    self.initial_gone.add(pid)
                    return
                try:
                    self.baseline.add(record.key)
                    if record.key not in self.ancestors and self.matches_root(record):
                        _record_conflict(self.root, "constructor", record, self.origin, scope=self)
                        fail("cleanup-failed", "private-process-conflict")
                finally:
                    self.backend.close(record)

            _resolve_all(initial, examine)
        except BaseException:
            self.failed = True
            self.close()
            raise

    def _capture(self, pid):
        basic = self.backend.capture(pid, paths=False)
        if basic is None:
            return None
        if basic.key in self.ancestors or basic.key in self.owned:
            return basic
        allowed = basic.key in self.registration.generations
        self.backend.close(basic)
        record = self.backend.capture(pid, paths=True, allow_missing_executable=allowed)
        if record is not None and record.executable_missing:
            if self.registration.generations.get(record.key) != record.generation or record.uid != os.geteuid():
                self.backend.close(record)
                fail("cleanup-failed", "private-process-baseline-generation")
        return record

    def matches_root(self, record):
        return _matches(self.root, record)

    def bind(self, group):
        self.group = group
        self.scan(force=True)

    def scan(self, *, force=False):
        try:
            return self._scan(force=force)
        except AepmError as error:
            observe(getattr(self, "diagnostics", None), "fault", "private-scan", error=error)
            self.failed = True
            raise
        except (OSError, ValueError, RuntimeError) as error:
            observe(getattr(self, "diagnostics", None), "fault", "private-scan", error=error)
            self.failed = True
            fail("cleanup-failed", "private-process-discovery")

    def _scan(self, *, force=False):
        if not force and time.monotonic() < self.next_scan:
            return
        self.next_scan = time.monotonic() + .1
        info = self.root.lstat()
        held = os.fstat(self.registration.descriptor)
        if (self.root.is_symlink() or not self.root.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or (info.st_dev, info.st_ino) != self.directory_identity or (held.st_dev, held.st_ino) != self.directory_identity):
            fail("cleanup-failed", "private-process-root")
        raced = False
        for pid in _listed(self.backend, self.root, "scan"):
            if self.root_exited and pid == self.group:
                continue
            try:
                record = self._capture(pid)
            except CaptureRace:
                raced = True
                continue
            if record is None:
                raced = raced or pid not in self.initial_gone
                continue
            keep = False
            try:
                if record.uid != os.geteuid() or record.key in self.ancestors:
                    continue
                if record.key in self.owned:
                    continue
                marked = self.matches_root(record)
                adopt = False
                if record.key in self.baseline:
                    if not marked:
                        continue
                    window = self.adoptable(record)
                    if window is None or len(self.adopted) >= ADOPTIONS_PER_STEP:
                        _record_conflict(self.root, "scan", record, self.origin, scope=self)
                        fail("cleanup-failed", "private-process-conflict")
                    _record_conflict(self.root, "scan", record, self.origin, scope=self,
                                     adopted_root=self.adoption_root, window=window)
                    self.adopted.append(record.key)
                    relative = Path(record.executable).resolve().relative_to(cast(Path, self.adoption_root)).as_posix()
                    observe(getattr(self, "diagnostics", None), "adopted", record.key, record.generation, relative, window)
                    adopt = True
                if adopt or record.group == self.group or marked:
                    if len(self.owned) >= 8192:
                        fail("cleanup-failed", "private-process-limit")
                    self.owned[record.key] = record
                    keep = True
            finally:
                if not keep:
                    self.backend.close(record)
        self.unresolved = raced

    def adoptable(self, record):
        """Window index if a launchd-started process from this run's steps runs code under the adoption root."""
        if self.adoption_root is None or record.parent != 1 or record.executable_missing or not record.executable:
            return None
        try:
            executable = Path(record.executable)
            if not executable.is_absolute():
                return None
            canonical = executable.resolve()
            if not canonical.is_relative_to(self.adoption_root) or canonical.is_relative_to(self.root.resolve()):
                return None
            return _window_index(record.started_ns)
        except (OSError, ValueError):
            return None

    def live(self):
        result = []
        for record in self.owned.values():
            if self.backend.refresh(record) is not None:
                result.append(record)
        return result

    def finish(self, deadline):
        self.root_exited = True
        quiescent = 0
        graceful_until = min(deadline, time.monotonic() + .5)
        while time.monotonic() < deadline:
            complete = True
            try:
                self.scan(force=True)
            except AepmError:
                complete = False
            live = []
            for record in self.owned.values():
                try:
                    if self.backend.refresh(record) is not None:
                        live.append(record)
                except (AepmError, OSError) as error:
                    observe(getattr(self, "diagnostics", None), "fault", "private-refresh", error=error)
                    self.failed = True
                    complete = False
            self.last_live_count = len(live)
            if complete and not live and not self.unresolved:
                quiescent += 1
                if quiescent == 2:
                    self.completed = not self.failed
                    return self.completed
            else:
                quiescent = 0
                for record in live:
                    try:
                        self.backend.terminate(record, signal.SIGTERM if time.monotonic() < graceful_until else signal.SIGKILL)
                    except SignalRace:
                        pass
                    except (AepmError, OSError) as error:
                        observe(getattr(self, "diagnostics", None), "fault", "private-signal", error=error)
                        self.failed = True
            time.sleep(.05)
        observe(getattr(self, "diagnostics", None), "fault", "private-scan", "cleanup-deadline")
        return False

    def close(self):
        if self.closed:
            return
        self.closed = True
        _close_window(getattr(self, "window", None))
        for record in self.owned.values():
            self.backend.close(record)
        with _BASELINE_LOCK:
            self.registration.active -= 1
            if self.failed or self.group is not None and not self.completed:
                self.registration.poisoned = True
