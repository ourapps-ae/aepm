"""Windows verification containment and private evidence files."""

import ctypes as c
from ctypes import wintypes as w
import os
from pathlib import Path
import subprocess
import time

from .io import fail


class SecurityAttributes(c.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]


class Startup(c.Structure):
    _fields_ = [("cb", w.DWORD), ("reserved", w.LPWSTR), ("desktop", w.LPWSTR), ("title", w.LPWSTR),
                ("x", w.DWORD), ("y", w.DWORD), ("xsize", w.DWORD), ("ysize", w.DWORD),
                ("xchars", w.DWORD), ("ychars", w.DWORD), ("fill", w.DWORD), ("flags", w.DWORD),
                ("show", w.WORD), ("reserved_size", w.WORD), ("reserved_data", c.c_void_p),
                ("stdin", w.HANDLE), ("stdout", w.HANDLE), ("stderr", w.HANDLE)]


class StartupEx(c.Structure):
    _fields_ = [("startup", Startup), ("attributes", c.c_void_p)]


class ProcessInfo(c.Structure):
    _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]


class BasicLimits(c.Structure):
    _fields_ = [("process_time", c.c_int64), ("job_time", c.c_int64), ("flags", w.DWORD),
                ("minimum", c.c_size_t), ("maximum", c.c_size_t), ("active", w.DWORD),
                ("affinity", c.c_size_t), ("priority", w.DWORD), ("scheduling", w.DWORD)]


class ExtendedLimits(c.Structure):
    _fields_ = [("basic", BasicLimits), ("io", c.c_uint64 * 6),
                ("process_memory", c.c_size_t), ("job_memory", c.c_size_t),
                ("peak_process", c.c_size_t), ("peak_job", c.c_size_t)]


class Accounting(c.Structure):
    _fields_ = [("times", c.c_int64 * 4), ("faults", w.DWORD), ("total", w.DWORD),
                ("active", w.DWORD), ("terminated", w.DWORD)]


def api():
    if os.name != "nt":
        fail("unsupported-host", "windows")
    kernel = c.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateJobObjectW": ([c.c_void_p, w.LPCWSTR], w.HANDLE),
        "SetInformationJobObject": ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD], w.BOOL),
        "AssignProcessToJobObject": ([w.HANDLE, w.HANDLE], w.BOOL),
        "QueryInformationJobObject": ([w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p], w.BOOL),
        "TerminateJobObject": ([w.HANDLE, w.UINT], w.BOOL),
        "TerminateProcess": ([w.HANDLE, w.UINT], w.BOOL),
        "CloseHandle": ([w.HANDLE], w.BOOL),
        "CreatePipe": ([c.POINTER(w.HANDLE), c.POINTER(w.HANDLE), c.POINTER(SecurityAttributes), w.DWORD], w.BOOL),
        "SetHandleInformation": ([w.HANDLE, w.DWORD, w.DWORD], w.BOOL),
        "CreateFileW": ([w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE),
        "InitializeProcThreadAttributeList": ([c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_size_t)], w.BOOL),
        "UpdateProcThreadAttribute": ([c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p, c.c_size_t, c.c_void_p, c.c_void_p], w.BOOL),
        "DeleteProcThreadAttributeList": ([c.c_void_p], None),
        "CreateProcessW": ([w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD,
                             c.c_void_p, w.LPCWSTR, c.POINTER(StartupEx), c.POINTER(ProcessInfo)], w.BOOL),
        "ResumeThread": ([w.HANDLE], w.DWORD),
        "GetExitCodeProcess": ([w.HANDLE, c.POINTER(w.DWORD)], w.BOOL),
        "GetCurrentProcess": ([], w.HANDLE),
        "GetWindowsDirectoryW": ([w.LPWSTR, w.UINT], w.UINT),
        "GetSystemDirectoryW": ([w.LPWSTR, w.UINT], w.UINT),
        "LocalFree": ([c.c_void_p], c.c_void_p),
        "FlushFileBuffers": ([w.HANDLE], w.BOOL),
        "MoveFileExW": ([w.LPCWSTR, w.LPCWSTR, w.DWORD], w.BOOL),
        "GetVolumePathNameW": ([w.LPCWSTR, w.LPWSTR, w.DWORD], w.BOOL),
        "GetVolumeInformationW": ([w.LPCWSTR, w.LPWSTR, w.DWORD, c.c_void_p, c.c_void_p,
                                    c.c_void_p, w.LPWSTR, w.DWORD], w.BOOL),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(kernel, name)
        function.argtypes, function.restype = arguments, result
    return kernel


def system_paths():
    kernel = api()
    windows, system = c.create_unicode_buffer(32768), c.create_unicode_buffer(32768)
    if not 0 < kernel.GetWindowsDirectoryW(windows, len(windows)) < len(windows):
        fail("windows-containment-unavailable", "system-directory")
    if not 0 < kernel.GetSystemDirectoryW(system, len(system)) < len(system):
        fail("windows-containment-unavailable", "system-directory")
    root, directory = Path(windows.value), Path(system.value)
    if not root.is_dir() or not directory.is_dir() or not directory.resolve().is_relative_to(root.resolve()) or not (directory / "cmd.exe").is_file():
        fail("windows-containment-unavailable", "system-directory")
    return root, directory


def protect(path):
    kernel = api()
    loader = getattr(c, "WinDLL", None)
    if not callable(loader):
        fail("unsupported-host", "windows")
    security = loader("advapi32", use_last_error=True)
    if not isinstance(security, c.CDLL):
        fail("unsupported-host", "windows")
    security.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    security.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    security.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p]
    security.SetFileSecurityW.argtypes = [w.LPCWSTR, w.DWORD, c.c_void_p]
    token, sid_text, descriptor = w.HANDLE(), w.LPWSTR(), c.c_void_p()
    try:
        if not security.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token)):
            fail("private-permissions", "windows")
        length = w.DWORD()
        security.GetTokenInformation(token, 1, None, 0, c.byref(length))
        data = c.create_string_buffer(length.value)
        if not security.GetTokenInformation(token, 1, data, length, c.byref(length)):
            fail("private-permissions", "windows")
        sid = c.cast(data, c.POINTER(c.c_void_p))[0]
        if not security.ConvertSidToStringSidW(sid, c.byref(sid_text)):
            fail("private-permissions", "windows")
        rules = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid_text.value})"
        if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(rules, 1, c.byref(descriptor), None):
            fail("private-permissions", "windows")
        if not security.SetFileSecurityW(str(path), 0x80000004, descriptor):
            fail("private-permissions", "windows")
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if sid_text:
            kernel.LocalFree(c.cast(sid_text, c.c_void_p))
        if token:
            kernel.CloseHandle(token)


def ntfs(path):
    kernel = api()
    volume, filesystem = c.create_unicode_buffer(32768), c.create_unicode_buffer(32)
    if not kernel.GetVolumePathNameW(str(Path(path).absolute()), volume, len(volume)):
        fail("unsupported-filesystem", "execution-state")
    if not kernel.GetVolumeInformationW(volume, None, 0, None, None, None, filesystem, len(filesystem)) or filesystem.value != "NTFS":
        fail("unsupported-filesystem", "execution-state")


def exclusive_bytes(path, data):
    import msvcrt
    kernel = api()
    opener = getattr(msvcrt, "open_osfhandle", None)
    getter = getattr(msvcrt, "get_osfhandle", None)
    if not callable(opener) or not callable(getter):
        fail("unsupported-host", "windows")
    ntfs(Path(path).parent)
    handle = kernel.CreateFileW(str(path), 0x40000000, 0, None, 1, 0x80000000, None)
    if handle == c.c_void_p(-1).value:
        fail("execution-replayed", "execution-state")
    try:
        descriptor = opener(handle, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    except OSError:
        kernel.CloseHandle(handle)
        fail("evidence-publication", "execution-state")
    if type(descriptor) is not int or descriptor < 0:
        kernel.CloseHandle(handle)
        fail("evidence-publication", "execution-state")
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        if not kernel.FlushFileBuffers(getter(stream.fileno())):
            fail("evidence-publication", "execution-state")
    protect(path)


def publish(source, destination, replace=False):
    ntfs(Path(destination).parent)
    if not api().MoveFileExW(str(source), str(destination), 8 | int(replace)):
        fail("evidence-publication", "evidence")


class OwnedPipe:
    """Retain descriptor ownership while constructing the Python stream."""

    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.stream = os.fdopen(descriptor, "rb", buffering=0, closefd=False)

    def read(self, size):
        return self.stream.read(size)

    def close(self):
        if self.descriptor is None:
            return
        descriptor, self.descriptor = self.descriptor, None
        try:
            self.stream.close()
        finally:
            os.close(descriptor)


class ContainedProcess:
    def __init__(self, argv, cwd, environment):
        import msvcrt
        self.kernel = kernel = api()
        self.job = kernel.CreateJobObjectW(None, None)
        self.process = None
        self.stdout = self.stderr = None
        limits = ExtendedLimits()
        limits.basic.flags = 0x2000
        handles, attributes, info = [], None, ProcessInfo()
        attributes_initialized = False
        try:
            if not self.job or not kernel.SetInformationJobObject(self.job, 9, c.byref(limits), c.sizeof(limits)):
                fail("windows-containment-unavailable", "process")
            security = SecurityAttributes(c.sizeof(SecurityAttributes), None, True)
            pipes = []
            for _ in range(2):
                read, write = w.HANDLE(), w.HANDLE()
                if not kernel.CreatePipe(c.byref(read), c.byref(write), c.byref(security), 0):
                    fail("windows-containment-unavailable", "process")
                handles.extend((read.value, write.value))
                if not kernel.SetHandleInformation(read, 1, 0):
                    fail("windows-containment-unavailable", "process")
                pipes.append((read.value, write.value))
            stdin = kernel.CreateFileW("NUL", 0x80000000, 3, c.byref(security), 3, 0x80, None)
            if stdin in (None, c.c_void_p(-1).value):
                fail("windows-containment-unavailable", "process")
            handles.append(stdin)
            size = c.c_size_t()
            kernel.InitializeProcThreadAttributeList(None, 1, 0, c.byref(size))
            if not size.value:
                fail("windows-containment-unavailable", "process")
            attributes = c.create_string_buffer(size.value)
            if not kernel.InitializeProcThreadAttributeList(attributes, 1, 0, c.byref(size)):
                fail("windows-containment-unavailable", "process")
            attributes_initialized = True
            inherited = (w.HANDLE * 3)(stdin, pipes[0][1], pipes[1][1])
            if not kernel.UpdateProcThreadAttribute(attributes, 0, 0x20002, inherited, c.sizeof(inherited), None, None):
                fail("windows-containment-unavailable", "process")
            startup = StartupEx()
            startup.startup.cb, startup.startup.flags = c.sizeof(startup), 0x100
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = inherited
            startup.attributes = c.cast(attributes, c.c_void_p)
            block = c.create_unicode_buffer("\0".join(f"{key}={value}" for key, value in sorted(environment.items())) + "\0\0")
            command = c.create_unicode_buffer(subprocess.list2cmdline(argv))
            if not kernel.CreateProcessW(argv[0], command, None, None, True, 4 | 0x400 | 0x80000,
                                         block, str(cwd), c.byref(startup), c.byref(info)):
                fail("tool-unavailable", "process")
            self.process, self.pid = info.process, info.pid
            if not kernel.AssignProcessToJobObject(self.job, self.process):
                kernel.TerminateProcess(self.process, 1)
                fail("windows-containment-unavailable", "process")
            opener = getattr(msvcrt, "open_osfhandle", None)
            if not callable(opener):
                fail("windows-containment-unavailable", "process")
            for name, (read, _) in zip(("stdout", "stderr"), pipes):
                try:
                    descriptor = opener(read, os.O_RDONLY | getattr(os, "O_BINARY", 0))
                except OSError:
                    fail("windows-containment-unavailable", "process")
                if type(descriptor) is not int or descriptor < 0:
                    fail("windows-containment-unavailable", "process")
                # The descriptor owns this handle after successful transfer.
                handles.remove(read)
                try:
                    stream = OwnedPipe(descriptor)
                except BaseException as error:
                    os.close(descriptor)
                    if isinstance(error, OSError):
                        fail("windows-containment-unavailable", "process")
                    raise
                setattr(self, name, stream)
            if kernel.ResumeThread(info.thread) == 0xFFFFFFFF:
                fail("windows-containment-unavailable", "process")
        except BaseException:
            self.close()
            raise
        finally:
            if info.thread:
                kernel.CloseHandle(info.thread)
            if attributes_initialized:
                kernel.DeleteProcThreadAttributeList(attributes)
            for handle in handles:
                kernel.CloseHandle(handle)

    def poll(self):
        code = w.DWORD()
        if not self.kernel.GetExitCodeProcess(self.process, c.byref(code)):
            fail("process-failed", "process")
        return None if code.value == 259 else code.value

    def terminate_tree(self):
        if not self.job:
            return True
        self.kernel.TerminateJobObject(self.job, 1)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            data = Accounting()
            if not self.kernel.QueryInformationJobObject(self.job, 1, c.byref(data), c.sizeof(data), None):
                return False
            if data.active == 0:
                return True
            time.sleep(0.01)
        return False

    def close(self):
        if getattr(self, "job", None):
            self.terminate_tree()
            self.kernel.CloseHandle(self.job)
            self.job = None
        if getattr(self, "process", None):
            self.kernel.CloseHandle(self.process)
            self.process = None
        for stream in (self.stdout, self.stderr):
            if stream:
                stream.close()
        self.stdout = self.stderr = None
