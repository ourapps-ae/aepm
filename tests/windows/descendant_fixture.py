"""Actual-host child fixture; never substitute mocked containment results."""

import os
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import subprocess
import sys
import time


if sys.argv[1] == "child":
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
    times = [wintypes.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(kernel.GetCurrentProcess(), *(ctypes.byref(value) for value in times)):
        raise OSError("Process identity unavailable")
    created = times[0].dwLowDateTime | times[0].dwHighDateTime << 32
    pending = Path(sys.argv[2] + ".pending")
    pending.write_text(json.dumps({"pid": os.getpid(), "created": created}))
    pending.replace(sys.argv[2])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        time.sleep(1)
else:
    subprocess.Popen([sys.executable, __file__, "child", sys.argv[2]])
    release = Path(sys.argv[2] + ".release")
    deadline = time.monotonic() + 20
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(.01)
    if sys.argv[1] == "hang":
        time.sleep(60)
