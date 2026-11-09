"""Bounded trusted processes with owned descendant cleanup."""

import math
import os
import queue
import threading
import time

from .model import AepmError
from .supervision import observe


MESSAGE_BATCH = 64  # queued reader messages handled per loop iteration


def run(argv, cwd, environment, timeout, output_limit=8 * 1024 * 1024, *, stdout_only=False, diagnostics=None,
        adoption_root=None):
    started = time.monotonic()
    output, messages, stopped = bytearray(), queue.Queue(maxsize=32), threading.Event()
    process, code, reason, readers = None, None, "", []
    phase, cleaned = "startup", None

    def drain(stream, index):
        try:
            while not stopped.is_set():
                data = stream.read(65536)
                while not stopped.is_set():
                    try:
                        messages.put((index, data), timeout=0.05)
                        break
                    except queue.Full:
                        pass
                if not data:
                    break
        except (OSError, ValueError) as error:
            observe(diagnostics, "fault", "reader-join", error=error)

    try:
        if os.name == "nt":
            from .windows import ContainedProcess
            process = ContainedProcess(argv, cwd, environment)
        else:
            from .posix_process import ContainedProcess
            options = {key: value for key, value in (("diagnostics", diagnostics), ("adoption_root", adoption_root))
                       if value is not None}
            process = ContainedProcess(argv, cwd, environment, **options)
        for index, stream in enumerate((process.stdout, process.stderr)):
            reader = threading.Thread(target=drain, args=(stream, index), daemon=True)
            reader.start()
            readers.append(reader)
        ended, total = 0, 0
        while True:
            phase = "sample"
            if os.name != "nt":
                process.sample_private()
            phase = "limit"
            if time.monotonic() - started >= timeout:
                reason = "timeout"
                observe(diagnostics, "stopped", phase, "timeout")
                break
            batch = []
            try:
                batch.append(messages.get(timeout=0.02))
                while len(batch) < MESSAGE_BATCH:
                    batch.append(messages.get_nowait())
            except queue.Empty:
                pass
            for index, data in batch:
                if not data:
                    ended += 1
                elif total + len(data) > output_limit:
                    reason = "output-limit"
                    observe(diagnostics, "stopped", phase, "output-limit")
                    break
                else:
                    total += len(data)
                    if not stdout_only or index == 0:
                        output.extend(data)
            if reason == "output-limit":
                break
            phase = "exit-observation"
            code = process.poll() if os.name == "nt" else process.observe_exit()
            if code is not None:
                observe(diagnostics, "stopped", phase, "natural-exit", exit_code=code)
                phase = "group-cleanup"
                cleaned = process.terminate_tree()
                if not cleaned:
                    observe(diagnostics, "fault", phase, "cleanup-incomplete")
                    reason = "cleanup-failed"
                    break
                if ended == 2:
                    break
    except AepmError as error:
        observe(diagnostics, "stopped", phase, "startup-failure" if phase == "startup" else "exception", error)
        observe(diagnostics, "fault", phase, error=error)
        reason = error.code
    except OSError as error:
        observe(diagnostics, "stopped", phase, "startup-failure" if phase == "startup" else "exception", error)
        observe(diagnostics, "fault", phase, error=error)
        reason = "tool-unavailable"
    finally:
        if process is not None:
            try:
                phase = "group-cleanup"
                cleaned = process.terminate_tree()
                if not cleaned:
                    observe(diagnostics, "fault", phase, "cleanup-incomplete")
                    reason = "cleanup-failed"
                if os.name != "nt":
                    phase = "reap"
                    reaped = process.reap()
                    observe(diagnostics, "event", phase, "return", "succeeded" if reaped is not None else "unavailable")
                    if code is None:
                        code = reaped
            except (AepmError, OSError) as error:
                observe(diagnostics, "fault", phase, error=error)
                cleaned = False
                reason = "cleanup-failed"
        stopped.set()
        joined = True
        for reader in readers:
            observe(diagnostics, "event", "reader-join", "enter", "attempted")
            reader.join(timeout=1)
            if reader.is_alive():
                joined = False
                observe(diagnostics, "fault", "reader-join", "reader-incomplete")
                observe(diagnostics, "event", "reader-join", "return", "failed")
                reason = "cleanup-failed"
            else:
                observe(diagnostics, "event", "reader-join", "return", "succeeded")
        observe(diagnostics, "finish", code, reason, True if process is not None else None, cleaned,
                joined, getattr(process, "scope", None))
        if process is not None:
            process.close()
    return code, math.ceil(time.monotonic() - started), reason, bytes(output)
