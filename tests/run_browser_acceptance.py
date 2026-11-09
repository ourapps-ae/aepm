"""Run real browser interruption checks against an explicitly prepared private root."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import ctypes
import os
import re
from pathlib import Path
import shutil
import signal
import sys
import time
from unittest.mock import patch

from aepm.contextual import tool_environment, tool_versions
from aepm.io import immutable_blob, load, private_directory, write
from aepm.model import canonical, digest
from aepm.posix_process import DarwinProcessInfo, ExitObserver
from aepm.process import run
from aepm.private_process import PrivateScope


class Observer:
    def __init__(self):
        if sys.platform != 'darwin':
            raise RuntimeError('This actual identity observer is supported on macOS only')
        self.library = ExitObserver().proc
        self.library.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        self.library.proc_listpids.restype = ctypes.c_int
        self.library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.library.proc_pidpath.restype = ctypes.c_int

    def identity(self, pid):
        details = DarwinProcessInfo()
        if self.library.proc_pidinfo(pid, 3, 0, ctypes.byref(details), ctypes.sizeof(details)) != ctypes.sizeof(details):
            return None
        unique = ctypes.create_string_buffer(56)
        if self.library.proc_pidinfo(pid, 17, 0, unique, 56) != 56:
            return None
        identity = ctypes.c_uint64.from_buffer(unique, 16).value
        path = ctypes.create_string_buffer(4096)
        size = self.library.proc_pidpath(pid, path, len(path))
        return {'pid': pid, 'identity': identity, 'group': details.group, 'status': details.status,
                'executable': path.value.decode('utf-8') if size else None}

    def snapshot(self):
        capacity = 65536
        values = (ctypes.c_int * capacity)()
        length = self.library.proc_listpids(4, os.geteuid(), values, ctypes.sizeof(values))
        if length <= 0 or length >= ctypes.sizeof(values):
            raise RuntimeError('Incomplete process inventory')
        return {pid: value for pid in values[:length // ctypes.sizeof(ctypes.c_int)] if pid and (value := self.identity(pid))}

    def alive(self, expected):
        actual = self.identity(expected['pid'])
        return actual is not None and actual['identity'] == expected['identity'] and actual['status'] != 5


def check(root, source, evidence, *, trial_prefix='trial'):
    root, source, evidence = map(lambda path: Path(path).resolve(), (root, source, evidence))
    if evidence.exists():
        raise FileExistsError('Preserve earlier acceptance evidence')
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', trial_prefix):
        raise ValueError('Invalid private trial prefix')
    if not root.is_dir() or root.is_symlink() or root.stat().st_mode & 0o077:
        raise RuntimeError('Expected an existing ordinary private root')
    if not source.is_relative_to(root):
        raise RuntimeError('Package must be inside the private root')
    launcher = source / 'implementation/verification/browser-process.mjs'
    helper_bytes = Path(__file__).with_name('browser_acceptance.mjs').read_bytes()
    helper = root / 'acceptance-harness' / (digest(helper_bytes) + '.mjs')
    immutable_blob(helper, helper_bytes)
    environment = tool_environment(root / 'home', {'node': '26.5.0'}, [])
    environment['PLAYWRIGHT_BROWSERS_PATH'] = str(root / 'browser-cache')
    versions = tool_versions({'tools': {'node': '26.5.0'}}, source, environment)
    playwright_version = load(source / 'node_modules/playwright/package.json')['version']
    if playwright_version != '1.64.1':
        raise AssertionError('Unexpected Playwright version')
    node = shutil.which('node', path=environment['PATH'])
    observer = Observer()
    records = []
    metadata = {'format': 1, 'root': str(root), 'source': str(source), 'tools': versions,
                'playwrightVersion': playwright_version, 'launcherDigest': digest(launcher.read_bytes()),
                'fixtureDigest': digest(helper_bytes),
                'launcherCoreDigest': digest(launcher.with_name('browser-process-core.mjs').read_bytes()),
                'lockDigest': digest((source / 'package-lock.json').read_bytes())}
    for mode in ('normal', 'startup-failure', 'connection-failure', 'timeout', 'forced-exit'):
        trial = root / (trial_prefix + '-' + mode)
        if trial.exists():
            raise FileExistsError('Trial paths must be fresh')
        private_directory(trial / 'profiles/browser')
        before = observer.snapshot()
        owned = {}
        result = None
        outcome = {'mode': mode, 'profilesRemoved': False}
        def profile_state():
            directory = trial / 'profiles/browser'
            return {'rootExists': (trial / 'profiles').exists(),
                    'children': sorted(path.name for path in directory.iterdir()) if directory.is_dir() else []}
        audits = []
        original_close = PrivateScope.close

        def record_close(scope):
            try:
                if not scope.closed:
                    records = [{'pid': item.pid, 'identity': item.key, 'group': item.group,
                                'signals': list(item.signals_sent), 'exited': scope.backend.refresh(item) is None}
                               for item in scope.owned.values()]
                    audits.append({'group': scope.group, 'completed': scope.completed, 'records': records})
            finally:
                original_close(scope)

        with patch.object(PrivateScope, 'close', record_close), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(run, [node, str(helper), mode, str(launcher), str(trial)], source, environment,
                                 12 if mode == 'timeout' else 45)
            try:
                deadline = time.monotonic() + (10 if mode == 'timeout' else 35)
                while not (trial / 'ready.json').exists() and not future.done() and time.monotonic() < deadline:
                    time.sleep(.02)
                if not (trial / 'ready.json').exists():
                    raise AssertionError('Browser did not reach the identity handshake')
                ready = load(trial / 'ready.json')
                for _ in range(3):
                    current = observer.snapshot()
                    for pid, identity in current.items():
                        executable = identity['executable']
                        new = pid not in before or before[pid]['identity'] != identity['identity']
                        private_executable = executable is not None and Path(executable).resolve().is_relative_to(root)
                        if identity['group'] == ready['helper'] or pid in ready['browserIds'] or new and private_executable:
                            owned[(pid, identity['identity'])] = identity
                    time.sleep(.1)
                browser_records = [item for item in owned.values() if item['pid'] in ready['browserIds']]
                if not browser_records:
                    raise AssertionError('No live browser identity was observed')
                outcome['observed'] = list(owned.values())
                outcome['escapedGroups'] = [item for item in owned.values() if item['group'] != ready['helper']]
                (trial / 'release').write_text('captured')
                result = future.result(timeout=50)
                code, seconds, reason, output = result
                outcome.update(exitCode=code, seconds=seconds, reason=reason, outputDigest=digest(output))
                expected = (-signal.SIGKILL, 'timeout') if mode == 'timeout' else (23, '') if mode == 'forced-exit' else (0, '')
                deadline = time.monotonic() + 5
                while any(observer.alive(item) for item in owned.values()) and time.monotonic() < deadline:
                    time.sleep(.05)
                survivors = [item for item in owned.values() if observer.alive(item)]
                outcome['survivors'] = survivors
                outcome['supervisor'] = audits
                outcome['profileStateBeforeRemoval'] = profile_state()
                if (code, reason) != expected:
                    raise AssertionError('Unexpected runner outcome')
                matching = [audit for audit in audits if audit['group'] == ready['helper']]
                if survivors or len(matching) != 1 or not matching[0]['completed'] or not all(item['exited'] for item in matching[0]['records']):
                    raise AssertionError('Generation-bound supervision did not establish exact process exit')
                supervised = {(item['pid'], item['identity']) for item in matching[0]['records']}
                if any((item['pid'], item['identity']) not in supervised for item in outcome['escapedGroups']):
                    raise AssertionError('A separate-group identity was not enrolled by the supervisor')
                if not list((trial / 'profiles/browser').iterdir()):
                    raise AssertionError('Expected a fresh browser profile before parent cleanup')
                shutil.rmtree(trial / 'profiles')
                outcome['profilesRemoved'] = not (trial / 'profiles').exists()
                outcome['passed'] = outcome['profilesRemoved']
            except BaseException as error:
                outcome['passed'] = False
                outcome['failure'] = type(error).__name__
                (trial / 'release').write_text('stop waiting')
                if result is None:
                    try:
                        result = future.result(timeout=50)
                    except BaseException as failure:
                        outcome['runnerFailure'] = type(failure).__name__
                if result is not None:
                    outcome.update(exitCode=result[0], seconds=result[1], reason=result[2], outputDigest=digest(result[3]))
                    outcome['runnerOutput'] = result[3].decode('utf-8', errors='replace')[:4096]
                outcome['supervisor'] = audits
                outcome['survivors'] = [item for item in owned.values() if observer.alive(item)]
                outcome['profileStateBeforeRemoval'] = profile_state()
                records.append(outcome)
                write(evidence, {**metadata, 'cases': records})
                raise
        records.append(outcome)
    write(evidence, {**metadata, 'cases': records})
    return records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--trial-prefix', default='trial')
    arguments = parser.parse_args()
    print(canonical(check(arguments.root, arguments.source, arguments.evidence, trial_prefix=arguments.trial_prefix)).decode())
