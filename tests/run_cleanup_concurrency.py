"""One bounded owned-process diagnostic; production policy is unchanged."""

import argparse
from concurrent.futures import Future
import ctypes
import os
from pathlib import Path
import sys
import threading
import time
from unittest.mock import patch

from aepm.contextual import tool_environment
from aepm.io import VerificationDirectory, load, private_directory, write
from aepm.model import canonical, digest
from aepm.posix_process import ContainedProcess
from aepm.private_process import DarwinBackend, PrivateScope
from aepm.process import run


CHILD = """import json,os,time
from pathlib import Path
root=Path.cwd()
pending=root/'ready.pending'
pending.write_text(json.dumps({'pid':os.getpid(),'readyMonotonic':time.monotonic()}))
pending.replace(root/'ready.json')
deadline=time.monotonic()+20
while not (root/'release').exists() and time.monotonic()<deadline:
 time.sleep(.01)
print('owned fixture completed')
"""


class Trace:
    def __init__(self, roots):
        self.roots = {str(root): label for label, root in roots.items()}
        self.started = time.monotonic()
        self.events = []
        self.identities = {}
        self.backend_owners = {}
        self.lock = threading.Lock()
        self.truncated = False

    def add(self, event, **values):
        with self.lock:
            if len(self.events) >= 2000:
                self.truncated = True
                return
            self.events.append({'at': round(time.monotonic() - self.started, 6), 'event': event, **values})

    def scope_label(self, scope):
        return self.roots.get(str(scope.root))

    def install(self):
        original_bind, original_capture = PrivateScope.bind, PrivateScope._capture
        original_scan, original_finish = PrivateScope.scan, PrivateScope.finish
        original_exit, original_reap = ContainedProcess.observe_exit, ContainedProcess.reap
        original_refresh = DarwinBackend.refresh
        last_exits = {}

        def bind(scope, group):
            label = self.scope_label(scope)
            if label:
                self.backend_owners[id(scope.backend)] = label
                self.add('bind', scope=label, group=group)
            return original_bind(scope, group)

        def capture(scope, pid):
            result = original_capture(scope, pid)
            error = ctypes.get_errno()
            expected = self.identities.get(pid)
            label = self.scope_label(scope)
            if label and expected:
                self.add('capture', scope=label, target=expected['label'], pid=pid,
                         result='none' if result is None else 'same-identity' if result.key == expected['identity'] else 'different-identity',
                         error=error if result is None else None)
            return result

        def scan(scope, *args, **kwargs):
            label, before = self.scope_label(scope), scope.next_scan
            try:
                return original_scan(scope, *args, **kwargs)
            finally:
                if label and (before != scope.next_scan or kwargs.get('force')):
                    self.add('scan', scope=label, rootExited=scope.root_exited, unresolved=scope.unresolved,
                             failed=scope.failed, ownedRecords=len(scope.owned))

        def finish(scope, deadline):
            label = self.scope_label(scope)
            if label:
                self.add('cleanup-enter', scope=label, remaining=round(deadline - time.monotonic(), 6))
            try:
                result = original_finish(scope, deadline)
                if label:
                    self.add('cleanup-return', scope=label, result=result, completed=scope.completed, failed=scope.failed)
                return result
            except BaseException as error:
                if label:
                    self.add('cleanup-exception', scope=label, exception=type(error).__name__, code=getattr(error, 'code', None))
                raise

        def observe(process):
            result = original_exit(process)
            label = self.scope_label(process.scope) if process.scope else None
            if label and result is not None and last_exits.get(label) != result:
                last_exits[label] = result
                self.add('root-exit-observed', scope=label, pid=process.pid, exitCode=result, reaped=process.reaped)
            return result

        def reap(process):
            label = self.scope_label(process.scope) if process.scope else None
            if label:
                self.add('reap-enter', scope=label, pid=process.pid, signalingFinished=process.signaling_finished)
            result = original_reap(process)
            if label:
                self.add('reap-return', scope=label, pid=process.pid, exitCode=result, reaped=process.reaped)
            return result

        def refresh(backend, record):
            result = original_refresh(backend, record)
            expected = self.identities.get(record.pid)
            label = self.backend_owners.get(id(backend))
            if label and expected and record.key == expected['identity']:
                self.add('owned-refresh', scope=label, target=expected['label'], pid=record.pid, exited=result is None)
            return result

        return [patch.object(PrivateScope, 'bind', bind), patch.object(PrivateScope, '_capture', capture),
                patch.object(PrivateScope, 'scan', scan), patch.object(PrivateScope, 'finish', finish),
                patch.object(ContainedProcess, 'observe_exit', observe), patch.object(ContainedProcess, 'reap', reap),
                patch.object(DarwinBackend, 'refresh', refresh)]


def case(out, mode, overall_deadline):
    from contextlib import ExitStack
    case_started = time.monotonic()
    deadline = min(overall_deadline, case_started + 40)
    count = 1 if mode == 'isolated' else 2
    directory = private_directory(out / mode)
    workspaces = {label: VerificationDirectory(prefix='cleanup-' + mode + '-' + label + '-') for label in ('A', 'B')[:count]}
    for workspace in workspaces.values():
        workspace.preserve = True
    roots = {label: workspace.path for label, workspace in workspaces.items()}
    environments = {label: tool_environment(root / 'home', {}, []) for label, root in roots.items()}
    trace = Trace(roots)
    results, failure = {}, None
    backend = DarwinBackend()

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError('diagnostic case limit')
        return value

    def release(label):
        (roots[label] / 'release').write_text('released')
        trace.add('release', scope=label)

    def collect(label, future):
        code, seconds, reason, output = future.result(timeout=remaining())
        results[label] = {'exitCode': code, 'seconds': seconds, 'reason': reason, 'outputDigest': digest(output)}
        (directory / (label + '.log')).write_bytes(output)
        trace.add('run-return', scope=label, **results[label])

    with ExitStack() as stack:
        for observer in trace.install():
            stack.enter_context(observer)
        futures = {label: Future() for label in roots}
        def worker(label):
            try:
                value = run([sys.executable, '-I', '-S', '-c', CHILD], roots[label], environments[label], 20)
                futures[label].set_result(value)
            except BaseException as error:
                futures[label].set_exception(error)
        workers = [threading.Thread(target=worker, args=(label,), daemon=True) for label in roots]
        for thread in workers:
            thread.start()
        try:
            try:
                for label, root in roots.items():
                    while not (root / 'ready.json').exists():
                        remaining()
                        if futures[label].done():
                            collect(label, futures[label])
                            raise RuntimeError('fixture ended before readiness')
                        time.sleep(.01)
                    ready = load(root / 'ready.json')
                    identity = backend.capture(ready['pid'], paths=False)
                    if identity is None:
                        raise RuntimeError('controlled identity unavailable')
                    record = {'label': label, 'pid': identity.pid, 'identity': identity.key,
                              'generation': identity.generation, 'group': identity.group}
                    trace.identities[identity.pid] = record
                    trace.add('ready', **record, childReady=ready['readyMonotonic'] - trace.started)
                if mode == 'staggered':
                    release('A')
                    collect('A', futures['A'])
                    release('B')
                    collect('B', futures['B'])
                else:
                    for label in roots:
                        release(label)
                    for label in roots:
                        collect(label, futures[label])
            except BaseException as error:
                failure = {'type': type(error).__name__, 'code': getattr(error, 'code', None)}
                trace.add('controller-failure', **failure)
            finally:
                for label, root in roots.items():
                    if not (root / 'release').exists():
                        release(label)
                for label, future in futures.items():
                    if label not in results:
                        try:
                            collect(label, future)
                        except BaseException as error:
                            trace.add('join-failure', scope=label, exception=type(error).__name__)
                            failure = failure or {'type': type(error).__name__, 'code': getattr(error, 'code', None)}
        finally:
            for thread in workers:
                thread.join(timeout=max(0, deadline - time.monotonic()))
    workers_complete = all(not thread.is_alive() for thread in workers)
    document = {'format': 1, 'kind': 'controlled-process-diagnostic', 'mode': mode, 'completeProof': False,
                'seconds': round(time.monotonic() - case_started, 6), 'results': results,
                'identities': list(trace.identities.values()), 'events': trace.events,
                'roots': {label: str(root) for label, root in roots.items()}, 'workersComplete': workers_complete,
                'traceTruncated': trace.truncated, 'failure': failure}
    write(directory / 'trace.json', document)
    return document


def diagnostic(out):
    if sys.platform != 'darwin':
        raise RuntimeError('This released diagnostic targets the observed macOS failure')
    out = Path(out).resolve()
    if out.exists() or not out.parent.is_dir():
        raise FileExistsError('Use a fresh private output')
    out.mkdir(mode=0o700)
    source = Path(__file__).resolve().parents[1] / 'aepm'
    hashes = {name: digest((source / name).read_bytes()) for name in ('process.py', 'posix_process.py', 'private_process.py')}
    started = time.monotonic()
    write(out / 'state.json', {'phase': 'running', 'completeProof': False, 'sourceHashes': hashes})
    documents = []
    for mode in ('isolated', 'staggered', 'synchronized'):
        if time.monotonic() >= started + 120:
            raise TimeoutError('diagnostic total limit')
        documents.append(case(out, mode, started + 120))
        if not documents[-1]['workersComplete']:
            break
    after = {name: digest((source / name).read_bytes()) for name in hashes}
    summary = {'format': 1, 'completeProof': False, 'sourceHashes': hashes, 'sourceUnchanged': hashes == after,
               'diagnosticDigest': digest(Path(__file__).read_bytes()),
               'seconds': round(time.monotonic() - started, 6),
               'cases': [{'mode': item['mode'], 'results': item['results'], 'workersComplete': item['workersComplete'],
                          'traceTruncated': item['traceTruncated'], 'failure': item['failure']} for item in documents]}
    write(out / 'summary.json', summary)
    write(out / 'state.json', {'phase': 'finished', 'completeProof': False, 'sourceUnchanged': hashes == after})
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    arguments = parser.parse_args()
    print(canonical(diagnostic(arguments.out)).decode())
