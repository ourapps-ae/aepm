import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from aepm.process import run


class ProcessTests(unittest.TestCase):
    def test_success_and_output_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run([sys.executable, "-c", "print('checked')"], directory, {"PATH": os.defpath}, 5)
            self.assertEqual(result[0], 0)
            self.assertEqual(result[2], "")
            self.assertIn(b"checked", result[3])
            result = run([sys.executable, "-c", "print('x' * 100000)"], directory, {"PATH": os.defpath}, 5, 1024)
            self.assertEqual(result[2], "output-limit")

    @unittest.skipIf(os.name == "nt", "Actual Windows fixture has separate containment assertions")
    def test_exited_parent_does_not_leave_grandchild_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "marker"
            child = "import time; from pathlib import Path; p=Path(" + repr(str(marker)) + ");\nwhile True: p.write_text(str(time.time())); time.sleep(.02)"
            parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c'," + repr(child) + "]); time.sleep(.15)"
            result = run([sys.executable, "-c", parent], directory, {"PATH": os.defpath}, 3)
            self.assertEqual(result[0], 0)
            value = marker.read_text()
            time.sleep(.15)
            self.assertEqual(marker.read_text(), value)

    def test_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run([sys.executable, "-c", "import time; time.sleep(30)"], directory, {"PATH": os.defpath}, .1)
            self.assertEqual(result[2], "timeout")

    @unittest.skipIf(os.name == "nt", "Windows Job Object containment has a separate actual-host check")
    @unittest.expectedFailure
    def test_timeout_must_stop_detached_descendant(self):
        """Known unsupported session escape, retained as failing boundary evidence."""
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "marker"
            child = ("import os,time; from pathlib import Path; "
                     f"p=Path({str(marker)!r}); deadline=time.monotonic()+3;\n"
                     "while time.monotonic()<deadline: p.write_text(str(time.monotonic())); time.sleep(.02)")
            parent = ("import subprocess,sys,time; "
                      f"subprocess.Popen([sys.executable,'-c',{child!r}],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(10)")
            try:
                result = run([sys.executable, "-c", parent], directory, {"PATH": os.defpath}, .5)
                self.assertEqual(result[2], "timeout")
                self.assertTrue(marker.exists())
                previous = marker.read_bytes()
                time.sleep(.15)
                self.assertEqual(marker.read_bytes(), previous, "Detached child survived the runner's timeout")
            finally:
                # The diagnostic child self-expires; never signal an unpinned identifier.
                time.sleep(3.1)

    def test_structured_probe_discards_stderr_but_still_bounds_it(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run([sys.executable, "-c", "import sys; print('{\"valid\":true}'); print('diagnostic',file=sys.stderr)"],
                         directory, {"PATH": os.defpath}, 5, stdout_only=True)
            self.assertEqual(result[3].strip(), b'{"valid":true}')
            result = run([sys.executable, "-c", "import sys; sys.stderr.write('x'*100000)"],
                         directory, {"PATH": os.defpath}, 5, 1024, stdout_only=True)
            self.assertEqual(result[2], "output-limit")
