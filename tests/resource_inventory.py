"""Read-only metadata counts for proposed native resource bounds."""

import json
import os
from pathlib import Path
import stat
import sys


def inventory(root):
    root = Path(root).resolve()
    counts = {"files": 0, "directories": 0, "executables": 0, "links": 0,
              "escapingLinks": 0, "hardlinkedFiles": 0, "bytes": 0, "maximumFileBytes": 0}
    escaping = []
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            path = Path(directory) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                counts["links"] += 1
                if not path.resolve().is_relative_to(root):
                    counts["escapingLinks"] += 1
                    escaping.append({"path": str(path.relative_to(root)), "target": str(path.resolve())})
            elif stat.S_ISDIR(info.st_mode):
                counts["directories"] += 1
            elif stat.S_ISREG(info.st_mode):
                counts["files"] += 1
                counts["executables"] += bool(info.st_mode & 0o111)
                counts["hardlinkedFiles"] += info.st_nlink != 1
                counts["bytes"] += info.st_size
                counts["maximumFileBytes"] = max(counts["maximumFileBytes"], info.st_size)
    return {"root": str(root), **counts, "escaping": escaping}


if __name__ == "__main__":
    print(json.dumps([inventory(path) for path in sys.argv[1:]], sort_keys=True))
