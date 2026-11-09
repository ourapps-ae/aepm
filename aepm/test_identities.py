"""Generate three disposable identities and external policy for local proof."""

import argparse
import os
from pathlib import Path
import subprocess

from .io import fail, write


def generate(destination: Path):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        fail("identity-output-exists", "identities")
    destination.mkdir(mode=0o700)
    keys = {}
    script = """
const c = require('node:crypto');
const fs = require('node:fs');
const pair = c.generateKeyPairSync('ed25519');
fs.writeFileSync(process.argv[1], pair.privateKey.export({type:'pkcs8',format:'pem'}), {mode:0o600});
process.stdout.write(pair.publicKey.export({type:'spki',format:'pem'}));
"""
    for role in ("release", "guardian", "owner"):
        result = subprocess.run(["node", "-e", script, str(destination / (role + ".pem"))],
                                check=True, capture_output=True, env={"PATH": os.environ.get("PATH", os.defpath)})
        keys[role] = [{"id": "local-" + role, "publicKey": result.stdout.decode("ascii")}]
    policy = {"format": 1, "keys": keys, "trustedExecution": []}
    write(destination / "policy.json", policy)
    return destination / "policy.json"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    print(generate(parser.parse_args().destination))
