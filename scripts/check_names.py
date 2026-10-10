#!/usr/bin/env python3
"""Check whether candidate names are free on PyPI, Homebrew and the local PATH.

Usage: python3 scripts/check_names.py [name ...]
"""

import re
import shutil
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

DEFAULT = [
    "cleanroom",
    "clean-room",
    "cleanre",
    "cleanrev",
    "crev",
    "reclean",
    "rekiss",
    "kissre",
    "dryre",
    "realite",
    "rea-lite",
    "pyrea",
    "reapy",
    "sage-re",
    "sagere",
]


def normalize(name):
    """PEP 503 form: PyPI treats runs of - _ . as one hyphen, case-insensitively."""
    return re.sub(r"[-_.]+", "-", name).lower()


def exists(url):
    """True if the URL answers, False on 404, None if the check itself failed."""
    req = urllib.request.Request(
        url, method="HEAD", headers={"User-Agent": "cleanroom-name-check"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            return True
    except urllib.error.HTTPError as e:
        return False if e.code == 404 else None
    except OSError:
        return None


def check(name):
    n = normalize(name)
    bare = n.replace("-", "")
    return {
        "name": name,
        "pypi": exists(f"https://pypi.org/pypi/{n}/json"),
        # PyPI also refuses names that differ only by separators.
        "pypi bare": exists(f"https://pypi.org/pypi/{bare}/json") if bare != n else False,
        "brew formula": exists(f"https://formulae.brew.sh/api/formula/{n}.json"),
        "brew cask": exists(f"https://formulae.brew.sh/api/cask/{n}.json"),
        "on PATH": shutil.which(name) is not None,
    }


def main():
    names = sys.argv[1:] or DEFAULT
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(check, names))
    cols = ["pypi", "pypi bare", "brew formula", "brew cask", "on PATH"]
    label = {True: "TAKEN", False: "free", None: "error"}
    width = max(len(n) for n in names) + 2
    print("name".ljust(width) + "".join(c.ljust(14) for c in cols))
    for r in rows:
        print(r["name"].ljust(width) + "".join(label[r[c]].ljust(14) for c in cols))
    free = [
        r["name"] for r in rows if not any(r[c] for c in cols) and None not in (r[c] for c in cols)
    ]
    print("\nFree everywhere:", ", ".join(free) or "none")
    print(
        "Caveat: PyPI also rejects names confusable with existing ones (o/0, l/1);"
        " only an upload confirms. Homebrew aliases and third-party taps are not checked."
    )


if __name__ == "__main__":
    main()
