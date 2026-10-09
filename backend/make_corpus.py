#!/usr/bin/env python3
"""
make_corpus.py — Generate a corpus of npm projects with REAL lockfiles for Hyron AI.

Each project pins a random mix of older, historically-vulnerable libraries so
transitive trees and overlapping CVEs are realistic.

IMPORTANT: The project corpus is generated. The lockfiles, dependency trees,
and CVE advisory data are real when retrieved live from npm and OSV.dev.

Usage:
  python -m backend.make_corpus 25        # generates corpus/app-01 … app-25
  python -m backend.make_corpus 5 --seed 42

Requires npm to be on PATH. Run BEFORE the pipeline.

Hyron AI · FUSION 2026 · CSB-03
"""

import argparse
import json
import random
import subprocess
from pathlib import Path

# Historically vulnerable npm packages (all are real published releases)
POOL = {
    "express":             "4.17.1",
    "lodash":              "4.17.15",
    "axios":               "0.21.1",
    "minimist":            "1.2.0",
    "moment":              "2.29.1",
    "jsonwebtoken":        "8.5.1",
    "node-fetch":          "2.6.0",
    "handlebars":          "4.7.6",
    "request":             "2.88.0",
    "ws":                  "7.2.0",
    "socket.io":           "2.3.0",
    "serialize-javascript":"2.1.0",
    "ejs":                 "3.0.1",
    "marked":              "0.7.0",
    "tar":                 "4.4.0",
    "js-yaml":             "3.13.0",
    "jquery":              "3.4.0",
    "validator":           "12.0.0",
    "passport":            "0.4.0",
    "mongoose":            "5.9.0",
    "sequelize":           "5.21.0",
    "webpack":             "4.41.0",
    "react-scripts":       "3.4.1",
    "bootstrap":           "3.3.7",
    "vue":                 "2.6.10",
    "next":                "10.0.0",
    "mocha":               "7.0.0",
    "winston":             "3.2.1",
}

# Packages with deep transitive trees (good for blast-radius demos)
BIG = ["react-scripts", "webpack", "next", "mongoose", "sequelize"]


def generate_project(out_dir: Path, name: str, deps: dict[str, str]) -> bool:
    """Write package.json and run npm install --package-lock-only."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "package.json").write_text(
        json.dumps(
            {"name": name, "version": "1.0.0", "dependencies": deps},
            indent=2,
        )
    )
    result = subprocess.run(
        [
            "npm", "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ],
        cwd=out_dir,
        capture_output=True,
        text=True,
    )
    ok = result.returncode == 0
    status = "ok" if ok else f"FAILED: {result.stderr[-300:]}"
    print(f"  {name}: {status}")
    return ok


def main(n: int, seed: int = 7, out: str = "corpus") -> None:
    random.seed(seed)
    out_path = Path(out)
    print(f"Generating {n} projects in ./{out}/ (seed={seed})")
    print("NOTE: corpus is generated; lockfiles and CVE data are real.\n")

    success = 0
    for i in range(1, n + 1):
        chosen = set(random.sample(list(POOL), random.randint(3, 6))) | {random.choice(BIG)}
        deps   = {k: POOL[k] for k in sorted(chosen)}
        name   = f"app-{i:02d}"
        ok = generate_project(out_path / name, name, deps)
        if ok:
            success += 1

    print(f"\n{success}/{n} projects generated successfully.")
    if success > 0:
        print(f"Run pipeline: python -m backend.main corpus/*/package-lock.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate sample npm corpus for Hyron AI")
    parser.add_argument("n", type=int, nargs="?", default=25, help="Number of projects to generate")
    parser.add_argument("--seed", type=int, default=7, help="Random seed (default: 7)")
    parser.add_argument("--out",  default="corpus", help="Output directory (default: corpus)")
    args = parser.parse_args()
    main(args.n, args.seed, args.out)
