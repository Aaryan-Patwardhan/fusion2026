#!/usr/bin/env python3
"""
make_corpus.py — Sample npm Corpus Generator

What:
    Generates a reproducible corpus of npm projects with REAL lockfiles (using npm install --package-lock-only).
    Pins combinations of historically vulnerable package releases to produce deep transitive dependency graphs.
Why:
    Allows realistic demonstration of cross-project blast radius and OSV.dev matching.
    NOTE: The projects and combination of pins are synthetic; the lockfiles, transitive trees,
    and OSV.dev advisory records are completely genuine.
Inputs:
    n (int): Number of projects to create (default: 25).
    --seed (int): Random seed for reproducible generation (default: 7).
    --out (str): Destination directory (default: "corpus").
Outputs:
    Directory tree containing <out>/app-XX/package.json and package-lock.json.
Called by:
    scripts/demo.fish, developer setup
"""

import argparse
import json
import random
import shutil
import subprocess
import sys
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
    """Create a package.json and generate a real package-lock.json without downloading binaries."""
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
    """Generate N sample npm projects with real lockfiles using the pinned dependency pool."""
    if not shutil.which("npm"):
        print(
            "Error: 'npm' command not found on PATH.\n"
            "make_corpus requires npm to generate genuine package-lock.json files.\n"
            "Please install Node.js/npm or use the pre-generated sample corpus.",
            file=sys.stderr,
        )
        sys.exit(1)

    random.seed(seed)
    out_path = Path(out)
    print(f"Generating {n} projects in ./{out}/ (seed={seed})")
    print("NOTE: project corpus is generated; lockfiles and CVE data are real.\n")

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
        print(f"Run pipeline: python -m backend.main {out}/*/package-lock.json")


def _parse_cli():
    """Parse CLI arguments with examples."""
    parser = argparse.ArgumentParser(
        prog="python -m backend.make_corpus",
        description="Hyron AI — Sample npm Project Corpus Generator (FUSION 2026 · CSB-03)",
        epilog=(
            "Examples:\n"
            "  python -m backend.make_corpus 25\n"
            "  python -m backend.make_corpus 5 --seed 42 --out demo_corpus\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("n", type=int, nargs="?", default=25, help="Number of projects to generate (default: 25)")
    parser.add_argument("--seed", type=int, default=7, help="Random seed (default: 7)")
    parser.add_argument("--out",  default="corpus", help="Output directory path (default: corpus)")
    return parser.parse_args()


if __name__ == "__main__":
    cli_args = _parse_cli()
    main(cli_args.n, cli_args.seed, cli_args.out)
