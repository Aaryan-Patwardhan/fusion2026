#!/usr/bin/env python3
"""
daemon.py — Background watcher for Hyron AI.

Watches lockfile directories for changes (file system events) and also polls
on a configurable schedule. When a change is detected:
  1. Runs the full scan pipeline.
  2. Compares the new state with the last scan.
  3. Emits an incident event if new high-risk findings appear.

Uses the `watchdog` library for cross-platform file system events.

Usage:
  python -m backend.daemon --corpus corpus --interval 300

Hyron AI · FUSION 2026 · CSB-03
"""

import argparse
import glob
import json
import logging
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent
from watchdog.observers import Observer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("hyron-daemon")

FINDINGS_FILE = Path("findings.json")
LAST_STATE    = Path(".last_scan_state.json")


def _current_findings() -> dict[str, float]:
    """Load the last findings.json and return {(project, package, vuln): risk}."""
    if not FINDINGS_FILE.exists():
        return {}
    rows = json.loads(FINDINGS_FILE.read_text())
    return {f"{r['project']}|{r['package']}|{r['vuln']}": r["risk"] for r in rows}


def _save_state(state: dict) -> None:
    LAST_STATE.write_text(json.dumps(state))


def _load_state() -> dict[str, float]:
    if LAST_STATE.exists():
        return json.loads(LAST_STATE.read_text())
    return {}


def run_scan(lockfile_paths: list[str]) -> tuple[dict, list[dict]]:
    """Run the full pipeline and return (new_state, rows)."""
    from backend.main import run_pipeline
    _, rows = run_pipeline(lockfile_paths)
    new_state = {f"{r['project']}|{r['package']}|{r['vuln']}": r["risk"] for r in rows}
    return new_state, rows


def diff_state(old: dict[str, float], new: dict[str, float]) -> dict:
    """
    Compare two scan states.
    Returns a dict with:
      new_findings: list of new (key, risk) tuples not in old state
      resolved:     list of keys in old but not in new (package removed/fixed)
      risk_changes: list of (key, old_risk, new_risk) where risk changed
    """
    new_findings  = [(k, v) for k, v in new.items() if k not in old]
    resolved      = [k for k in old if k not in new]
    risk_changes  = [
        (k, old[k], new[k]) for k in new
        if k in old and abs(old[k] - new[k]) > 1.0
    ]
    return {
        "new_findings": new_findings,
        "resolved":     resolved,
        "risk_changes": risk_changes,
    }


def emit_incident(diff: dict, rows: list[dict]) -> None:
    """Log an incident summary when meaningful changes are detected."""
    if not any(diff.values()):
        log.info("Scan complete — no new findings or changes.")
        return

    if diff["new_findings"]:
        log.warning(f"NEW FINDINGS: {len(diff['new_findings'])} new vulnerability/project pairs")
        for key, risk in sorted(diff["new_findings"], key=lambda x: -x[1])[:5]:
            proj, pkg, vuln = key.split("|")
            log.warning(f"  RISK {risk:5.1f}  {proj:18}  {pkg:30}  {vuln}")

    if diff["resolved"]:
        log.info(f"RESOLVED: {len(diff['resolved'])} findings resolved (package fixed or removed)")

    if diff["risk_changes"]:
        log.info(f"RISK CHANGES: {len(diff['risk_changes'])} findings changed risk score")


class LockfileHandler(FileSystemEventHandler):
    """Watch for package-lock.json changes and trigger a scan."""

    def __init__(self, lockfile_pattern: str, cooldown: float = 5.0):
        self.lockfile_pattern = lockfile_pattern
        self.cooldown = cooldown
        self._last_scan: float = 0.0

    def _should_scan(self, src_path: str) -> bool:
        return (
            "package-lock.json" in src_path
            and time.time() - self._last_scan > self.cooldown
        )

    def on_modified(self, event: FileModifiedEvent):
        if not event.is_directory and self._should_scan(event.src_path):
            log.info(f"Detected change: {event.src_path}")
            self._trigger()

    def on_created(self, event: FileCreatedEvent):
        if not event.is_directory and self._should_scan(event.src_path):
            log.info(f"New lockfile: {event.src_path}")
            self._trigger()

    def _trigger(self):
        self._last_scan = time.time()
        paths = glob.glob(self.lockfile_pattern, recursive=True)
        if not paths:
            log.warning(f"No lockfiles found matching: {self.lockfile_pattern}")
            return
        try:
            old_state = _load_state()
            new_state, rows = run_scan(paths)
            diff = diff_state(old_state, new_state)
            emit_incident(diff, rows)
            _save_state(new_state)
        except Exception as e:
            log.error(f"Scan failed: {e}")


def run_daemon(corpus_dir: str, interval: int) -> None:
    """
    Start the background daemon:
      - Runs an immediate scan on startup.
      - Watches the corpus directory for lockfile changes.
      - Polls on a `interval`-second schedule for advisory changes.
    """
    pattern = f"{corpus_dir}/**/package-lock.json"
    paths   = glob.glob(pattern, recursive=True)

    log.info(f"Hyron AI daemon starting — watching {corpus_dir}, interval={interval}s")
    log.info(f"Found {len(paths)} lockfiles on startup")

    # Initial scan
    if paths:
        old_state = _load_state()
        try:
            new_state, rows = run_scan(paths)
            diff = diff_state(old_state, new_state)
            emit_incident(diff, rows)
            _save_state(new_state)
        except Exception as e:
            log.error(f"Initial scan failed: {e}")
    else:
        log.warning(f"No lockfiles found in {corpus_dir}. Generate with: python -m backend.make_corpus")

    # File-system watcher
    handler  = LockfileHandler(pattern)
    observer = Observer()
    observer.schedule(handler, path=corpus_dir, recursive=True)
    observer.start()
    log.info("Filesystem watcher active.")

    # Polling loop (catches advisory-only changes when files haven't changed)
    try:
        while True:
            time.sleep(interval)
            if not paths:
                paths = glob.glob(pattern, recursive=True)
                continue
            log.info(f"Scheduled scan ({interval}s interval)…")
            old_state = _load_state()
            try:
                new_state, rows = run_scan(paths)
                diff = diff_state(old_state, new_state)
                emit_incident(diff, rows)
                _save_state(new_state)
            except Exception as e:
                log.error(f"Scheduled scan failed: {e}")
    except KeyboardInterrupt:
        log.info("Daemon stopped by user.")
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hyron AI background daemon")
    parser.add_argument("--corpus",   default="corpus", help="Root directory to watch")
    parser.add_argument("--interval", type=int, default=300, help="Polling interval in seconds")
    args = parser.parse_args()
    run_daemon(args.corpus, args.interval)
