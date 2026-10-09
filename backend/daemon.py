#!/usr/bin/env python3
"""
daemon.py — Background Watcher & Polling Scheduler

What:
    Monitors lockfile directories for filesystem events and triggers scheduled rescans.
    Diffs findings between consecutive scans and emits structured incident alerts.
Why:
    Stage 01 (Watch) of the 9-stage pipeline. Guarantees continuous supply-chain
    monitoring as developers install packages or when new advisories are published.
Inputs:
    --corpus (directory path to monitor, default: "corpus")
    --interval (seconds between periodic checks, default: 300)
Outputs:
    Automated scan executions, console/log incident diff notifications.
Called by:
    Operator / systemd service: python -m backend.daemon --corpus corpus --interval 300
"""

import argparse
import glob
import json
import logging
import sys
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


def _save_state(state: dict) -> None:
    """Save the current finding state hash map to the state file."""
    LAST_STATE.write_text(json.dumps(state))


def _load_state() -> dict[str, float]:
    """Load the previous finding state mapping from disk if present."""
    if LAST_STATE.exists():
        return json.loads(LAST_STATE.read_text())
    return {}


def run_scan(lockfile_paths: list[str]) -> tuple[dict, list[dict]]:
    """Execute the pipeline on specified lockfiles and return (new_state_map, raw_finding_rows)."""
    from backend.main import run_pipeline
    _, rows = run_pipeline(lockfile_paths)
    new_state = {f"{r['project']}|{r['package']}|{r['vuln']}": r["risk"] for r in rows}
    return new_state, rows


def diff_state(old: dict[str, float], new: dict[str, float]) -> dict:
    """
    Compare prior and new scan states to detect added, resolved, or changed findings.

    Returns:
        dict: with keys 'new_findings', 'resolved', and 'risk_changes'.
    """
    new_findings = [(k, v) for k, v in new.items() if k not in old]
    resolved     = [k for k in old if k not in new]
    risk_changes = [
        (k, old[k], new[k]) for k in new
        if k in old and abs(old[k] - new[k]) > 1.0
    ]
    return {
        "new_findings": new_findings,
        "resolved":     resolved,
        "risk_changes": risk_changes,
    }


def emit_incident(diff: dict, rows: list[dict]) -> None:
    """Log structured incident notifications when state differences are detected."""
    if not any(diff.values()):
        log.info("Scan complete — no new findings or state changes detected.")
        return

    if diff["new_findings"]:
        log.warning(f"NEW FINDINGS: {len(diff['new_findings'])} newly introduced vulnerability instances")
        for key, risk in sorted(diff["new_findings"], key=lambda x: -x[1])[:5]:
            proj, pkg, vuln = key.split("|")
            log.warning(f"  RISK {risk:5.1f}  {proj:18}  {pkg:30}  {vuln}")

    if diff["resolved"]:
        log.info(f"RESOLVED: {len(diff['resolved'])} findings resolved (package upgraded or removed)")

    if diff["risk_changes"]:
        log.info(f"RISK CHANGES: {len(diff['risk_changes'])} findings updated risk score")


class LockfileHandler(FileSystemEventHandler):
    """Filesystem event handler triggering throttled scans on package-lock.json changes."""

    def __init__(self, lockfile_pattern: str, cooldown: float = 5.0):
        super().__init__()
        self.lockfile_pattern = lockfile_pattern
        self.cooldown = cooldown
        self._last_scan: float = 0.0

    def _should_scan(self, src_path: str) -> bool:
        """Check whether the modified file is a lockfile and cooldown period has elapsed."""
        return (
            "package-lock.json" in src_path
            and time.time() - self._last_scan > self.cooldown
        )

    def on_modified(self, event: FileModifiedEvent):
        """Handle file modification events on watched lockfiles."""
        if not event.is_directory and self._should_scan(event.src_path):
            log.info(f"Detected lockfile change: {event.src_path}")
            self._trigger()

    def on_created(self, event: FileCreatedEvent):
        """Handle new file creation events on watched lockfiles."""
        if not event.is_directory and self._should_scan(event.src_path):
            log.info(f"Detected new lockfile: {event.src_path}")
            self._trigger()

    def _trigger(self):
        """Trigger scan and compare against prior state."""
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
            log.error(f"Automated scan failed: {e}")


def run_daemon(corpus_dir: str, interval: int) -> None:
    """Start the background watcher and periodic polling loop."""
    corpus_path = Path(corpus_dir)
    if not corpus_path.exists():
        print(
            f"Error: Corpus directory '{corpus_dir}' does not exist.\n"
            f"Generate a sample corpus with: python -m backend.make_corpus 25\n"
            f"Or specify an existing repository directory with: python -m backend.daemon --corpus <dir>",
            file=sys.stderr,
        )
        sys.exit(1)

    pattern = f"{corpus_dir}/**/package-lock.json"
    paths   = glob.glob(pattern, recursive=True)

    log.info(f"Hyron AI daemon starting — watching '{corpus_dir}', polling interval={interval}s")
    log.info(f"Discovered {len(paths)} lockfiles on startup")

    # Perform initial baseline scan
    if paths:
        old_state = _load_state()
        try:
            new_state, rows = run_scan(paths)
            diff = diff_state(old_state, new_state)
            emit_incident(diff, rows)
            _save_state(new_state)
        except Exception as e:
            log.error(f"Initial baseline scan failed: {e}")
    else:
        log.warning(f"No lockfiles found in '{corpus_dir}'. Watching directory for new additions...")

    # Start filesystem event observer
    handler  = LockfileHandler(pattern)
    observer = Observer()
    observer.schedule(handler, path=corpus_dir, recursive=True)
    observer.start()
    log.info("Filesystem watcher active. Press Ctrl+C to stop.")

    # Periodic polling loop
    try:
        while True:
            time.sleep(interval)
            current_paths = glob.glob(pattern, recursive=True)
            if not current_paths:
                continue
            log.info(f"Running periodic scheduled scan ({interval}s interval)...")
            old_state = _load_state()
            try:
                new_state, rows = run_scan(current_paths)
                diff = diff_state(old_state, new_state)
                emit_incident(diff, rows)
                _save_state(new_state)
            except Exception as e:
                log.error(f"Periodic scan failed: {e}")
    except KeyboardInterrupt:
        log.info("Daemon stopped by user.")
    finally:
        observer.stop()
        observer.join()


def _parse_cli():
    """Parse CLI arguments with usage examples."""
    parser = argparse.ArgumentParser(
        prog="python -m backend.daemon",
        description="Hyron AI — Background Lockfile Watcher & Scheduler (FUSION 2026 · CSB-03)",
        epilog=(
            "Examples:\n"
            "  python -m backend.daemon --corpus corpus\n"
            "  python -m backend.daemon --corpus corpus --interval 60\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--corpus",
        default="corpus",
        help="Root directory containing repository lockfiles to monitor (default: corpus).",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Polling interval in seconds for periodic rescan (default: 300).",
    )
    return parser.parse_args()


if __name__ == "__main__":
    cli_args = _parse_cli()
    run_daemon(cli_args.corpus, cli_args.interval)
