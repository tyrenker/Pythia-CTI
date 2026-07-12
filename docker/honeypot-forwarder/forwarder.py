"""
Tails Cowrie's JSON log and POSTs batches to Pythia's bulk ingest endpoint.
Tracks its position so restarts don't re-send old events.
"""

import json
import os
import sys
import time
from pathlib import Path

import httpx

PYTHIA_URL = os.environ["PYTHIA_URL"].rstrip("/")
PYTHIA_API_KEY = os.environ["PYTHIA_API_KEY"]
LOG_FILE = os.environ.get("COWRIE_LOG", "/cowrie-logs/cowrie.json")
STATE_FILE = os.environ.get("STATE_FILE", "/tmp/forwarder.pos")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50"))
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "5"))
HONEYPOT_TYPE = os.environ.get("HONEYPOT_TYPE", "cowrie")


def _read_pos() -> int:
    try:
        return int(Path(STATE_FILE).read_text())
    except Exception:
        return 0


def _save_pos(pos: int) -> None:
    Path(STATE_FILE).write_text(str(pos))


def _post_batch(events: list[dict]) -> bool:
    tagged = [{**e, "honeypot_type": HONEYPOT_TYPE} for e in events]
    try:
        resp = httpx.post(
            f"{PYTHIA_URL}/v1/honeypot/events/bulk",
            json=tagged,
            headers={"X-API-Key": PYTHIA_API_KEY},
            timeout=15,
        )
        if resp.status_code == 200:
            ingested = resp.json().get("ingested", 0)
            print(f"[forwarder] sent {len(tagged)} events → {ingested} ingested", flush=True)
            return True
        print(f"[forwarder] HTTP {resp.status_code}: {resp.text[:200]}", flush=True)
    except Exception as exc:
        print(f"[forwarder] POST failed: {exc}", flush=True)
    return False


def tail() -> None:
    log_path = Path(LOG_FILE)
    print(f"[forwarder] watching {log_path} → {PYTHIA_URL}", flush=True)

    while not log_path.exists():
        print(f"[forwarder] waiting for {log_path}...", flush=True)
        time.sleep(POLL_INTERVAL)

    pos = _read_pos()
    inode = log_path.stat().st_ino

    while True:
        # Detect log rotation
        try:
            current_inode = log_path.stat().st_ino
        except FileNotFoundError:
            time.sleep(POLL_INTERVAL)
            continue

        if current_inode != inode:
            pos = 0
            inode = current_inode

        with log_path.open() as f:
            f.seek(pos)
            batch: list[dict] = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    batch.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if len(batch) >= BATCH_SIZE:
                    if _post_batch(batch):
                        pos = f.tell()
                        _save_pos(pos)
                    batch = []
            if batch and _post_batch(batch):
                pos = f.tell()
                _save_pos(pos)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        tail()
    except KeyboardInterrupt:
        sys.exit(0)
