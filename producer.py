"""
SIEM Astra - Module 1 producer.

Reads every .json file in Data/Datasets/Json_files, applies the group's four
data fixes in memory (the files themselves are never changed), validates each
event, removes duplicate event_ids, sorts events by time, and sends each one
to a Kafka topic as a single JSON message.

Run from the SIEM-Astra folder:
    python producer.py --dry-run      # fix + validate only, sends nothing
    python producer.py                # send everything to Kafka
    python producer.py --delay 0.2    # slow replay (about 5 events/second)
"""
import argparse
import json
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent / "Data" / "Datasets" / "Json_files"
REQUIRED_FIELDS = ["event_id", "timestamp", "event_type", "log_source", "label"]
VALID_LOG_SOURCES = {"system", "web_server"}
IST = timezone(timedelta(hours=5, minutes=30))  # used if a timestamp has no timezone

# Fix 1 - attack_vector (values not listed here are left unchanged)
ATTACK_VECTOR_MAP = {
    "normal web activity": "web",
    "robots.txt reconnaissance": "web",
    "multi-port network scan": "network",
    "web crawling": "web",
    "unauthorized web access": "web",
    "anomalous user agent": "web",
    "service enumeration": "web",
    "web scanner activity": "web",
}
# Fix 2 - log_source
LOG_SOURCE_MAP = {"apache2": "web_server", "ufw": "system"}


def normalise(ev):
    """Apply the four group fixes to a COPY of the event. Returns (event, fixes)."""
    ev = dict(ev)
    fixes = []

    av = ev.get("attack_vector")
    if isinstance(av, str) and av in ATTACK_VECTOR_MAP:
        ev["attack_vector"] = ATTACK_VECTOR_MAP[av]
        fixes.append("attack_vector")

    ls = ev.get("log_source")
    if isinstance(ls, str) and ls in LOG_SOURCE_MAP:
        ev["log_source"] = LOG_SOURCE_MAP[ls]
        fixes.append("log_source")

    proto = ev.get("protocol")
    if isinstance(proto, str) and proto != proto.lower():
        ev["protocol"] = proto.lower()
        fixes.append("protocol")

    # Fix 4 - missing event_type on normal traffic (label 0) becomes web_request
    if ev.get("event_type") is None and ev.get("label") == 0:
        ev["event_type"] = "web_request"
        fixes.append("event_type")

    return ev, fixes


def parse_ts(value):
    """Parse an ISO timestamp like 2026-08-03T01:59:38+05:30 into an aware datetime."""
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=IST)


def check_event(ev):
    """Return None if the event is valid, otherwise a short reason string."""
    if not isinstance(ev, dict):
        return "not a JSON object"
    for field in REQUIRED_FIELDS:
        if ev.get(field) is None:
            return f"missing {field}"
    if ev["label"] not in (0, 1):
        return f"label must be 0 or 1, got {ev['label']!r}"
    if ev["log_source"] not in VALID_LOG_SOURCES:
        return f"log_source {ev['log_source']!r} is not system/web_server"
    try:
        parse_ts(ev["timestamp"])
    except ValueError:
        return "bad timestamp"
    return None


def load_events():
    files = sorted(DATA_DIR.glob("*.json"))
    if not files:
        sys.exit(f"No .json files found in {DATA_DIR}")

    events, seen = [], set()
    stats = {"read": 0, "invalid": 0, "duplicates": 0}
    fixed, invalid = Counter(), Counter()
    first_keys = None

    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, OSError) as e:
            print(f"[skipped file] {f.name}: {e}")
            continue
        if isinstance(data, dict):
            data = [data]

        keys = set()
        kept = 0
        for ev in data:
            stats["read"] += 1
            if isinstance(ev, dict):
                ev, fixes = normalise(ev)
                fixed.update(fixes)
            reason = check_event(ev)
            if reason:
                stats["invalid"] += 1
                invalid[(f.name, reason)] += 1
                continue
            keys.update(ev.keys())
            if ev["event_id"] in seen:
                stats["duplicates"] += 1
                continue
            seen.add(ev["event_id"])
            events.append((parse_ts(ev["timestamp"]), ev))
            kept += 1
        print(f"{f.name}: {len(data)} read, {kept} kept")

        # Warn if this file's fields differ from the first file's fields
        if first_keys is None:
            first_keys = keys
        elif keys != first_keys:
            print(f"  [schema note] missing: {sorted(first_keys - keys)} "
                  f"extra: {sorted(keys - first_keys)}")

    if fixed:
        print("\nFixes applied in memory: " +
              ", ".join(f"{name} x{n}" for name, n in fixed.items()))
    if invalid:
        print("Skipped as invalid:")
        for (fname, reason), n in invalid.most_common():
            print(f"  {n} x {reason}  ({fname})")

    events.sort(key=lambda pair: pair[0])  # replay in chronological order
    return [ev for _, ev in events], stats


def send_events(events, args):
    from kafka import KafkaProducer
    from kafka.errors import KafkaError

    try:
        producer = KafkaProducer(
            bootstrap_servers=args.bootstrap,
            acks="all",
            retries=5,
            key_serializer=lambda k: k.encode("utf-8"),
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )
    except KafkaError as e:
        sys.exit(f"Cannot connect to Kafka at {args.bootstrap} ({type(e).__name__}). "
                 f"Is the container running? Try: docker compose up -d")

    errors = []
    for n, ev in enumerate(events, 1):
        producer.send(args.topic, key=ev["event_id"], value=ev).add_errback(errors.append)
        if args.delay:
            time.sleep(args.delay)
        if n % 500 == 0:
            print(f"  queued {n} events...")
    producer.flush()
    producer.close()
    return len(events) - len(errors), len(errors)


def main():
    parser = argparse.ArgumentParser(description="Send JSON events to Kafka")
    parser.add_argument("--bootstrap", default="localhost:9092")
    parser.add_argument("--topic", default="normalised-events")
    parser.add_argument("--delay", type=float, default=0.0, help="seconds between events")
    parser.add_argument("--limit", type=int, default=0, help="send only the first N events")
    parser.add_argument("--dry-run", action="store_true", help="fix + validate only, do not send")
    args = parser.parse_args()

    events, stats = load_events()
    if args.limit:
        events = events[: args.limit]

    print(f"\nRead {stats['read']} | invalid {stats['invalid']} | "
          f"duplicates {stats['duplicates']} | ready to send {len(events)}")

    if args.dry_run:
        print("Dry run: nothing was sent.")
        return

    ok, failed = send_events(events, args)
    print(f"Sent {ok} events to topic '{args.topic}' ({failed} failed).")


if __name__ == "__main__":
    main()