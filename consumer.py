"""
SIEM Astra - Module 1 consumer.

Reads events from the Kafka topic normalised-events and stores them in
Redis so Module 2 (and ad-hoc lookups) can query them quickly.

Redis layout:
    event:{event_id}              hash    - the full event, null fields dropped
    events:by_time                zset    - score=UTC epoch, member=event_id (global timeline)
    idx:src:{source_ip}           zset    - that IP's events by time
    idx:user:{user}               zset    - that user's events by time (ssh/sudo events)
    cnt:{event_type}:{source_ip}:{minute} string - per-minute count, 1h TTL (brute-force rate)

Run from the SIEM-Astra folder (after producer.py has sent events):
    python consumer.py                  # read from the beginning, once, then exit
    python consumer.py --follow         # keep running, wait for new events live
    python consumer.py --flush          # wipe Redis first (asks to confirm)
"""
import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))
# event_types that represent a login/auth attempt worth rate-counting.
# Extend this set as the group adds more brute-force-style event types.
RATE_COUNTED_TYPES = {"failed_ssh_login"}
COUNTER_TTL_SECONDS = 3600  # 1 hour is enough headroom for a per-minute window


def parse_ts(value):
    """Same parser as producer.py, kept in sync so both scripts agree."""
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=IST)


def clean_for_redis(ev):
    """Redis hashes cannot store JSON null. Drop those fields. Ports and
    byte counts sometimes arrive as whole-number floats (e.g. 42728.0);
    store them as plain integers so lookups are consistent."""
    out = {}
    for k, v in ev.items():
        if v is None:
            continue
        if isinstance(v, float) and v.is_integer():
            v = int(v)
        out[k] = v
    return out


def store_event(r, ev):
    """Write one event into Redis. Returns True if newly stored, False if
    this event_id was already there (so re-running the consumer, or Kafka
    redelivering a message, never double-counts anything)."""
    event_id = ev.get("event_id")
    if not event_id:
        return False
    key = f"event:{event_id}"
    if r.exists(key):
        return False

    dt = parse_ts(ev["timestamp"])
    epoch = dt.timestamp()

    pipe = r.pipeline()
    pipe.hset(key, mapping=clean_for_redis(ev))
    pipe.zadd("events:by_time", {event_id: epoch})

    src = ev.get("source_ip")
    if src:
        pipe.zadd(f"idx:src:{src}", {event_id: epoch})

    user = ev.get("user")
    if user:
        pipe.zadd(f"idx:user:{user}", {event_id: epoch})

    if ev.get("event_type") in RATE_COUNTED_TYPES and src:
        minute = dt.strftime("%Y%m%d%H%M")
        counter_key = f"cnt:{ev['event_type']}:{src}:{minute}"
        pipe.incr(counter_key)
        pipe.expire(counter_key, COUNTER_TTL_SECONDS)

    pipe.execute()
    return True


def run(args):
    import redis
    from kafka import KafkaConsumer
    from kafka.errors import KafkaError

    try:
        r = redis.Redis(host=args.redis_host, port=args.redis_port, decode_responses=True)
        r.ping()
    except redis.exceptions.RedisError as e:
        sys.exit(f"Cannot reach Redis at {args.redis_host}:{args.redis_port} ({e}). "
                 f"Is the container running? Try: docker compose up -d")

    if args.flush:
        answer = input(f"This will DELETE ALL keys in Redis at {args.redis_host}:{args.redis_port}. "
                       f"Type 'yes' to continue: ")
        if answer.strip().lower() != "yes":
            sys.exit("Cancelled, nothing was deleted.")
        r.flushdb()
        print("Redis flushed.")

    try:
        consumer = KafkaConsumer(
            args.topic,
            bootstrap_servers=args.bootstrap,
            group_id=args.group,
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            consumer_timeout_ms=(-1 if args.follow else 5000),
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        )
    except KafkaError as e:
        sys.exit(f"Cannot connect to Kafka at {args.bootstrap} ({type(e).__name__}). "
                 f"Is the container running? Try: docker compose up -d")

    stored, skipped, bad = 0, 0, 0
    for msg in consumer:
        ev = msg.value
        if not isinstance(ev, dict) or "event_id" not in ev or "timestamp" not in ev:
            bad += 1
            continue
        if store_event(r, ev):
            stored += 1
        else:
            skipped += 1
        if (stored + skipped) % 1000 == 0:
            print(f"  processed {stored + skipped} (stored {stored}, duplicates {skipped})")
        consumer.commit()

    print(f"\nStored {stored} new events | {skipped} already present | {bad} malformed")
    print(f"Redis events:by_time size: {r.zcard('events:by_time')}")
    consumer.close()


def main():
    parser = argparse.ArgumentParser(description="Move events from Kafka into Redis")
    parser.add_argument("--bootstrap", default="localhost:9092")
    parser.add_argument("--topic", default="normalised-events")
    parser.add_argument("--group", default="redis-writer")
    parser.add_argument("--redis-host", default="localhost")
    parser.add_argument("--redis-port", type=int, default=6379)
    parser.add_argument("--follow", action="store_true",
                        help="keep running and wait for new events instead of exiting")
    parser.add_argument("--flush", action="store_true",
                        help="wipe Redis before loading (asks for confirmation)")
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()