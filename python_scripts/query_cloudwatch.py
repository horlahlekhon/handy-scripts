#!/usr/bin/env python3
"""
Query AWS CloudWatch Logs from the terminal.

Usage:
    python query_cloudwatch.py <LOG_GROUP> [OPTIONS]

Examples:
    # Last hour of logs
    python query_cloudwatch.py /aws/lambda/my-fn --from 1h

    # Filter for errors in a time range
    python query_cloudwatch.py /aws/lambda/my-fn --from 2025-05-18T10:00:00 --to 2025-05-18T11:00:00 --search error

    # Tail last 20 events then follow live
    python query_cloudwatch.py /aws/lambda/my-fn --tail 20

    # Follow from 30 minutes ago, output as NDJSON
    python query_cloudwatch.py /aws/lambda/my-fn --from 30m --follow --json

    # Narrow to a specific stream prefix
    python query_cloudwatch.py /aws/lambda/my-fn --from 1h --stream 2025/05/18

Options:
    --from TEXT           Start time: ISO 8601 or relative (1h, 10m, 1d, 30s, 2hr). Required unless --tail.
    --to TEXT             End time: ISO 8601 or relative. Defaults to now UTC. Ignored with --follow/--tail.
    --search TEXT         Free-text filter (server-side). Multiple words → OR semantics (?word1 ?word2).
    --stream TEXT         Log stream name prefix filter.
    --limit N             Max events to return. Cannot combine with --follow.
    --follow              After initial window, continuously poll for new events (Ctrl+C to exit).
    --tail N              Backfill last N events from past 24 h, then enter follow mode.
    --poll-interval N     Seconds between polls in follow/tail mode (default: 5).
    --json                Emit NDJSON (one JSON object per line) instead of pretty-print.
    --profile TEXT        AWS named profile.
    --region TEXT         AWS region (default: from profile or AWS_DEFAULT_REGION).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Iterator

import boto3
from botocore.exceptions import ClientError


_RELATIVE_RE = re.compile(r'^(\d+)(s|m|hr|h|d)$')
_UNIT_MAP = {
    's': lambda n: timedelta(seconds=n),
    'm': lambda n: timedelta(minutes=n),
    'h': lambda n: timedelta(hours=n),
    'hr': lambda n: timedelta(hours=n),
    'd': lambda n: timedelta(days=n),
}

_RESET = "\033[0m"
_RED = "\033[31m"
_YELLOW = "\033[33m"


def pretty_print(event: dict) -> None:
    """Print a log event with timestamp, stream name, message, and ANSI color coding."""
    ts_ms = event.get("timestamp", 0)
    dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    ts_str = dt.strftime("%Y-%m-%d %H:%M:%S") + f".{ts_ms % 1000:03d} UTC"
    stream = event.get("logStreamName", "")
    message = event.get("message", "")

    msg_lower = message.lower()
    if re.search(r"error|exception", msg_lower):
        color, reset = _RED, _RESET
    elif "warn" in msg_lower:
        color, reset = _YELLOW, _RESET
    else:
        color, reset = "", ""

    print(f"{color}{ts_str}  [{stream}]  {message}{reset}")


def json_print(event: dict) -> None:
    print(json.dumps(event))


def parse_time(s: str, now: datetime | None = None) -> int:
    """Return epoch milliseconds for an ISO 8601 string or relative shorthand."""
    if now is None:
        now = datetime.now(timezone.utc)

    m = _RELATIVE_RE.match(s)
    if m:
        value, unit = int(m.group(1)), m.group(2)
        dt = now - _UNIT_MAP[unit](value)
        return int(dt.timestamp() * 1000)

    try:
        if re.match(r'^\d{4}-\d{2}-\d{2}$', s):
            dt = datetime.strptime(s, '%Y-%m-%d').replace(tzinfo=timezone.utc)
        else:
            dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        raise ValueError(
            f"Cannot parse time '{s}'. Use ISO 8601 (2025-05-18T10:00:00) "
            "or relative shorthand (1h, 10m, 30s, 1d)."
        )

    return int(dt.timestamp() * 1000)


def build_filter_pattern(search: str | None) -> str:
    """Convert a free-text term to a CloudWatch filter pattern string."""
    if not search:
        return ""
    return " ".join(f"?{token}" for token in search.split())


def make_client(profile: str | None = None, region: str | None = None):
    """Return a boto3 CloudWatch Logs client."""
    session_kwargs: dict = {}
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(**session_kwargs)
    client_kwargs: dict = {}
    if region:
        client_kwargs["region_name"] = region
    return session.client("logs", **client_kwargs)


def fetch_events(
    client,
    log_group: str,
    start_ms: int,
    end_ms: int,
    filter_pattern: str = "",
    stream_prefix: str | None = None,
    limit: int | None = None,
) -> Iterator[dict]:
    """Yield log events from a single time window, auto-paginating."""
    kwargs: dict = {
        "logGroupName": log_group,
        "startTime": start_ms,
        "endTime": end_ms,
    }
    if filter_pattern:
        kwargs["filterPattern"] = filter_pattern
    if stream_prefix:
        kwargs["logStreamNamePrefix"] = stream_prefix

    count = 0
    while True:
        try:
            response = client.filter_log_events(**kwargs)
        except client.exceptions.ResourceNotFoundException:
            raise ValueError(f"Log group '{log_group}' not found.")

        for event in response.get("events", []):
            yield event
            count += 1
            if limit is not None and count >= limit:
                return

        next_token = response.get("nextToken")
        if not next_token:
            break
        kwargs["nextToken"] = next_token


def follow_events(
    client,
    log_group: str,
    last_ms: int,
    filter_pattern: str = "",
    stream_prefix: str | None = None,
    poll_interval: int = 5,
) -> Iterator[dict]:
    """Yield new log events indefinitely, polling every poll_interval seconds."""
    while True:
        time.sleep(poll_interval)
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        kwargs: dict = {
            "logGroupName": log_group,
            "startTime": last_ms + 1,
            "endTime": now_ms,
        }
        if filter_pattern:
            kwargs["filterPattern"] = filter_pattern
        if stream_prefix:
            kwargs["logStreamNamePrefix"] = stream_prefix

        while True:
            response = client.filter_log_events(**kwargs)
            for event in response.get("events", []):
                last_ms = max(last_ms, event["timestamp"])
                yield event
            next_token = response.get("nextToken")
            if not next_token:
                break
            kwargs["nextToken"] = next_token


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Query AWS CloudWatch Logs from the terminal."
    )
    parser.add_argument("log_group", help="CloudWatch log group name")
    parser.add_argument("--from", dest="from_time", default=None,
                        help="Start time: ISO 8601 or relative (1h, 10m, 1d, 30s, 2hr)")
    parser.add_argument("--to", dest="to_time", default=None,
                        help="End time: ISO 8601 or relative. Defaults to now UTC")
    parser.add_argument("--search", default=None, help="Free text filter term")
    parser.add_argument("--stream", default=None, help="Log stream name prefix filter")
    parser.add_argument("--limit", type=int, default=None,
                        help="Max events to return. Cannot combine with --follow or --tail")
    parser.add_argument("--follow", action="store_true",
                        help="Continuously poll for new events after the initial window")
    parser.add_argument("--tail", type=int, default=None, metavar="N",
                        help="Backfill last N events (24 h window) then enter follow mode")
    parser.add_argument("--poll-interval", type=int, default=5, dest="poll_interval",
                        help="Poll interval in seconds for follow/tail mode (default: 5)")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Emit NDJSON instead of pretty-print")
    parser.add_argument("--profile", default=None, help="AWS named profile")
    parser.add_argument("--region", default=None, help="AWS region")

    args = parser.parse_args()

    if args.limit is not None and (args.follow or args.tail is not None):
        parser.error("--limit cannot be combined with --follow or --tail")

    if args.tail is None and not args.from_time:
        parser.error("--from is required unless --tail is set")

    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    printer = json_print if args.json_output else pretty_print
    filter_pattern = build_filter_pattern(args.search)

    try:
        client = make_client(args.profile, args.region)

        if args.tail is not None:
            start_ms = now_ms - 86_400_000
            last_ms = now_ms
            for event in fetch_events(
                client, args.log_group, start_ms, now_ms,
                filter_pattern=filter_pattern,
                stream_prefix=args.stream,
                limit=args.tail,
            ):
                printer(event)
                last_ms = max(last_ms, event["timestamp"])
            try:
                for event in follow_events(
                    client, args.log_group, last_ms,
                    filter_pattern=filter_pattern,
                    stream_prefix=args.stream,
                    poll_interval=args.poll_interval,
                ):
                    printer(event)
            except KeyboardInterrupt:
                pass

        elif args.follow:
            start_ms = parse_time(args.from_time)
            last_ms = now_ms
            for event in fetch_events(
                client, args.log_group, start_ms, now_ms,
                filter_pattern=filter_pattern,
                stream_prefix=args.stream,
            ):
                printer(event)
                last_ms = max(last_ms, event["timestamp"])
            try:
                for event in follow_events(
                    client, args.log_group, last_ms,
                    filter_pattern=filter_pattern,
                    stream_prefix=args.stream,
                    poll_interval=args.poll_interval,
                ):
                    printer(event)
            except KeyboardInterrupt:
                pass

        else:
            start_ms = parse_time(args.from_time)
            end_ms = parse_time(args.to_time) if args.to_time else now_ms
            for event in fetch_events(
                client, args.log_group, start_ms, end_ms,
                filter_pattern=filter_pattern,
                stream_prefix=args.stream,
                limit=args.limit,
            ):
                printer(event)

    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except ClientError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
