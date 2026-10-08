"""plaso's BSM events (psort JSON lines) as the TSV tests/plaso.rs compares.

One line per record: file, offset, size, event type, seconds, the header's
sub-second field as written, and the tokens: NAME key=value ... joined with
" | ", keys sorted. plaso reads the sub-second field as microseconds; it is
written as milliseconds, so it is kept raw here (as is a file token's).
plaso's name for error 18 lost its first letter ("ross-device link"); it
is put back.
Run: python3 -I gen.py plaso.jsonl | gzip -9n > plaso-bsm.tsv.gz
"""

import json
import sys


def value(token, key, v):
    if token == "AUT_OTHER_FILE32" and key == "timestamp":
        day, clock = v.split(" ")
        hms, frac = clock.split(".")
        h, m, s = (int(x) for x in hms.split(":"))
        assert day == "1970-01-01"
        return f"{h * 3600 + m * 60 + s}.{int(frac)}"
    if v == "ross-device link":
        return "Cross-device link"
    return str(v)


lines = []
for line in open(sys.argv[1]):
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if event.get("data_type") != "bsm:entry":
        continue
    tokens = []
    for item in event["extra_tokens"]:
        for name, fields in item.items():
            pairs = " ".join(
                f"{k}={value(name, k, fields[k])}" for k in sorted(fields)
            )
            tokens.append(f"{name} {pairs}".rstrip())
    micros = event["timestamp"]
    lines.append(
        "\t".join(
            [
                event["display_name"].rsplit("/", 1)[1],
                str(event["offset"]),
                str(event["record_length"]),
                str(event["event_type"]),
                str(micros // 1_000_000),
                str(micros % 1_000_000),
                " | ".join(tokens),
            ]
        )
    )
for line in sorted(set(lines)):
    print(line)
