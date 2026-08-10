#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_PHASE_FILE = Path("experiment_phase.json")

ALLOWED_PHASES = {
    "BASELINE",
    "PRE_ATTACK",
    "ATTACK",
    "RECOVERY",
    "POST_RECOVERY",
}


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def write_phase_atomic(
    phase_file: Path,
    phase: str,
    note: str,
) -> None:
    phase_file = phase_file.resolve()
    phase_file.parent.mkdir(parents=True, exist_ok=True)

    temporary_file = phase_file.with_name(
        f".{phase_file.name}.tmp"
    )

    data = {
        "phase": phase,
        "updated_at": utc_now(),
        "note": note,
    }

    temporary_file.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    os.replace(temporary_file, phase_file)

    print(f"Phase   : {phase}")
    print(f"Time    : {data['updated_at']}")
    print(f"Note    : {note}")
    print(f"File    : {phase_file}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mengubah fase eksperimen secara atomic."
    )

    parser.add_argument(
        "phase",
        choices=sorted(ALLOWED_PHASES),
    )

    parser.add_argument(
        "note",
        nargs="?",
        default="",
    )

    parser.add_argument(
        "--file",
        type=Path,
        default=DEFAULT_PHASE_FILE,
    )

    args = parser.parse_args()

    write_phase_atomic(
        args.file,
        args.phase,
        args.note,
    )


if __name__ == "__main__":
    main()