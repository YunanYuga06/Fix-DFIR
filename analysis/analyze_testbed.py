#!/usr/bin/env python3
"""
analyze_testbed_pamsimas.py
============================

Analisis cross-layer untuk testbed PAMSIMAS:

    ThingsBoard mock/telemetry
        -> Raspberry Pi sender + state proxy
        -> Modbus/TCP
        -> OpenPLC controller
        -> ValveCommand

Input utama adalah output raw collector terbaru:

    <collector-session>/raw/raspi_evidence.csv
    <collector-session>/raw/openplc_evidence.csv

Script dapat digunakan untuk:
1. Baseline saja; atau
2. Perbandingan Baseline dengan Perlakuan 1 FDI.

Definisi operasional:

Source encoding integrity
    nilai telemetry asli == nilai yang diencoding/dikirim Raspberry Pi

Cross-layer integrity
    nilai yang dikirim Raspberry Pi == nilai yang diterima OpenPLC

PLC internal consistency
    OdoMeter_FromPi == OdoMeter_Processed

Controller logic consistency
    output OpenPLC sesuai nilai yang diterima OpenPLC

Operational impact relative to legitimate source
    output valve aktual dibandingkan keputusan yang seharusnya dibuat dari
    nilai legitimate yang dikirim Raspberry Pi.

Perlakuan 1 default:
    target register : HR1024
    attack value    : 1000

Catatan penting:
- Tanpa modbus_write_events.csv/PCAP, script hanya dapat menyatakan bahwa
  terdapat observasi nilai 1000 pada OpenPLC yang tidak sesuai nilai source.
  Script tidak mengklaim FC06 terkonfirmasi pada network layer.
- Tidak memerlukan library eksternal.

Contoh Baseline saja:

    python3 analyze_testbed_pamsimas.py \
      --baseline-session evidence/BASELINE/collector-... \
      --operator "Yunan Yuga Pratama"

Contoh Baseline vs Perlakuan 1:

    python3 analyze_testbed_pamsimas.py \
      --baseline-session evidence/BASELINE/collector-... \
      --treatment-session evidence/PERLAKUAN_1_FDI/collector-... \
      --operator "Yunan Yuga Pratama" \
      --attack-value 1000

Auto-discovery dari root DFIR:

    python3 analyze_testbed_pamsimas.py \
      --dfir-root . \
      --operator "Yunan Yuga Pratama"
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import math
import os
import re
import socket
import statistics
import sys
import traceback
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


SCRIPT_PATH = Path(__file__).resolve()
SCHEMA_VERSION = "1.0-pamsimas-thingsboard-analysis"

DEFAULT_TARGET_REGISTER = 1024
DEFAULT_ATTACK_VALUE = 1000
DEFAULT_ABNORMAL_THRESHOLD = 100
DEFAULT_STABLE_RECORDS = 3
DEFAULT_CORRELATION_WINDOW_SECONDS = 2.5

FLOW_RATE_SCALE = 1000
VOLUME_SCALE = 10000

RASPI_FILE_NAME = "raspi_evidence.csv"
OPENPLC_FILE_NAME = "openplc_evidence.csv"
HASH_MANIFEST_NAME = "hash_manifest.csv"
MODBUS_WRITE_EVENTS_NAME = "modbus_write_events.csv"

REQUIRED_RASPI_FIELDS = {
    "collection_id",
    "collection_sequence",
    "experiment_phase",
    "read_status",
    "send_status",
    "original_odo_meter_litre",
    "sent_odo_meter_litre",
    "original_flow_rate_lpm",
    "sent_flow_rate_x1000",
    "original_volume_litre",
    "sent_volume_x10000",
    "original_payment_status",
    "sent_payment_status",
    "source_sequence",
    "observed_valve_raw",
    "node_id",
}

REQUIRED_OPENPLC_FIELDS = {
    "collection_id",
    "collection_sequence",
    "experiment_phase",
    "read_status",
    "register_read_status",
    "coil_read_status",
    "odo_meter_from_pi",
    "flow_rate_x1000_from_pi",
    "volume_x10000_from_pi",
    "payment_status_from_pi",
    "source_sequence_from_pi",
    "observed_valve_raw_from_pi",
    "node_id_from_pi",
    "odo_meter_processed",
    "process_state",
    "valve_reason",
    "valve_command",
    "abnormal_usage",
    "payment_blocked",
}


@dataclass(frozen=True)
class ScenarioData:
    label: str
    session_dir: Path
    raspi_path: Path
    openplc_path: Path
    raspi_rows: list[dict[str, str]]
    openplc_rows: list[dict[str, str]]
    paired_rows: list[dict[str, Any]]
    input_hash_rows: list[dict[str, Any]]
    modbus_writes: list[dict[str, Any]]


# =========================================================
# UTILITAS
# =========================================================


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def create_run_id() -> str:
    return (
        "analysis-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex[:8]
    )


def parse_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def format_datetime(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_int(value: Any) -> Optional[int]:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    try:
        return int(text)
    except ValueError:
        try:
            number = float(text)
        except ValueError:
            return None

        if not math.isfinite(number):
            return None
        return int(round(number))


def parse_float(value: Any) -> Optional[float]:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    try:
        result = float(text)
    except ValueError:
        return None

    return result if math.isfinite(result) else None


def parse_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None:
        return None

    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "y", "open", "on"}:
        return True
    if text in {"false", "0", "no", "n", "closed", "off"}:
        return False
    return None


def normalise_phase(value: Any) -> str:
    text = str(value or "UNSPECIFIED").strip().upper()
    return text or "UNSPECIFIED"


def bool_text(value: Any) -> str:
    parsed = parse_bool(value)
    if parsed is None:
        return ""
    return "TRUE" if parsed else "FALSE"


def csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if not rows:
        path.write_text("", encoding="utf-8")
        return

    fieldnames: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)

    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_value(row.get(key)) for key in fieldnames})
        handle.flush()
        os.fsync(handle.fileno())

    os.replace(temporary, path)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(
            payload,
            handle,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            default=str,
        )
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def safe_percentage(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return round((numerator / denominator) * 100, 3)


def format_percent(value: Any) -> str:
    number = parse_float(value)
    return "N/A" if number is None else f"{number:.3f}%"


def format_number(value: Any, digits: int = 3) -> str:
    number = parse_float(value)
    return "N/A" if number is None else f"{number:.{digits}f}"


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    def escape(value: Any) -> str:
        return str("" if value is None else value).replace("|", "\\|")

    lines = [
        "| " + " | ".join(escape(header) for header in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(escape(value) for value in row) + " |")
    return "\n".join(lines)


def row_timestamp(row: dict[str, Any]) -> Optional[datetime]:
    for key in (
        "record_timestamp_utc",
        "openplc_read_finished_at",
        "cycle_completed_at",
        "raspi_read_finished_at",
        "cycle_started_at",
    ):
        parsed = parse_datetime(row.get(key))
        if parsed is not None:
            return parsed
    return None


def validate_headers(path: Path, required: set[str]) -> None:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration as exc:
            raise ValueError(f"CSV kosong: {path}") from exc

    missing = sorted(required.difference(header))
    if missing:
        raise ValueError(
            f"Schema CSV tidak sesuai pada {path}. "
            f"Field yang belum tersedia: {', '.join(missing)}"
        )


# =========================================================
# PENEMUAN INPUT
# =========================================================


def find_latest_collector_session(scenario_root: Path) -> Optional[Path]:
    if not scenario_root.exists():
        return None

    candidates: list[Path] = []
    for path in scenario_root.rglob("collector-*"):
        if not path.is_dir():
            continue
        if (path / "raw" / RASPI_FILE_NAME).exists() and (
            path / "raw" / OPENPLC_FILE_NAME
        ).exists():
            candidates.append(path)

    if not candidates:
        return None

    return max(candidates, key=lambda item: item.stat().st_mtime)


def resolve_session_path(
    supplied: Optional[Path],
    *,
    dfir_root: Path,
    scenario_name: str,
    required: bool,
) -> Optional[Path]:
    if supplied is not None:
        path = supplied.resolve()

        if path.is_file():
            raise ValueError(f"Session path harus berupa folder: {path}")

        # Menerima collector session, raw dir, atau salah satu parent-nya.
        candidates = [path, path.parent]
        for candidate in candidates:
            if (candidate / "raw" / RASPI_FILE_NAME).exists() and (
                candidate / "raw" / OPENPLC_FILE_NAME
            ).exists():
                return candidate

        if (path / RASPI_FILE_NAME).exists() and (
            path / OPENPLC_FILE_NAME
        ).exists():
            return path.parent

        discovered = find_latest_collector_session(path)
        if discovered is not None:
            return discovered

        raise FileNotFoundError(
            f"Tidak menemukan {RASPI_FILE_NAME} dan {OPENPLC_FILE_NAME} "
            f"di bawah {path}"
        )

    scenario_root = dfir_root / "evidence" / scenario_name
    discovered = find_latest_collector_session(scenario_root)

    if discovered is None and required:
        raise FileNotFoundError(
            f"Session {scenario_name} tidak ditemukan otomatis di {scenario_root}. "
            f"Gunakan --{'baseline' if scenario_name == 'BASELINE' else 'treatment'}-session."
        )

    return discovered


def locate_optional_modbus_writes(session_dir: Path) -> Optional[Path]:
    candidates = sorted(
        session_dir.rglob(MODBUS_WRITE_EVENTS_NAME),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


# =========================================================
# VERIFIKASI INPUT
# =========================================================


def find_hash_manifest(session_dir: Path) -> Optional[Path]:
    direct = session_dir / "metadata" / HASH_MANIFEST_NAME
    if direct.exists():
        return direct

    candidates = sorted(
        session_dir.rglob(HASH_MANIFEST_NAME),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def verify_input_hashes(
    session_dir: Path,
    input_paths: list[Path],
) -> list[dict[str, Any]]:
    manifest_path = find_hash_manifest(session_dir)
    manifest_rows = read_csv(manifest_path) if manifest_path else []

    expected_by_relative: dict[str, str] = {}
    expected_by_name: dict[str, list[str]] = defaultdict(list)

    for row in manifest_rows:
        relative = str(row.get("relative_path", "")).replace("\\", "/")
        expected = str(row.get("sha256", "")).strip().lower()
        if relative and expected:
            expected_by_relative[relative] = expected
            expected_by_name[Path(relative).name].append(expected)

    verification: list[dict[str, Any]] = []
    for path in input_paths:
        actual = sha256_file(path)
        try:
            relative = str(path.relative_to(session_dir)).replace("\\", "/")
        except ValueError:
            relative = path.name

        expected = expected_by_relative.get(relative)
        if expected is None:
            name_matches = expected_by_name.get(path.name, [])
            if len(set(name_matches)) == 1:
                expected = name_matches[0]

        if manifest_path is None:
            status = "MANIFEST_NOT_FOUND"
        elif expected is None:
            status = "FILE_NOT_LISTED"
        elif expected == actual:
            status = "VERIFIED"
        else:
            status = "HASH_MISMATCH"

        verification.append(
            {
                "session_directory": str(session_dir),
                "input_file": str(path),
                "relative_path": relative,
                "manifest_file": str(manifest_path) if manifest_path else None,
                "expected_sha256": expected,
                "actual_sha256": actual,
                "verification_status": status,
            }
        )

    return verification


# =========================================================
# OPTIONAL NETWORK WRITE EVENTS
# =========================================================


def first_present(row: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip() != "":
            return value
    return None


def load_modbus_writes(
    path: Optional[Path],
    *,
    target_register: int,
    attack_value: int,
) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []

    result: list[dict[str, Any]] = []
    for row in read_csv(path):
        function_code = parse_int(
            first_present(row, ["function_code", "modbus_function_code", "fc"])
        )
        register = parse_int(
            first_present(
                row,
                ["register_address", "reference_number", "target_register", "address"],
            )
        )
        value = parse_int(
            first_present(
                row,
                ["register_value", "written_value", "attack_value", "value"],
            )
        )
        timestamp = parse_datetime(
            first_present(
                row,
                [
                    "timestamp_utc",
                    "event_timestamp",
                    "frame_timestamp_utc",
                    "packet_timestamp_utc",
                    "timestamp",
                ],
            )
        )

        is_target = register == target_register and value == attack_value
        if function_code is not None:
            is_target = is_target and function_code in {6, 16}

        if is_target:
            result.append(
                {
                    "timestamp": timestamp,
                    "timestamp_utc": format_datetime(timestamp),
                    "function_code": function_code,
                    "register_address": register,
                    "register_value": value,
                    "packet_number": first_present(row, ["packet_number", "frame_number"]),
                    "transaction_id": first_present(row, ["transaction_id"]),
                    "source_file": str(path),
                }
            )

    result.sort(key=lambda item: item["timestamp"] or datetime.min.replace(tzinfo=timezone.utc))
    return result


# =========================================================
# PAIRING DAN DERIVASI CROSS-LAYER
# =========================================================


def compare_values(left: Any, right: Any) -> Optional[bool]:
    if left is None or right is None:
        return None
    return left == right


def expected_controller_logic(
    odo_value: Optional[int],
    payment_status: Optional[int],
    abnormal_threshold: int,
) -> dict[str, Any]:
    if odo_value is None or payment_status is None:
        return {
            "abnormal_usage": None,
            "payment_blocked": None,
            "valve_command": None,
            "process_state": None,
            "valve_reason": None,
        }

    payment_blocked = payment_status == 0
    abnormal_usage = odo_value >= abnormal_threshold

    if payment_blocked:
        process_state = 2
        valve_reason = 1
        valve_command = False
    elif abnormal_usage:
        process_state = 3
        valve_reason = 2
        valve_command = False
    else:
        process_state = 1
        valve_reason = 0
        valve_command = True

    return {
        "abnormal_usage": abnormal_usage,
        "payment_blocked": payment_blocked,
        "valve_command": valve_command,
        "process_state": process_state,
        "valve_reason": valve_reason,
    }


def build_paired_rows(
    label: str,
    raspi_rows: list[dict[str, str]],
    openplc_rows: list[dict[str, str]],
    *,
    abnormal_threshold: int,
    attack_value: int,
) -> list[dict[str, Any]]:
    raspi_by_id = {
        row.get("collection_id", ""): row
        for row in raspi_rows
        if row.get("collection_id")
    }
    openplc_by_id = {
        row.get("collection_id", ""): row
        for row in openplc_rows
        if row.get("collection_id")
    }

    all_ids = sorted(
        set(raspi_by_id).union(openplc_by_id),
        key=lambda key: (
            parse_int(
                (raspi_by_id.get(key) or openplc_by_id.get(key) or {}).get(
                    "collection_sequence"
                )
            )
            or 0,
            key,
        ),
    )

    paired: list[dict[str, Any]] = []

    for collection_id in all_ids:
        raspi = raspi_by_id.get(collection_id, {})
        plc = openplc_by_id.get(collection_id, {})

        original_odo = parse_int(raspi.get("original_odo_meter_litre"))
        sent_odo = parse_int(raspi.get("sent_odo_meter_litre"))
        original_flow = parse_float(raspi.get("original_flow_rate_lpm"))
        sent_flow = parse_int(raspi.get("sent_flow_rate_x1000"))
        original_volume = parse_float(raspi.get("original_volume_litre"))
        sent_volume = parse_int(raspi.get("sent_volume_x10000"))
        original_payment = parse_int(raspi.get("original_payment_status"))
        sent_payment = parse_int(raspi.get("sent_payment_status"))
        source_sequence = parse_int(raspi.get("source_sequence"))
        source_valve_raw = parse_int(raspi.get("observed_valve_raw"))
        source_node_id = parse_int(raspi.get("node_id"))

        plc_odo = parse_int(plc.get("odo_meter_from_pi"))
        plc_flow = parse_int(plc.get("flow_rate_x1000_from_pi"))
        plc_volume = parse_int(plc.get("volume_x10000_from_pi"))
        plc_payment = parse_int(plc.get("payment_status_from_pi"))
        plc_sequence = parse_int(plc.get("source_sequence_from_pi"))
        plc_valve_raw = parse_int(plc.get("observed_valve_raw_from_pi"))
        plc_node_id = parse_int(plc.get("node_id_from_pi"))
        plc_odo_processed = parse_int(plc.get("odo_meter_processed"))
        plc_process_state = parse_int(plc.get("process_state"))
        plc_valve_reason = parse_int(plc.get("valve_reason"))
        plc_valve_command = parse_bool(plc.get("valve_command"))
        plc_abnormal = parse_bool(plc.get("abnormal_usage"))
        plc_payment_blocked = parse_bool(plc.get("payment_blocked"))

        expected_flow_encoded = (
            round(original_flow * FLOW_RATE_SCALE)
            if original_flow is not None
            else None
        )
        expected_volume_encoded = (
            round(original_volume * VOLUME_SCALE)
            if original_volume is not None
            else None
        )

        source_logic = expected_controller_logic(
            sent_odo,
            sent_payment,
            abnormal_threshold,
        )
        plc_logic = expected_controller_logic(
            plc_odo,
            plc_payment,
            abnormal_threshold,
        )

        source_odo_match = compare_values(original_odo, sent_odo)
        source_flow_match = compare_values(expected_flow_encoded, sent_flow)
        source_volume_match = compare_values(expected_volume_encoded, sent_volume)
        source_payment_match = compare_values(original_payment, sent_payment)

        cross_odo_match = compare_values(sent_odo, plc_odo)
        cross_flow_match = compare_values(sent_flow, plc_flow)
        cross_volume_match = compare_values(sent_volume, plc_volume)
        cross_payment_match = compare_values(sent_payment, plc_payment)
        cross_sequence_match = compare_values(source_sequence, plc_sequence)
        cross_valve_feedback_match = compare_values(source_valve_raw, plc_valve_raw)
        cross_node_id_match = compare_values(source_node_id, plc_node_id)

        plc_internal_odo_match = compare_values(plc_odo, plc_odo_processed)
        plc_logic_abnormal_match = compare_values(
            plc_logic["abnormal_usage"], plc_abnormal
        )
        plc_logic_payment_match = compare_values(
            plc_logic["payment_blocked"], plc_payment_blocked
        )
        plc_logic_valve_match = compare_values(
            plc_logic["valve_command"], plc_valve_command
        )
        plc_logic_state_match = compare_values(
            plc_logic["process_state"], plc_process_state
        )
        plc_logic_reason_match = compare_values(
            plc_logic["valve_reason"], plc_valve_reason
        )

        source_expected_valve_match = compare_values(
            source_logic["valve_command"], plc_valve_command
        )

        source_checks = [
            source_odo_match,
            source_flow_match,
            source_volume_match,
            source_payment_match,
        ]
        cross_checks = [
            cross_odo_match,
            cross_flow_match,
            cross_volume_match,
            cross_payment_match,
            cross_sequence_match,
            cross_valve_feedback_match,
            cross_node_id_match,
        ]
        plc_logic_checks = [
            plc_internal_odo_match,
            plc_logic_abnormal_match,
            plc_logic_payment_match,
            plc_logic_valve_match,
            plc_logic_state_match,
            plc_logic_reason_match,
        ]

        def all_known_true(values: list[Optional[bool]]) -> Optional[bool]:
            known = [value for value in values if value is not None]
            if not known:
                return None
            if len(known) != len(values):
                return False
            return all(known)

        phase = normalise_phase(
            raspi.get("experiment_phase") or plc.get("experiment_phase")
        )

        record_time = row_timestamp(plc) or row_timestamp(raspi)
        is_observed_attack_value = (
            plc_odo == attack_value
            and sent_odo is not None
            and sent_odo != attack_value
        )
        controller_impact = (
            source_logic["valve_command"] is not None
            and plc_valve_command is not None
            and source_logic["valve_command"] != plc_valve_command
        )

        paired.append(
            {
                "scenario": label,
                "experiment_id": raspi.get("experiment_id") or plc.get("experiment_id"),
                "collector_session_id": raspi.get("collector_session_id")
                or plc.get("collector_session_id"),
                "collection_id": collection_id,
                "collection_sequence": parse_int(
                    raspi.get("collection_sequence") or plc.get("collection_sequence")
                ),
                "experiment_phase": phase,
                "record_timestamp_utc": format_datetime(record_time),
                "raspi_read_status": raspi.get("read_status") or "MISSING",
                "sender_send_status": raspi.get("send_status") or "MISSING",
                "openplc_read_status": plc.get("read_status") or "MISSING",
                "register_read_status": plc.get("register_read_status") or "MISSING",
                "coil_read_status": plc.get("coil_read_status") or "MISSING",
                "pair_complete": bool(raspi and plc),
                "source_sequence": source_sequence,
                "state_sequence": parse_int(raspi.get("state_sequence")),
                "source_mode": raspi.get("source_mode"),
                "thingsboard_timestamp_ms": parse_int(
                    raspi.get("thingsboard_timestamp_ms")
                ),
                "node_id_source": source_node_id,
                "node_id_openplc": plc_node_id,
                "original_odo_meter_litre": original_odo,
                "sent_odo_meter_litre": sent_odo,
                "openplc_odo_meter_litre": plc_odo,
                "odo_meter_processed": plc_odo_processed,
                "original_flow_rate_lpm": original_flow,
                "expected_flow_rate_x1000": expected_flow_encoded,
                "sent_flow_rate_x1000": sent_flow,
                "openplc_flow_rate_x1000": plc_flow,
                "openplc_flow_rate_lpm": (
                    round(plc_flow / FLOW_RATE_SCALE, 6)
                    if plc_flow is not None
                    else None
                ),
                "original_volume_litre": original_volume,
                "expected_volume_x10000": expected_volume_encoded,
                "sent_volume_x10000": sent_volume,
                "openplc_volume_x10000": plc_volume,
                "openplc_volume_litre": (
                    round(plc_volume / VOLUME_SCALE, 6)
                    if plc_volume is not None
                    else None
                ),
                "original_payment_status": original_payment,
                "sent_payment_status": sent_payment,
                "openplc_payment_status": plc_payment,
                "observed_valve_raw_source": source_valve_raw,
                "observed_valve_raw_openplc": plc_valve_raw,
                "openplc_source_sequence": plc_sequence,
                "process_state": plc_process_state,
                "valve_reason": plc_valve_reason,
                "valve_command": plc_valve_command,
                "abnormal_usage": plc_abnormal,
                "payment_blocked": plc_payment_blocked,
                "source_expected_valve_command": source_logic["valve_command"],
                "source_expected_process_state": source_logic["process_state"],
                "source_expected_valve_reason": source_logic["valve_reason"],
                "plc_expected_valve_command": plc_logic["valve_command"],
                "plc_expected_process_state": plc_logic["process_state"],
                "plc_expected_valve_reason": plc_logic["valve_reason"],
                "source_odo_encoding_match": source_odo_match,
                "source_flow_encoding_match": source_flow_match,
                "source_volume_encoding_match": source_volume_match,
                "source_payment_encoding_match": source_payment_match,
                "source_encoding_integrity_match": all_known_true(source_checks),
                "cross_layer_odo_match": cross_odo_match,
                "cross_layer_flow_match": cross_flow_match,
                "cross_layer_volume_match": cross_volume_match,
                "cross_layer_payment_match": cross_payment_match,
                "cross_layer_sequence_match": cross_sequence_match,
                "cross_layer_valve_feedback_match": cross_valve_feedback_match,
                "cross_layer_node_id_match": cross_node_id_match,
                "cross_layer_all_fields_match": all_known_true(cross_checks),
                "plc_internal_odo_match": plc_internal_odo_match,
                "plc_logic_abnormal_match": plc_logic_abnormal_match,
                "plc_logic_payment_match": plc_logic_payment_match,
                "plc_logic_valve_match": plc_logic_valve_match,
                "plc_logic_state_match": plc_logic_state_match,
                "plc_logic_reason_match": plc_logic_reason_match,
                "plc_logic_consistency_match": all_known_true(plc_logic_checks),
                "source_expected_valve_match": source_expected_valve_match,
                "controller_operational_impact": controller_impact,
                "observed_attack_value": is_observed_attack_value,
                "source_age_ms": parse_float(raspi.get("source_age_ms")),
                "sampling_skew_ms": parse_float(
                    raspi.get("sampling_skew_ms") or plc.get("sampling_skew_ms")
                ),
            }
        )

    return paired


# =========================================================
# LOAD SCENARIO
# =========================================================


def load_scenario(
    label: str,
    session_dir: Path,
    *,
    abnormal_threshold: int,
    target_register: int,
    attack_value: int,
    explicit_modbus_writes: Optional[Path] = None,
) -> ScenarioData:
    raspi_path = session_dir / "raw" / RASPI_FILE_NAME
    openplc_path = session_dir / "raw" / OPENPLC_FILE_NAME

    validate_headers(raspi_path, REQUIRED_RASPI_FIELDS)
    validate_headers(openplc_path, REQUIRED_OPENPLC_FIELDS)

    raspi_rows = read_csv(raspi_path)
    openplc_rows = read_csv(openplc_path)

    paired = build_paired_rows(
        label,
        raspi_rows,
        openplc_rows,
        abnormal_threshold=abnormal_threshold,
        attack_value=attack_value,
    )

    hash_rows = verify_input_hashes(
        session_dir,
        [raspi_path, openplc_path],
    )

    writes_path = explicit_modbus_writes or locate_optional_modbus_writes(session_dir)
    modbus_writes = load_modbus_writes(
        writes_path,
        target_register=target_register,
        attack_value=attack_value,
    )

    return ScenarioData(
        label=label,
        session_dir=session_dir,
        raspi_path=raspi_path,
        openplc_path=openplc_path,
        raspi_rows=raspi_rows,
        openplc_rows=openplc_rows,
        paired_rows=paired,
        input_hash_rows=hash_rows,
        modbus_writes=modbus_writes,
    )


# =========================================================
# AGREGASI METRIK
# =========================================================


def phases_for_rows(rows: list[dict[str, Any]]) -> list[str]:
    phases = sorted({normalise_phase(row.get("experiment_phase")) for row in rows})
    return ["ALL", *phases]


def rows_for_phase(
    rows: list[dict[str, Any]],
    phase: str,
) -> list[dict[str, Any]]:
    if phase == "ALL":
        return rows
    return [
        row
        for row in rows
        if normalise_phase(row.get("experiment_phase")) == phase
    ]


def metric_rate(
    rows: list[dict[str, Any]],
    field: str,
) -> tuple[int, int, Optional[float]]:
    values = [parse_bool(row.get(field)) for row in rows]
    known = [value for value in values if value is not None]
    passed = sum(value is True for value in known)
    return passed, len(known), safe_percentage(passed, len(known))


def build_integrity_summary(
    scenario: ScenarioData,
) -> list[dict[str, Any]]:
    metric_fields = {
        "source_odo_encoding_rate_pct": "source_odo_encoding_match",
        "source_flow_encoding_rate_pct": "source_flow_encoding_match",
        "source_volume_encoding_rate_pct": "source_volume_encoding_match",
        "source_payment_encoding_rate_pct": "source_payment_encoding_match",
        "source_encoding_all_fields_rate_pct": "source_encoding_integrity_match",
        "cross_layer_odo_rate_pct": "cross_layer_odo_match",
        "cross_layer_flow_rate_pct": "cross_layer_flow_match",
        "cross_layer_volume_rate_pct": "cross_layer_volume_match",
        "cross_layer_payment_rate_pct": "cross_layer_payment_match",
        "cross_layer_sequence_rate_pct": "cross_layer_sequence_match",
        "cross_layer_valve_feedback_rate_pct": "cross_layer_valve_feedback_match",
        "cross_layer_node_id_rate_pct": "cross_layer_node_id_match",
        "cross_layer_all_fields_rate_pct": "cross_layer_all_fields_match",
        "plc_internal_odo_rate_pct": "plc_internal_odo_match",
        "plc_logic_consistency_rate_pct": "plc_logic_consistency_match",
        "source_expected_valve_rate_pct": "source_expected_valve_match",
    }

    result: list[dict[str, Any]] = []
    for phase in phases_for_rows(scenario.paired_rows):
        subset = rows_for_phase(scenario.paired_rows, phase)
        row: dict[str, Any] = {
            "scenario": scenario.label,
            "phase": phase,
            "record_count": len(subset),
            "observed_attack_value_count": sum(
                parse_bool(item.get("observed_attack_value")) is True
                for item in subset
            ),
            "controller_operational_impact_count": sum(
                parse_bool(item.get("controller_operational_impact")) is True
                for item in subset
            ),
        }

        for output_name, field_name in metric_fields.items():
            passed, evaluated, rate = metric_rate(subset, field_name)
            row[output_name] = rate
            row[output_name.replace("_rate_pct", "_passed")] = passed
            row[output_name.replace("_rate_pct", "_evaluated")] = evaluated

        result.append(row)

    return result


def sequence_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(
        rows,
        key=lambda item: (
            parse_int(item.get("collection_sequence")) or 0,
            str(item.get("collection_id") or ""),
        ),
    )

    sequences = [
        parse_int(row.get("source_sequence"))
        for row in ordered
        if parse_int(row.get("source_sequence")) is not None
    ]

    duplicate_count = 0
    backward_count = 0
    gap_count = 0
    missing_sequence_values = 0

    previous: Optional[int] = None
    for current in sequences:
        if previous is None:
            previous = current
            continue

        if current == previous:
            duplicate_count += 1
        elif current < previous:
            backward_count += 1
        elif current > previous + 1:
            gap_count += 1
            missing_sequence_values += current - previous - 1

        previous = current

    return {
        "source_sequence_observation_count": len(sequences),
        "source_sequence_duplicate_observation_count": duplicate_count,
        "source_sequence_backward_count": backward_count,
        "source_sequence_gap_event_count": gap_count,
        "source_sequence_missing_value_count": missing_sequence_values,
        "source_sequence_unique_count": len(set(sequences)),
    }


def build_availability_summary(
    scenario: ScenarioData,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []

    for phase in phases_for_rows(scenario.paired_rows):
        subset = rows_for_phase(scenario.paired_rows, phase)
        total = len(subset)

        raspi_success = sum(
            str(row.get("raspi_read_status", "")).upper() == "SUCCESS"
            for row in subset
        )
        sender_success = sum(
            str(row.get("sender_send_status", "")).upper() == "SUCCESS"
            for row in subset
        )
        openplc_success = sum(
            str(row.get("openplc_read_status", "")).upper() == "SUCCESS"
            for row in subset
        )
        register_success = sum(
            str(row.get("register_read_status", "")).upper() == "SUCCESS"
            for row in subset
        )
        coil_success = sum(
            str(row.get("coil_read_status", "")).upper() == "SUCCESS"
            for row in subset
        )
        complete_pairs = sum(parse_bool(row.get("pair_complete")) is True for row in subset)

        source_age_values = [
            parse_float(row.get("source_age_ms"))
            for row in subset
            if parse_float(row.get("source_age_ms")) is not None
        ]
        skew_values = [
            parse_float(row.get("sampling_skew_ms"))
            for row in subset
            if parse_float(row.get("sampling_skew_ms")) is not None
        ]

        row = {
            "scenario": scenario.label,
            "phase": phase,
            "collection_cycle_count": total,
            "raspi_read_success_count": raspi_success,
            "raspi_read_availability_rate_pct": safe_percentage(raspi_success, total),
            "sender_send_success_count": sender_success,
            "sender_send_availability_rate_pct": safe_percentage(sender_success, total),
            "openplc_read_success_count": openplc_success,
            "openplc_read_availability_rate_pct": safe_percentage(openplc_success, total),
            "register_read_success_count": register_success,
            "register_read_availability_rate_pct": safe_percentage(register_success, total),
            "coil_read_success_count": coil_success,
            "coil_read_availability_rate_pct": safe_percentage(coil_success, total),
            "complete_pair_count": complete_pairs,
            "paired_collection_rate_pct": safe_percentage(complete_pairs, total),
            "mean_source_age_ms": (
                round(statistics.fmean(source_age_values), 3)
                if source_age_values
                else None
            ),
            "max_source_age_ms": max(source_age_values) if source_age_values else None,
            "mean_sampling_skew_ms": (
                round(statistics.fmean(skew_values), 3) if skew_values else None
            ),
            "max_sampling_skew_ms": max(skew_values) if skew_values else None,
        }
        row.update(sequence_metrics(subset))
        result.append(row)

    return result


def build_control_logic_summary(
    scenario: ScenarioData,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for phase in phases_for_rows(scenario.paired_rows):
        subset = rows_for_phase(scenario.paired_rows, phase)

        state_counts = Counter(
            parse_int(row.get("process_state"))
            for row in subset
            if parse_int(row.get("process_state")) is not None
        )
        reason_counts = Counter(
            parse_int(row.get("valve_reason"))
            for row in subset
            if parse_int(row.get("valve_reason")) is not None
        )
        valve_open = sum(parse_bool(row.get("valve_command")) is True for row in subset)
        valve_closed = sum(parse_bool(row.get("valve_command")) is False for row in subset)
        abnormal = sum(parse_bool(row.get("abnormal_usage")) is True for row in subset)
        payment_blocked = sum(
            parse_bool(row.get("payment_blocked")) is True for row in subset
        )
        impact = sum(
            parse_bool(row.get("controller_operational_impact")) is True
            for row in subset
        )

        logic_passed, logic_evaluated, logic_rate = metric_rate(
            subset, "plc_logic_consistency_match"
        )
        source_valve_passed, source_valve_evaluated, source_valve_rate = metric_rate(
            subset, "source_expected_valve_match"
        )

        result.append(
            {
                "scenario": scenario.label,
                "phase": phase,
                "record_count": len(subset),
                "valve_open_count": valve_open,
                "valve_closed_count": valve_closed,
                "abnormal_usage_true_count": abnormal,
                "payment_blocked_true_count": payment_blocked,
                "process_state_1_normal_count": state_counts.get(1, 0),
                "process_state_2_unpaid_count": state_counts.get(2, 0),
                "process_state_3_abnormal_count": state_counts.get(3, 0),
                "valve_reason_0_none_count": reason_counts.get(0, 0),
                "valve_reason_1_unpaid_count": reason_counts.get(1, 0),
                "valve_reason_2_abnormal_count": reason_counts.get(2, 0),
                "plc_logic_consistency_passed": logic_passed,
                "plc_logic_consistency_evaluated": logic_evaluated,
                "plc_logic_consistency_rate_pct": logic_rate,
                "source_expected_valve_passed": source_valve_passed,
                "source_expected_valve_evaluated": source_valve_evaluated,
                "source_expected_valve_rate_pct": source_valve_rate,
                "controller_operational_impact_count": impact,
                "controller_operational_impact_rate_pct": safe_percentage(
                    impact, len(subset)
                ),
            }
        )

    return result


# =========================================================
# ATTACK DAN RECOVERY
# =========================================================


def build_attack_observations(
    treatment: ScenarioData,
    *,
    target_register: int,
    attack_value: int,
    correlation_window_seconds: float,
) -> list[dict[str, Any]]:
    writes = treatment.modbus_writes
    result: list[dict[str, Any]] = []

    for row in treatment.paired_rows:
        if parse_bool(row.get("observed_attack_value")) is not True:
            continue

        observation_time = parse_datetime(row.get("record_timestamp_utc"))
        nearest: Optional[dict[str, Any]] = None
        nearest_delta: Optional[float] = None

        if observation_time is not None:
            for write in writes:
                write_time = write.get("timestamp")
                if not isinstance(write_time, datetime):
                    continue
                delta = (observation_time - write_time).total_seconds()
                if delta < 0:
                    continue
                if nearest_delta is None or delta < nearest_delta:
                    nearest = write
                    nearest_delta = delta

        network_correlated = (
            nearest is not None
            and nearest_delta is not None
            and nearest_delta <= correlation_window_seconds
        )

        result.append(
            {
                "scenario": treatment.label,
                "collection_id": row.get("collection_id"),
                "collection_sequence": row.get("collection_sequence"),
                "experiment_phase": row.get("experiment_phase"),
                "observation_timestamp_utc": row.get("record_timestamp_utc"),
                "target_register": target_register,
                "configured_attack_value": attack_value,
                "source_sent_odo_meter_litre": row.get("sent_odo_meter_litre"),
                "openplc_odo_meter_litre": row.get("openplc_odo_meter_litre"),
                "openplc_odo_meter_processed": row.get("odo_meter_processed"),
                "cross_layer_odo_match": row.get("cross_layer_odo_match"),
                "process_state": row.get("process_state"),
                "valve_reason": row.get("valve_reason"),
                "valve_command": row.get("valve_command"),
                "abnormal_usage": row.get("abnormal_usage"),
                "payment_blocked": row.get("payment_blocked"),
                "source_expected_valve_command": row.get(
                    "source_expected_valve_command"
                ),
                "controller_operational_impact": row.get(
                    "controller_operational_impact"
                ),
                "nearest_network_write_timestamp_utc": (
                    nearest.get("timestamp_utc") if nearest else None
                ),
                "network_to_control_delay_seconds": nearest_delta,
                "network_correlation_status": (
                    "CORRELATED"
                    if network_correlated
                    else "NETWORK_EVIDENCE_NOT_AVAILABLE_OR_OUTSIDE_WINDOW"
                ),
                "evidence_interpretation": (
                    "SOURCE_NORMAL_TO_NETWORK_WRITE_TO_OPENPLC_FALSE_VALUE"
                    if network_correlated
                    else "SOURCE_OPENPLC_MISMATCH_WITH_ATTACK_VALUE_OBSERVED"
                ),
            }
        )

    return result


def stable_recovery_metrics(
    treatment: ScenarioData,
    *,
    attack_value: int,
    stable_records: int,
) -> dict[str, Any]:
    ordered = sorted(
        treatment.paired_rows,
        key=lambda row: (
            row_timestamp(row)
            or datetime.min.replace(tzinfo=timezone.utc),
            parse_int(row.get("collection_sequence")) or 0,
        ),
    )

    attack_rows = [
        row
        for row in ordered
        if parse_bool(row.get("observed_attack_value")) is True
    ]

    first_attack_time = row_timestamp(attack_rows[0]) if attack_rows else None
    last_attack_time = row_timestamp(attack_rows[-1]) if attack_rows else None

    first_normal_row: Optional[dict[str, Any]] = None
    stable_start_row: Optional[dict[str, Any]] = None
    stable_confirm_row: Optional[dict[str, Any]] = None

    if last_attack_time is not None:
        after = [
            row
            for row in ordered
            if (row_timestamp(row) or datetime.min.replace(tzinfo=timezone.utc))
            > last_attack_time
        ]

        for row in after:
            normal = (
                parse_bool(row.get("cross_layer_odo_match")) is True
                and parse_int(row.get("openplc_odo_meter_litre")) != attack_value
                and parse_bool(row.get("source_expected_valve_match")) is True
                and parse_bool(row.get("plc_logic_consistency_match")) is True
            )
            if normal:
                first_normal_row = row
                break

        consecutive: list[dict[str, Any]] = []
        for row in after:
            normal = (
                parse_bool(row.get("cross_layer_odo_match")) is True
                and parse_int(row.get("openplc_odo_meter_litre")) != attack_value
                and parse_bool(row.get("source_expected_valve_match")) is True
                and parse_bool(row.get("plc_logic_consistency_match")) is True
            )
            if normal:
                consecutive.append(row)
                if len(consecutive) >= stable_records:
                    stable_start_row = consecutive[0]
                    stable_confirm_row = consecutive[-1]
                    break
            else:
                consecutive.clear()

    first_normal_time = row_timestamp(first_normal_row or {})
    stable_start_time = row_timestamp(stable_start_row or {})
    stable_confirm_time = row_timestamp(stable_confirm_row or {})

    network_times = [
        item.get("timestamp")
        for item in treatment.modbus_writes
        if isinstance(item.get("timestamp"), datetime)
    ]
    first_network_write = min(network_times) if network_times else None
    last_network_write = max(network_times) if network_times else None

    def delta(later: Optional[datetime], earlier: Optional[datetime]) -> Optional[float]:
        if later is None or earlier is None:
            return None
        return round((later - earlier).total_seconds(), 3)

    return {
        "scenario": treatment.label,
        "configured_attack_value": attack_value,
        "attack_observation_count": len(attack_rows),
        "first_network_write_utc": format_datetime(first_network_write),
        "last_network_write_utc": format_datetime(last_network_write),
        "first_attack_value_observed_utc": format_datetime(first_attack_time),
        "last_attack_value_observed_utc": format_datetime(last_attack_time),
        "first_normal_observation_utc": format_datetime(first_normal_time),
        "stable_recovery_start_utc": format_datetime(stable_start_time),
        "stable_recovery_confirmed_utc": format_datetime(stable_confirm_time),
        "network_to_first_attack_observation_seconds": delta(
            first_attack_time, first_network_write
        ),
        "last_network_write_to_first_normal_seconds": delta(
            first_normal_time, last_network_write
        ),
        "last_attack_observation_to_first_normal_seconds": delta(
            first_normal_time, last_attack_time
        ),
        "last_network_write_to_stable_confirmation_seconds": delta(
            stable_confirm_time, last_network_write
        ),
        "last_attack_observation_to_stable_confirmation_seconds": delta(
            stable_confirm_time, last_attack_time
        ),
        "stable_record_requirement": stable_records,
        "network_evidence_available": bool(network_times),
    }


# =========================================================
# COMPARISON DAN FINDINGS
# =========================================================


def all_phase_row(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return next((row for row in rows if row.get("phase") == "ALL"), {})


def build_comparison(
    baseline_integrity: list[dict[str, Any]],
    baseline_availability: list[dict[str, Any]],
    baseline_control: list[dict[str, Any]],
    treatment_integrity: Optional[list[dict[str, Any]]],
    treatment_availability: Optional[list[dict[str, Any]]],
    treatment_control: Optional[list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    bi = all_phase_row(baseline_integrity)
    ba = all_phase_row(baseline_availability)
    bc = all_phase_row(baseline_control)

    ti = all_phase_row(treatment_integrity or [])
    ta = all_phase_row(treatment_availability or [])
    tc = all_phase_row(treatment_control or [])

    metrics = [
        (
            "Source encoding integrity - all fields",
            bi.get("source_encoding_all_fields_rate_pct"),
            ti.get("source_encoding_all_fields_rate_pct"),
            "%",
        ),
        (
            "Cross-layer ODO integrity",
            bi.get("cross_layer_odo_rate_pct"),
            ti.get("cross_layer_odo_rate_pct"),
            "%",
        ),
        (
            "Cross-layer all-fields integrity",
            bi.get("cross_layer_all_fields_rate_pct"),
            ti.get("cross_layer_all_fields_rate_pct"),
            "%",
        ),
        (
            "PLC internal ODO consistency",
            bi.get("plc_internal_odo_rate_pct"),
            ti.get("plc_internal_odo_rate_pct"),
            "%",
        ),
        (
            "PLC controller logic consistency",
            bc.get("plc_logic_consistency_rate_pct"),
            tc.get("plc_logic_consistency_rate_pct"),
            "%",
        ),
        (
            "Valve output match against legitimate source",
            bc.get("source_expected_valve_rate_pct"),
            tc.get("source_expected_valve_rate_pct"),
            "%",
        ),
        (
            "Raspberry Pi acquisition availability",
            ba.get("raspi_read_availability_rate_pct"),
            ta.get("raspi_read_availability_rate_pct"),
            "%",
        ),
        (
            "OpenPLC acquisition availability",
            ba.get("openplc_read_availability_rate_pct"),
            ta.get("openplc_read_availability_rate_pct"),
            "%",
        ),
        (
            "Paired collection rate",
            ba.get("paired_collection_rate_pct"),
            ta.get("paired_collection_rate_pct"),
            "%",
        ),
        (
            "Observed controller impact records",
            bc.get("controller_operational_impact_count"),
            tc.get("controller_operational_impact_count"),
            "records",
        ),
    ]

    result: list[dict[str, Any]] = []
    for name, baseline_value, treatment_value, unit in metrics:
        delta = None
        baseline_number = parse_float(baseline_value)
        treatment_number = parse_float(treatment_value)
        if baseline_number is not None and treatment_number is not None:
            delta = round(treatment_number - baseline_number, 3)

        result.append(
            {
                "metric": name,
                "baseline_value": baseline_value,
                "treatment_value": treatment_value,
                "treatment_minus_baseline": delta,
                "unit": unit,
            }
        )

    return result


def build_timeline(
    baseline: ScenarioData,
    treatment: Optional[ScenarioData],
    attack_observations: list[dict[str, Any]],
    recovery: Optional[dict[str, Any]],
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    for scenario in [baseline, treatment] if treatment else [baseline]:
        if scenario is None or not scenario.paired_rows:
            continue

        times = [row_timestamp(row) for row in scenario.paired_rows]
        valid_times = [value for value in times if value is not None]
        if valid_times:
            events.append(
                {
                    "timestamp_utc": format_datetime(min(valid_times)),
                    "scenario": scenario.label,
                    "event_type": "COLLECTION_STARTED",
                    "layer": "collector",
                    "description": f"First paired evidence record for {scenario.label}.",
                }
            )
            events.append(
                {
                    "timestamp_utc": format_datetime(max(valid_times)),
                    "scenario": scenario.label,
                    "event_type": "COLLECTION_ENDED",
                    "layer": "collector",
                    "description": f"Last paired evidence record for {scenario.label}.",
                }
            )

    if treatment is not None:
        # Record phase transitions once so the report remains concise.
        previous_phase: Optional[str] = None
        ordered_treatment_rows = sorted(
            treatment.paired_rows,
            key=lambda row: (
                row_timestamp(row)
                or datetime.max.replace(tzinfo=timezone.utc),
                parse_int(row.get("collection_sequence")) or 0,
            ),
        )
        for row in ordered_treatment_rows:
            phase = normalise_phase(row.get("experiment_phase"))
            if phase != previous_phase:
                events.append(
                    {
                        "timestamp_utc": format_datetime(row_timestamp(row)),
                        "scenario": treatment.label,
                        "event_type": f"PHASE_{phase}",
                        "layer": "collector",
                        "description": f"First paired record classified as phase {phase}.",
                    }
                )
                previous_phase = phase

        # The complete write list remains in network_write_events_used.csv.
        # The final timeline includes only the first and last configured writes.
        if treatment.modbus_writes:
            first_write = treatment.modbus_writes[0]
            last_write = treatment.modbus_writes[-1]
            for event_type, write in [
                ("FIRST_CONFIGURED_MODBUS_WRITE", first_write),
                ("LAST_CONFIGURED_MODBUS_WRITE", last_write),
            ]:
                if (
                    event_type == "LAST_CONFIGURED_MODBUS_WRITE"
                    and last_write is first_write
                ):
                    continue
                events.append(
                    {
                        "timestamp_utc": write.get("timestamp_utc"),
                        "scenario": treatment.label,
                        "event_type": event_type,
                        "layer": "network",
                        "description": (
                            f"Modbus write to HR{write.get('register_address')}="
                            f"{write.get('register_value')}."
                        ),
                    }
                )

        if attack_observations:
            first = attack_observations[0]
            last = attack_observations[-1]
            events.append(
                {
                    "timestamp_utc": first.get("observation_timestamp_utc"),
                    "scenario": treatment.label,
                    "event_type": "FIRST_ATTACK_VALUE_OBSERVED",
                    "layer": "openplc",
                    "description": (
                        "First cross-layer ODO mismatch with configured attack value; "
                        "controller entered abnormal-usage path."
                    ),
                }
            )
            events.append(
                {
                    "timestamp_utc": last.get("observation_timestamp_utc"),
                    "scenario": treatment.label,
                    "event_type": "LAST_ATTACK_VALUE_OBSERVED",
                    "layer": "openplc",
                    "description": "Last observed configured attack value at OpenPLC.",
                }
            )

        if recovery:
            for field, event_type, description in [
                (
                    "first_normal_observation_utc",
                    "FIRST_NORMAL_OBSERVATION",
                    "First normal cross-layer ODO and valve observation after attack.",
                ),
                (
                    "stable_recovery_confirmed_utc",
                    "STABLE_RECOVERY_CONFIRMED",
                    "Configured number of consecutive normal records reached.",
                ),
            ]:
                if recovery.get(field):
                    events.append(
                        {
                            "timestamp_utc": recovery.get(field),
                            "scenario": treatment.label,
                            "event_type": event_type,
                            "layer": "cross_layer",
                            "description": description,
                        }
                    )

    events.sort(
        key=lambda item: parse_datetime(item.get("timestamp_utc"))
        or datetime.max.replace(tzinfo=timezone.utc)
    )
    return events


def build_findings(
    baseline: ScenarioData,
    baseline_integrity: list[dict[str, Any]],
    baseline_availability: list[dict[str, Any]],
    baseline_control: list[dict[str, Any]],
    treatment: Optional[ScenarioData],
    treatment_integrity: Optional[list[dict[str, Any]]],
    treatment_availability: Optional[list[dict[str, Any]]],
    treatment_control: Optional[list[dict[str, Any]]],
    attack_observations: list[dict[str, Any]],
    recovery: Optional[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    bi = all_phase_row(baseline_integrity)
    ba = all_phase_row(baseline_availability)
    bc = all_phase_row(baseline_control)

    findings.append(
        {
            "finding_id": "F-BASELINE-01",
            "severity": "INFORMATIONAL",
            "title": "Baseline cross-layer integrity",
            "statement": (
                "Baseline cross-layer ODO integrity rate was "
                f"{format_percent(bi.get('cross_layer_odo_rate_pct'))}; "
                "all-fields cross-layer rate was "
                f"{format_percent(bi.get('cross_layer_all_fields_rate_pct'))}."
            ),
            "evidence": [str(baseline.raspi_path), str(baseline.openplc_path)],
        }
    )
    findings.append(
        {
            "finding_id": "F-BASELINE-02",
            "severity": "INFORMATIONAL",
            "title": "Baseline acquisition availability",
            "statement": (
                "Raspberry Pi read availability was "
                f"{format_percent(ba.get('raspi_read_availability_rate_pct'))} "
                "and OpenPLC read availability was "
                f"{format_percent(ba.get('openplc_read_availability_rate_pct'))}."
            ),
            "evidence": [str(baseline.raspi_path), str(baseline.openplc_path)],
        }
    )
    findings.append(
        {
            "finding_id": "F-BASELINE-03",
            "severity": "INFORMATIONAL",
            "title": "Baseline controller behaviour",
            "statement": (
                "OpenPLC logic consistency rate was "
                f"{format_percent(bc.get('plc_logic_consistency_rate_pct'))}; "
                "valve output agreement with the legitimate source was "
                f"{format_percent(bc.get('source_expected_valve_rate_pct'))}."
            ),
            "evidence": [str(baseline.openplc_path)],
        }
    )

    if treatment is None:
        return findings

    ti = all_phase_row(treatment_integrity or [])
    ta = all_phase_row(treatment_availability or [])
    tc = all_phase_row(treatment_control or [])

    if attack_observations:
        network_status = (
            "Network write events were available and correlated."
            if treatment.modbus_writes
            else (
                "Network write events were not available; attribution is limited "
                "to source-to-OpenPLC mismatch and controller observations."
            )
        )
        findings.append(
            {
                "finding_id": "F-P1-01",
                "severity": "HIGH",
                "title": "ODO Meter cross-layer integrity violation",
                "statement": (
                    f"{len(attack_observations)} record(s) showed OpenPLC ODO Meter "
                    "equal to the configured attack value while the Raspberry Pi "
                    "source sent a different legitimate value. "
                    + network_status
                ),
                "evidence": [
                    "attack_observations.csv",
                    str(treatment.raspi_path),
                    str(treatment.openplc_path),
                ],
            }
        )

    findings.append(
        {
            "finding_id": "F-P1-02",
            "severity": "MEDIUM" if attack_observations else "INFORMATIONAL",
            "title": "Controller impact on valve output",
            "statement": (
                f"Controller operational impact was observed in "
                f"{tc.get('controller_operational_impact_count', 0)} record(s). "
                "This metric compares the actual valve output with the output "
                "expected from the legitimate Raspberry Pi source."
            ),
            "evidence": ["control_logic_analysis.csv", "paired_cross_layer_analysis.csv"],
        }
    )

    findings.append(
        {
            "finding_id": "F-P1-03",
            "severity": "INFORMATIONAL",
            "title": "OpenPLC controller logic remained internally consistent",
            "statement": (
                "PLC logic consistency was "
                f"{format_percent(tc.get('plc_logic_consistency_rate_pct'))}. "
                "A high rate means OpenPLC correctly applied its control rules to "
                "the value it received, even when that value differed from the "
                "legitimate source."
            ),
            "evidence": ["control_logic_analysis.csv"],
        }
    )

    findings.append(
        {
            "finding_id": "F-P1-04",
            "severity": "INFORMATIONAL",
            "title": "Acquisition availability during treatment",
            "statement": (
                "Raspberry Pi read availability was "
                f"{format_percent(ta.get('raspi_read_availability_rate_pct'))}; "
                "OpenPLC read availability was "
                f"{format_percent(ta.get('openplc_read_availability_rate_pct'))}. "
                "Availability of acquisition can remain high while process-data "
                "integrity is violated."
            ),
            "evidence": ["availability_analysis.csv"],
        }
    )

    if recovery and recovery.get("stable_recovery_confirmed_utc"):
        findings.append(
            {
                "finding_id": "F-P1-05",
                "severity": "INFORMATIONAL",
                "title": "Stable recovery observed",
                "statement": (
                    "Stable recovery was confirmed at "
                    f"{recovery.get('stable_recovery_confirmed_utc')} after "
                    f"{recovery.get('stable_record_requirement')} consecutive "
                    "normal records."
                ),
                "evidence": ["recovery_analysis.csv", "final_incident_timeline.csv"],
            }
        )

    return findings


# =========================================================
# REPORT
# =========================================================


def build_report_markdown(
    *,
    operator: str,
    run_id: str,
    baseline: ScenarioData,
    treatment: Optional[ScenarioData],
    integrity_rows: list[dict[str, Any]],
    availability_rows: list[dict[str, Any]],
    control_rows: list[dict[str, Any]],
    comparison_rows: list[dict[str, Any]],
    attack_observations: list[dict[str, Any]],
    recovery: Optional[dict[str, Any]],
    findings: list[dict[str, Any]],
    limitations: list[str],
    timeline: list[dict[str, Any]],
    target_register: int,
    attack_value: int,
) -> str:
    baseline_integrity = all_phase_row(
        [row for row in integrity_rows if row.get("scenario") == "BASELINE"]
    )
    treatment_integrity = all_phase_row(
        [row for row in integrity_rows if row.get("scenario") != "BASELINE"]
    )

    lines = [
        "# Cross-Layer DFIR Analysis — PAMSIMAS ThingsBoard–Raspberry Pi–OpenPLC",
        "",
        f"**Analysis run:** `{run_id}`  ",
        f"**Operator:** `{operator}`  ",
        f"**Generated:** `{utc_now()}`",
        "",
        "## Scope",
        "",
        "This report analyses source encoding, Raspberry Pi–OpenPLC cross-layer "
        "integrity, OpenPLC control logic, valve impact, and acquisition availability.",
        "",
        f"Baseline session: `{baseline.session_dir}`",
    ]

    if treatment is not None:
        lines.append(f"Treatment session: `{treatment.session_dir}`")

    lines.extend(
        [
            "",
            "## Operational definitions",
            "",
            "- **Source encoding integrity:** original telemetry equals the encoded value sent by Raspberry Pi.",
            "- **Cross-layer integrity:** Raspberry Pi sent value equals OpenPLC received value.",
            "- **PLC logic consistency:** OpenPLC output matches the control rule for the value received by OpenPLC.",
            "- **Controller impact:** actual valve output differs from the output expected from the legitimate Raspberry Pi source.",
            "- **Acquisition availability:** collector read/send/pair success; this is not automatically full physical-process availability.",
            "",
            "## Main metrics",
            "",
            f"- Baseline source encoding integrity: **{format_percent(baseline_integrity.get('source_encoding_all_fields_rate_pct'))}**.",
            f"- Baseline cross-layer ODO integrity: **{format_percent(baseline_integrity.get('cross_layer_odo_rate_pct'))}**.",
        ]
    )

    if treatment is not None:
        lines.extend(
            [
                f"- Treatment source encoding integrity: **{format_percent(treatment_integrity.get('source_encoding_all_fields_rate_pct'))}**.",
                f"- Treatment cross-layer ODO integrity: **{format_percent(treatment_integrity.get('cross_layer_odo_rate_pct'))}**.",
                f"- Observed HR{target_register} attack-value records (`{attack_value}`): **{len(attack_observations)}**.",
                f"- Network write evidence available: **{'YES' if treatment.modbus_writes else 'NO'}**.",
            ]
        )

    lines.extend(
        [
            "",
            "## Integrity by phase",
            "",
            markdown_table(
                [
                    "Scenario",
                    "Phase",
                    "Records",
                    "Source all fields",
                    "Cross ODO",
                    "Cross all fields",
                    "PLC logic",
                    "Impact records",
                ],
                [
                    [
                        row.get("scenario"),
                        row.get("phase"),
                        row.get("record_count"),
                        format_percent(row.get("source_encoding_all_fields_rate_pct")),
                        format_percent(row.get("cross_layer_odo_rate_pct")),
                        format_percent(row.get("cross_layer_all_fields_rate_pct")),
                        format_percent(row.get("plc_logic_consistency_rate_pct")),
                        row.get("controller_operational_impact_count"),
                    ]
                    for row in integrity_rows
                ],
            ),
            "",
            "## Availability by phase",
            "",
            markdown_table(
                [
                    "Scenario",
                    "Phase",
                    "Cycles",
                    "Raspi read",
                    "Sender send",
                    "OpenPLC read",
                    "Paired",
                    "Seq gaps",
                    "Seq backwards",
                ],
                [
                    [
                        row.get("scenario"),
                        row.get("phase"),
                        row.get("collection_cycle_count"),
                        format_percent(row.get("raspi_read_availability_rate_pct")),
                        format_percent(row.get("sender_send_availability_rate_pct")),
                        format_percent(row.get("openplc_read_availability_rate_pct")),
                        format_percent(row.get("paired_collection_rate_pct")),
                        row.get("source_sequence_gap_event_count"),
                        row.get("source_sequence_backward_count"),
                    ]
                    for row in availability_rows
                ],
            ),
            "",
            "## Controller logic by phase",
            "",
            markdown_table(
                [
                    "Scenario",
                    "Phase",
                    "Valve open",
                    "Valve closed",
                    "Abnormal",
                    "Unpaid",
                    "PLC logic rate",
                    "Source-expected valve rate",
                    "Impact",
                ],
                [
                    [
                        row.get("scenario"),
                        row.get("phase"),
                        row.get("valve_open_count"),
                        row.get("valve_closed_count"),
                        row.get("abnormal_usage_true_count"),
                        row.get("payment_blocked_true_count"),
                        format_percent(row.get("plc_logic_consistency_rate_pct")),
                        format_percent(row.get("source_expected_valve_rate_pct")),
                        row.get("controller_operational_impact_count"),
                    ]
                    for row in control_rows
                ],
            ),
        ]
    )

    if treatment is not None:
        lines.extend(
            [
                "",
                "## Baseline vs treatment",
                "",
                markdown_table(
                    ["Metric", "Baseline", "Treatment", "Delta", "Unit"],
                    [
                        [
                            row.get("metric"),
                            row.get("baseline_value"),
                            row.get("treatment_value"),
                            row.get("treatment_minus_baseline"),
                            row.get("unit"),
                        ]
                        for row in comparison_rows
                    ],
                ),
                "",
                "## Attack and recovery",
                "",
                f"Configured target: `HR{target_register}={attack_value}`.",
                "",
                (
                    "Network write evidence was found and used for correlation."
                    if treatment.modbus_writes
                    else (
                        "No parsed network write evidence was found. Results identify "
                        "source-to-OpenPLC mismatch and controller impact, but do not "
                        "independently confirm the Modbus function code."
                    )
                ),
            ]
        )

        if recovery:
            lines.extend(
                [
                    "",
                    markdown_table(
                        ["Recovery metric", "Value"],
                        [
                            ["Attack observations", recovery.get("attack_observation_count")],
                            ["First network write", recovery.get("first_network_write_utc")],
                            ["First attack value observed", recovery.get("first_attack_value_observed_utc")],
                            ["Last attack value observed", recovery.get("last_attack_value_observed_utc")],
                            ["First normal observation", recovery.get("first_normal_observation_utc")],
                            ["Stable recovery confirmed", recovery.get("stable_recovery_confirmed_utc")],
                            [
                                "Last attack observation to stable confirmation",
                                format_number(
                                    recovery.get(
                                        "last_attack_observation_to_stable_confirmation_seconds"
                                    )
                                )
                                + " s",
                            ],
                        ],
                    ),
                ]
            )

    lines.extend(["", "## Findings", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {finding.get('finding_id')} — {finding.get('title')}",
                "",
                f"**Severity:** `{finding.get('severity')}`",
                "",
                str(finding.get("statement")),
            ]
        )
        evidence_files = finding.get("evidence") or []
        if evidence_files:
            lines.extend(
                [
                    "",
                    "**Evidence:** " + ", ".join(f"`{item}`" for item in evidence_files),
                ]
            )
        lines.append("")

    if timeline:
        lines.extend(
            [
                "## Significant incident timeline",
                "",
                markdown_table(
                    ["UTC", "Scenario", "Layer", "Event", "Description"],
                    [
                        [
                            row.get("timestamp_utc"),
                            row.get("scenario"),
                            row.get("layer"),
                            row.get("event_type"),
                            row.get("description"),
                        ]
                        for row in timeline
                    ],
                ),
                "",
            ]
        )

    lines.extend(["## Limitations", ""])
    for limitation in limitations:
        lines.append(f"- {limitation}")

    lines.extend(
        [
            "",
            "## Claim boundary",
            "",
            "The conclusions apply to the evaluated laboratory testbed, input files, "
            "register mapping, controller logic, and experiment windows. They do not "
            "constitute universal validation for every PAMSIMAS or OT deployment.",
            "",
        ]
    )

    return "\n".join(lines)


def markdown_to_html(markdown_text: str, title: str) -> str:
    """
    Render subset Markdown yang digunakan report menjadi HTML semantik.

    Mendukung heading, paragraf, bold, inline code, unordered list, dan
    tabel Markdown tanpa dependency eksternal. Berbeda dari implementasi
    lama, laporan tidak lagi dibungkus seluruhnya di dalam elemen <pre>.
    """

    def inline_markup(value: str) -> str:
        escaped = html.escape(value.strip())
        escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
        escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
        return escaped

    def split_table_row(value: str) -> list[str]:
        stripped = value.strip().strip("|")
        return [cell.strip() for cell in stripped.split("|")]

    def is_separator_row(value: str) -> bool:
        cells = split_table_row(value)
        return bool(cells) and all(
            re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) is not None
            for cell in cells
        )

    lines = markdown_text.splitlines()
    body: list[str] = []
    index = 0
    list_open = False

    def close_list() -> None:
        nonlocal list_open
        if list_open:
            body.append("</ul>")
            list_open = False

    while index < len(lines):
        line = lines[index]
        stripped = line.strip()

        if not stripped:
            close_list()
            index += 1
            continue

        # Markdown table: header, separator, followed by zero or more rows.
        if (
            stripped.startswith("|")
            and stripped.endswith("|")
            and index + 1 < len(lines)
            and is_separator_row(lines[index + 1])
        ):
            close_list()
            headers = split_table_row(stripped)
            index += 2
            rows: list[list[str]] = []
            while index < len(lines):
                candidate = lines[index].strip()
                if not (candidate.startswith("|") and candidate.endswith("|")):
                    break
                rows.append(split_table_row(candidate))
                index += 1

            body.append('<div class="table-wrap"><table>')
            body.append(
                "<thead><tr>"
                + "".join(f"<th>{inline_markup(cell)}</th>" for cell in headers)
                + "</tr></thead>"
            )
            body.append("<tbody>")
            for row in rows:
                padded = row + [""] * max(0, len(headers) - len(row))
                body.append(
                    "<tr>"
                    + "".join(
                        f"<td>{inline_markup(cell)}</td>"
                        for cell in padded[: len(headers)]
                    )
                    + "</tr>"
                )
            body.append("</tbody></table></div>")
            continue

        heading_match = re.match(r"^(#{1,3})\s+(.+)$", stripped)
        if heading_match:
            close_list()
            level = len(heading_match.group(1))
            body.append(
                f"<h{level}>{inline_markup(heading_match.group(2))}</h{level}>"
            )
            index += 1
            continue

        if stripped.startswith("- "):
            if not list_open:
                body.append("<ul>")
                list_open = True
            body.append(f"<li>{inline_markup(stripped[2:])}</li>")
            index += 1
            continue

        close_list()

        # Join adjacent ordinary lines into one readable paragraph.
        paragraph_parts = [stripped.rstrip()]
        index += 1
        while index < len(lines):
            candidate = lines[index].strip()
            if (
                not candidate
                or candidate.startswith("#")
                or candidate.startswith("- ")
                or (
                    candidate.startswith("|")
                    and candidate.endswith("|")
                )
            ):
                break
            paragraph_parts.append(candidate.rstrip())
            index += 1

        paragraph = " ".join(part.removesuffix("  ") for part in paragraph_parts)
        body.append(f"<p>{inline_markup(paragraph)}</p>")

    close_list()

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{
  color-scheme: light;
  --text: #1f2937;
  --muted: #4b5563;
  --line: #d1d5db;
  --head: #f3f4f6;
  --accent: #1d4ed8;
}}
* {{ box-sizing: border-box; }}
body {{
  font-family: Arial, Helvetica, sans-serif;
  max-width: 1180px;
  margin: 36px auto;
  padding: 0 24px 48px;
  line-height: 1.58;
  color: var(--text);
  background: #ffffff;
}}
h1 {{
  color: #111827;
  border-bottom: 3px solid var(--accent);
  padding-bottom: 12px;
  margin-bottom: 28px;
}}
h2 {{
  color: #111827;
  margin-top: 34px;
  padding-bottom: 7px;
  border-bottom: 1px solid var(--line);
}}
h3 {{ color: #111827; margin-top: 25px; }}
p {{ margin: 10px 0; }}
ul {{ margin: 10px 0 18px 22px; padding: 0; }}
li {{ margin: 6px 0; }}
code {{
  background: #f3f4f6;
  border: 1px solid #e5e7eb;
  border-radius: 4px;
  padding: 1px 5px;
  font-family: Consolas, "Courier New", monospace;
  font-size: 0.94em;
}}
.table-wrap {{
  width: 100%;
  overflow-x: auto;
  margin: 14px 0 28px;
}}
table {{
  border-collapse: collapse;
  width: 100%;
  min-width: 720px;
}}
th, td {{
  border: 1px solid var(--line);
  padding: 9px 10px;
  text-align: left;
  vertical-align: top;
}}
th {{
  background: var(--head);
  color: #111827;
  position: sticky;
  top: 0;
}}
tbody tr:nth-child(even) {{ background: #fafafa; }}
strong {{ color: #111827; }}
@media print {{
  body {{ max-width: none; margin: 0; padding: 0; }}
  .table-wrap {{ overflow: visible; }}
  table {{ min-width: 0; font-size: 9pt; }}
  h2 {{ break-after: avoid; }}
  tr {{ break-inside: avoid; }}
}}
</style>
</head>
<body>
<main>
{chr(10).join(body)}
</main>
</body>
</html>
"""


# =========================================================
# MANIFEST OUTPUT
# =========================================================


def build_output_manifest(output_dir: Path, manifest_path: Path) -> None:
    rows: list[dict[str, Any]] = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file() or path.resolve() == manifest_path.resolve():
            continue
        rows.append(
            {
                "relative_path": str(path.relative_to(output_dir)).replace("\\", "/"),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
                "hashed_at_utc": utc_now(),
            }
        )
    write_csv(manifest_path, rows)


# =========================================================
# MAIN ANALYSIS
# =========================================================


def run_analysis(args: argparse.Namespace) -> Path:
    started_at = utc_now()
    run_id = create_run_id()

    baseline_dir = resolve_session_path(
        args.baseline_session,
        dfir_root=args.dfir_root,
        scenario_name="BASELINE",
        required=True,
    )
    assert baseline_dir is not None

    treatment_dir = resolve_session_path(
        args.treatment_session,
        dfir_root=args.dfir_root,
        scenario_name=args.treatment_scenario,
        required=False,
    )

    baseline = load_scenario(
        "BASELINE",
        baseline_dir,
        abnormal_threshold=args.abnormal_threshold,
        target_register=args.target_register,
        attack_value=args.attack_value,
        explicit_modbus_writes=None,
    )

    treatment: Optional[ScenarioData] = None
    if treatment_dir is not None:
        treatment = load_scenario(
            args.treatment_scenario,
            treatment_dir,
            abnormal_threshold=args.abnormal_threshold,
            target_register=args.target_register,
            attack_value=args.attack_value,
            explicit_modbus_writes=args.modbus_writes,
        )

    output_dir = (
        args.output.resolve()
        if args.output is not None
        else (
            args.dfir_root
            / "analysis"
            / "results"
            / (
                "BASELINE_ONLY_PAMSIMAS"
                if treatment is None
                else f"BASELINE_vs_{args.treatment_scenario}_PAMSIMAS"
            )
        ).resolve()
    )

    if output_dir.exists() and any(output_dir.iterdir()) and not args.force:
        raise FileExistsError(
            f"Output directory sudah berisi file: {output_dir}. Gunakan --force."
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    baseline_integrity = build_integrity_summary(baseline)
    baseline_availability = build_availability_summary(baseline)
    baseline_control = build_control_logic_summary(baseline)

    treatment_integrity: Optional[list[dict[str, Any]]] = None
    treatment_availability: Optional[list[dict[str, Any]]] = None
    treatment_control: Optional[list[dict[str, Any]]] = None
    attack_observations: list[dict[str, Any]] = []
    recovery: Optional[dict[str, Any]] = None

    if treatment is not None:
        treatment_integrity = build_integrity_summary(treatment)
        treatment_availability = build_availability_summary(treatment)
        treatment_control = build_control_logic_summary(treatment)
        attack_observations = build_attack_observations(
            treatment,
            target_register=args.target_register,
            attack_value=args.attack_value,
            correlation_window_seconds=args.correlation_window_seconds,
        )
        recovery = stable_recovery_metrics(
            treatment,
            attack_value=args.attack_value,
            stable_records=args.stable_records,
        )

    integrity_rows = [
        *baseline_integrity,
        *(treatment_integrity or []),
    ]
    availability_rows = [
        *baseline_availability,
        *(treatment_availability or []),
    ]
    control_rows = [
        *baseline_control,
        *(treatment_control or []),
    ]

    comparison_rows = build_comparison(
        baseline_integrity,
        baseline_availability,
        baseline_control,
        treatment_integrity,
        treatment_availability,
        treatment_control,
    )

    timeline = build_timeline(
        baseline,
        treatment,
        attack_observations,
        recovery,
    )

    findings = build_findings(
        baseline,
        baseline_integrity,
        baseline_availability,
        baseline_control,
        treatment,
        treatment_integrity,
        treatment_availability,
        treatment_control,
        attack_observations,
        recovery,
    )

    input_hash_rows = [
        *baseline.input_hash_rows,
        *(treatment.input_hash_rows if treatment else []),
    ]

    limitations = [
        "The current source is ThingsBoard-shaped hardcoded/mock telemetry until the STM32 and live ThingsBoard integration are completed.",
        "The Valve field from ThingsBoard is treated as observed field feedback; ValveCommand is the OpenPLC controller output.",
        "Collector polling may be faster than sender publication, so duplicate source_sequence observations are expected and are not automatically classified as replay.",
        "Acquisition availability does not by itself prove physical water-service availability.",
    ]

    if treatment is not None and not treatment.modbus_writes:
        limitations.append(
            "No parsed Modbus write-event file was found; the analysis does not independently confirm FC06/FC16 at the network layer."
        )

    if any(row.get("verification_status") == "HASH_MISMATCH" for row in input_hash_rows):
        limitations.append(
            "At least one input file failed hash verification against the collector hash manifest."
        )

    write_csv(output_dir / "input_integrity_verification.csv", input_hash_rows)
    write_csv(
        output_dir / "paired_cross_layer_analysis.csv",
        [
            *baseline.paired_rows,
            *(treatment.paired_rows if treatment else []),
        ],
    )
    write_csv(output_dir / "integrity_analysis.csv", integrity_rows)
    write_csv(output_dir / "availability_analysis.csv", availability_rows)
    write_csv(output_dir / "control_logic_analysis.csv", control_rows)
    write_csv(output_dir / "attack_observations.csv", attack_observations)
    write_csv(
        output_dir / "network_write_events_used.csv",
        treatment.modbus_writes if treatment else [],
    )
    write_csv(
        output_dir / "recovery_analysis.csv",
        [recovery] if recovery else [],
    )
    write_csv(output_dir / "baseline_comparison.csv", comparison_rows)
    write_csv(output_dir / "final_incident_timeline.csv", timeline)
    write_json(output_dir / "findings.json", findings)

    report_markdown = build_report_markdown(
        operator=args.operator,
        run_id=run_id,
        baseline=baseline,
        treatment=treatment,
        integrity_rows=integrity_rows,
        availability_rows=availability_rows,
        control_rows=control_rows,
        comparison_rows=comparison_rows,
        attack_observations=attack_observations,
        recovery=recovery,
        findings=findings,
        limitations=limitations,
        timeline=timeline,
        target_register=args.target_register,
        attack_value=args.attack_value,
    )
    (output_dir / "analysis_report.md").write_text(
        report_markdown + "\n", encoding="utf-8"
    )
    (output_dir / "analysis_report.html").write_text(
        markdown_to_html(
            report_markdown,
            "Cross-Layer DFIR Analysis — PAMSIMAS",
        ),
        encoding="utf-8",
    )

    summary = {
        "analysis_schema_version": SCHEMA_VERSION,
        "analysis_run_id": run_id,
        "operator": args.operator,
        "collector_host": socket.gethostname(),
        "script_path": str(SCRIPT_PATH),
        "script_sha256": sha256_file(SCRIPT_PATH),
        "started_at_utc": started_at,
        "completed_at_utc": utc_now(),
        "scope": (
            "BASELINE only"
            if treatment is None
            else f"BASELINE vs {args.treatment_scenario}"
        ),
        "architecture": "ThingsBoard-shaped telemetry -> Raspberry Pi -> Modbus/TCP -> OpenPLC -> ValveCommand",
        "register_mapping": {
            "HR1024": "ODO Meter",
            "HR1025": "Flow Rate x1000",
            "HR1026": "Volume x10000",
            "HR1027": "Payment Status",
            "HR1028": "Source Sequence",
            "HR1029": "Observed Valve Raw",
            "HR1030": "Node ID",
            "HR1031": "ODO Meter Processed",
            "HR1032": "Process State",
            "HR1033": "Valve Reason",
        },
        "coil_mapping": {
            "Coil0": "ValveCommand",
            "Coil1": "AbnormalUsage",
            "Coil2": "PaymentBlocked",
        },
        "configured_treatment": {
            "target_register": args.target_register,
            "attack_value": args.attack_value,
            "abnormal_threshold": args.abnormal_threshold,
            "stable_records": args.stable_records,
            "correlation_window_seconds": args.correlation_window_seconds,
        },
        "inputs": {
            "baseline_session": str(baseline.session_dir),
            "baseline_raspi_csv": str(baseline.raspi_path),
            "baseline_openplc_csv": str(baseline.openplc_path),
            "treatment_session": str(treatment.session_dir) if treatment else None,
            "treatment_raspi_csv": str(treatment.raspi_path) if treatment else None,
            "treatment_openplc_csv": str(treatment.openplc_path) if treatment else None,
            "network_write_event_count": len(treatment.modbus_writes) if treatment else 0,
        },
        "record_counts": {
            "baseline_paired_records": len(baseline.paired_rows),
            "treatment_paired_records": len(treatment.paired_rows) if treatment else 0,
            "attack_observation_count": len(attack_observations),
        },
        "recovery": recovery,
        "findings": findings,
        "limitations": limitations,
        "claim_boundary": (
            "Conclusions apply to this laboratory testbed and evaluated files; "
            "not universal validation for all PAMSIMAS/OT environments."
        ),
    }
    write_json(output_dir / "analysis_summary.json", summary)

    manifest_path = output_dir / "analysis_manifest.csv"
    build_output_manifest(output_dir, manifest_path)
    (output_dir / "analysis_manifest.sha256.txt").write_text(
        f"{sha256_file(manifest_path)}  {manifest_path.name}\n",
        encoding="utf-8",
    )

    print("=" * 76)
    print(" CROSS-LAYER DFIR ANALYSIS — PAMSIMAS")
    print("=" * 76)
    print(f"Baseline session : {baseline.session_dir}")
    print(
        f"Treatment session: {treatment.session_dir if treatment else '(not provided)'}"
    )
    print(f"Output            : {output_dir}")
    print(f"Baseline records  : {len(baseline.paired_rows)}")
    print(
        f"Treatment records : {len(treatment.paired_rows) if treatment else 0}"
    )
    print(f"Attack observations: {len(attack_observations)}")
    print(
        "Network evidence   : "
        + (
            f"{len(treatment.modbus_writes)} configured write event(s)"
            if treatment and treatment.modbus_writes
            else "not available"
        )
    )
    print("=" * 76)
    print(f"Report: {output_dir / 'analysis_report.html'}")

    return output_dir


# =========================================================
# ARGUMENTS
# =========================================================


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Cross-layer analyzer untuk ThingsBoard-shaped telemetry, "
            "Raspberry Pi, Modbus/TCP, dan OpenPLC PAMSIMAS."
        )
    )
    parser.add_argument(
        "--operator",
        default="UNSPECIFIED",
        help="Nama operator/analyst.",
    )
    parser.add_argument(
        "--dfir-root",
        type=Path,
        default=SCRIPT_PATH.parent,
        help="Root DFIR untuk auto-discovery evidence dan output.",
    )
    parser.add_argument(
        "--baseline-session",
        type=Path,
        help="Folder collector session Baseline atau parent folder-nya.",
    )
    parser.add_argument(
        "--treatment-session",
        type=Path,
        help="Folder collector session Perlakuan 1 atau parent folder-nya.",
    )
    parser.add_argument(
        "--treatment-scenario",
        default="PERLAKUAN_1_FDI",
        help="Nama skenario treatment untuk auto-discovery dan output.",
    )
    parser.add_argument(
        "--modbus-writes",
        type=Path,
        help="Optional modbus_write_events.csv dari Examination/PCAP parser.",
    )
    parser.add_argument(
        "--target-register",
        type=int,
        default=DEFAULT_TARGET_REGISTER,
    )
    parser.add_argument(
        "--attack-value",
        type=int,
        default=DEFAULT_ATTACK_VALUE,
    )
    parser.add_argument(
        "--abnormal-threshold",
        type=int,
        default=DEFAULT_ABNORMAL_THRESHOLD,
    )
    parser.add_argument(
        "--stable-records",
        type=int,
        default=DEFAULT_STABLE_RECORDS,
    )
    parser.add_argument(
        "--correlation-window-seconds",
        type=float,
        default=DEFAULT_CORRELATION_WINDOW_SECONDS,
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Folder output. Default: analysis/results/...",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Izinkan penulisan ke folder output yang sudah berisi file.",
    )

    args = parser.parse_args()
    args.dfir_root = args.dfir_root.resolve()

    if args.target_register < 0:
        parser.error("--target-register tidak boleh negatif")
    if not 0 <= args.attack_value <= 65535:
        parser.error("--attack-value harus 0-65535")
    if not 0 <= args.abnormal_threshold <= 65535:
        parser.error("--abnormal-threshold harus 0-65535")
    if args.stable_records <= 0:
        parser.error("--stable-records harus lebih besar dari 0")
    if args.correlation_window_seconds <= 0:
        parser.error("--correlation-window-seconds harus lebih besar dari 0")

    if args.modbus_writes is not None:
        args.modbus_writes = args.modbus_writes.resolve()
        if not args.modbus_writes.exists():
            parser.error(f"--modbus-writes tidak ditemukan: {args.modbus_writes}")

    return args


def main() -> int:
    args = parse_arguments()

    try:
        run_analysis(args)
        return 0
    except Exception as error:
        print(
            f"[FATAL] {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        if getattr(args, "debug", False):
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())