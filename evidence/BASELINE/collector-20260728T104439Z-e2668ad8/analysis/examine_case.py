#!/usr/bin/env python3
"""
examine_case.py

Script Examination generik untuk testbed DFIR Raspberry Pi–OpenPLC.

Letakkan script ini di:

    evidence/<scenario>/<collector-session>/analysis/examine_case.py

Struktur yang diharapkan setelah preservation:

    collector-session/
    ├── raw/
    ├── metadata/
    ├── master/
    │   ├── raw/
    │   └── metadata/
    ├── working/
    │   ├── raw/
    │   └── metadata/
    ├── preservation/
    └── analysis/
        └── examine_case.py

Script ini hanya membaca:
- master/
- working/
- preservation/

Semua hasil turunan ditulis ke:

    analysis/examination/

Tahapan yang dilakukan:
1. Verifikasi working copy terhadap master.
2. Validasi file, format, header, record, sequence, dan collection_id.
3. Normalisasi evidence Raspberry Pi dan OpenPLC.
4. Pairing lintas layer berdasarkan collection_id.
5. Ekstraksi phase event.
6. Ekstraksi PCAP/PCAPNG secara native dengan Python standard library.
7. Ekstraksi event Modbus/TCP.
8. Penyusunan candidate timeline.
9. Pembuatan summary, log, validation issues, dan manifest hasil examination.

Catatan metodologis:
- Script tidak mengubah raw, metadata, master, atau working.
- Output examination adalah derived evidence.
- Script belum memberikan kesimpulan insiden; interpretasi dilakukan pada tahap Analysis.
- Parser PCAP mendukung format PCAPNG/PCAP dan link type yang umum
  pada testbed ini: Ethernet dan Npcap Loopback/NULL.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import shutil
import socket
import stat
import struct
import sys
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any, Iterable, Iterator, Optional


# =========================================================
# LOKASI DEFAULT
# =========================================================

SCRIPT_PATH = Path(__file__).resolve()
ANALYSIS_DIR = SCRIPT_PATH.parent
CASE_ROOT = ANALYSIS_DIR.parent

MASTER_DIR = CASE_ROOT / "master"
WORKING_DIR = CASE_ROOT / "working"
PRESERVATION_DIR = CASE_ROOT / "preservation"
OUTPUT_DIR = ANALYSIS_DIR / "examination"

MASTER_RAW_DIR = MASTER_DIR / "raw"
MASTER_METADATA_DIR = MASTER_DIR / "metadata"
WORKING_RAW_DIR = WORKING_DIR / "raw"
WORKING_METADATA_DIR = WORKING_DIR / "metadata"


# =========================================================
# KONSTANTA
# =========================================================

EXAMINATION_SCHEMA_VERSION = "1.0"
DEFAULT_MODBUS_PORT = 502

REQUIRED_RASPI_COLUMNS = {
    "experiment_id",
    "scenario",
    "experiment_phase",
    "collector_session_id",
    "collection_id",
    "collection_sequence",
    "cycle_completed_at",
    "read_status",
    "original_odo_meter_litre",
    "sent_odo_meter_litre",
    "original_flow_rate_lpm",
    "sent_flow_rate_x1000",
    "original_volume_litre",
    "sent_volume_x10000",
    "original_payment_status",
    "sent_payment_status",
    "source_sequence",
}

REQUIRED_OPENPLC_COLUMNS = {
    "experiment_id",
    "scenario",
    "experiment_phase",
    "collector_session_id",
    "collection_id",
    "collection_sequence",
    "cycle_completed_at",
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

REQUIRED_PHASE_COLUMNS = {
    "event_timestamp",
    "experiment_id",
    "collector_session_id",
    "event_type",
    "experiment_phase",
}

TIMESTAMP_FIELDS = {
    "collector_started_at",
    "cycle_started_at",
    "cycle_completed_at",
    "raspi_read_started_at",
    "raspi_read_finished_at",
    "openplc_read_started_at",
    "openplc_read_finished_at",
    "source_updated_at",
    "sender_started_at",
    "event_timestamp",
    "modified_at_utc",
    "hashed_at_utc",
    "verified_at_utc",
}

INTEGER_FIELDS = {
    "collection_sequence",
    "http_status_code",
    "raw_state_size_bytes",
    "source_updated_at_epoch_ms",
    "sender_pid",
    "state_sequence",
    "bottle_event_sequence",
    "original_bottle_count",
    "sent_bottle_count",
    "batch_size",
    "bottle_in_batch_source",
    "target_port",
    "target_unit_id",
    "bottle_count_register",
    "ready_coil_address",
    "openplc_port",
    "unit_id",
    "holding_register_start",
    "holding_register_count",
    "coil_start",
    "coil_count",
    "bottle_count_from_pi",
    "total_bottle",
    "process_state",
    "bottle_in_batch",
    "last_processed_batch_count",
    "bottle_remainder",
}

FLOAT_FIELDS = {
    "acquisition_window_ms",
    "sampling_skew_ms",
    "raspi_read_duration_ms",
    "openplc_read_duration_ms",
    "source_age_ms",
}

BOOLEAN_FIELDS = {
    "expected_batch_full",
    "expected_pusher_status",
    "ready_for_next_batch",
    "pusher_output",
    "batch_full",
}

JSON_FIELDS = {
    "raw_registers_unsigned",
    "raw_registers_signed",
    "raw_coils",
}

PAIR_FIELDS = [
    "experiment_id",
    "scenario",
    "experiment_phase",
    "collector_session_id",
    "collection_id",
    "collection_sequence",
    "cycle_started_at",
    "cycle_completed_at",
    "acquisition_window_ms",
    "sampling_skew_ms",
    "original_bottle_count",
    "sent_bottle_count",
    "bottle_count_from_pi",
    "total_bottle",
    "process_state",
    "bottle_in_batch",
    "last_processed_batch_count",
    "bottle_remainder",
    "pusher_output",
    "ready_for_next_batch",
    "batch_full",
    "raspi_read_status",
    "openplc_read_status",
    "register_read_status",
    "coil_read_status",
    "send_status",
    "source_match",
    "cross_layer_match",
    "plc_internal_match",
    "raspi_acquisition_success",
    "openplc_acquisition_success",
    "pairing_status",
]

TIMELINE_FIELDS = [
    "timestamp_utc",
    "timeline_sequence",
    "source_type",
    "event_type",
    "experiment_phase",
    "collection_id",
    "collection_sequence",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "tcp_stream_key",
    "modbus_transaction_id",
    "modbus_function_code",
    "modbus_register_address",
    "modbus_register_value",
    "original_bottle_count",
    "sent_bottle_count",
    "bottle_count_from_pi",
    "total_bottle",
    "read_status",
    "note",
    "provenance_file",
    "provenance_record",
]

EXAMINATION_OUTPUT_NAMES = {
    "working_pre_examination_verification.csv",
    "schema_validation.csv",
    "validation_issues.csv",
    "normalized_raspi.csv",
    "normalized_openplc.csv",
    "paired_cross_layer_evidence.csv",
    "unpaired_raspi.csv",
    "unpaired_openplc.csv",
    "duplicate_collection_ids.csv",
    "phase_events.csv",
    "pcap_summary.csv",
    "modbus_events.csv",
    "modbus_write_events.csv",
    "candidate_timeline.csv",
    "examination_summary.json",
    "examination_log.txt",
    "examination_manifest.csv",
    "examination_manifest.sha256.txt",
    "examination_run.json",
}


# =========================================================
# MODEL DATA
# =========================================================

@dataclass(frozen=True)
class FileHashRecord:
    relative_path: str
    size_bytes: int
    sha256: str


@dataclass
class ValidationIssue:
    severity: str
    category: str
    source_file: str
    record_reference: str
    field: str
    issue: str
    observed_value: str = ""
    expected_value: str = ""


@dataclass
class InterfaceInfo:
    interface_id: int
    link_type: int
    snaplen: int
    timestamp_resolution: float
    name: str = ""
    description: str = ""


@dataclass
class CapturedPacket:
    packet_number: int
    timestamp_epoch: Optional[float]
    captured_length: int
    original_length: int
    link_type: int
    interface_id: int
    interface_name: str
    interface_description: str
    packet_data: bytes


@dataclass
class NetworkPacket:
    packet_number: int
    timestamp_epoch: Optional[float]
    timestamp_utc: str
    interface_id: int
    interface_name: str
    interface_description: str
    link_type: int
    ip_version: int
    source_ip: str
    destination_ip: str
    protocol: int
    source_port: Optional[int]
    destination_port: Optional[int]
    tcp_sequence: Optional[int]
    tcp_acknowledgment: Optional[int]
    tcp_flags: str
    tcp_payload: bytes
    parse_status: str
    parse_note: str


# =========================================================
# UTILITAS UMUM
# =========================================================

def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def create_run_id() -> str:
    return (
        "examination-"
        + datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-"
        + uuid.uuid4().hex[:8]
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file_handle:
        while True:
            chunk = file_handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def relative_path(root: Path, path: Path) -> str:
    return path.resolve().relative_to(
        root.resolve()
    ).as_posix()


def list_files(root: Path) -> list[Path]:
    if not root.exists():
        return []

    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
    )


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(
        "r",
        newline="",
        encoding="utf-8-sig",
    ) as file_handle:
        reader = csv.DictReader(file_handle)

        if reader.fieldnames is None:
            raise ValueError(
                f"Header CSV tidak ditemukan: {path}"
            )

        return list(reader.fieldnames), list(reader)


def write_csv(
    path: Path,
    fieldnames: list[str],
    rows: Iterable[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )
        writer.writeheader()

        for row in rows:
            writer.writerow({
                field: normalize_csv_output(
                    row.get(field)
                )
                for field in fieldnames
            })


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            default=str,
        ) + "\n",
        encoding="utf-8",
    )


def normalize_csv_output(value: Any) -> Any:
    if value is None:
        return ""

    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"

    if isinstance(value, (dict, list, tuple)):
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    return value


def parse_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    try:
        parsed = datetime.fromisoformat(
            text.replace("Z", "+00:00")
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(timezone.utc)


def canonical_timestamp(value: Any) -> Optional[str]:
    parsed = parse_datetime(value)

    if parsed is None:
        return None

    return (
        parsed.isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def epoch_to_utc(value: Optional[float]) -> str:
    if value is None:
        return ""

    try:
        return (
            datetime.fromtimestamp(
                value,
                tz=timezone.utc,
            )
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
    except (OverflowError, OSError, ValueError):
        return ""


def parse_int(value: Any) -> Optional[int]:
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    try:
        return int(text, 10)
    except ValueError:
        try:
            number = float(text)

            if number.is_integer():
                return int(number)
        except ValueError:
            return None

    return None


def parse_float(value: Any) -> Optional[float]:
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    try:
        return float(text)
    except ValueError:
        return None


def parse_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None

    text = str(value).strip().upper()

    if text in {"TRUE", "1", "YES", "Y"}:
        return True

    if text in {"FALSE", "0", "NO", "N"}:
        return False

    return None


def bool_equal(
    left: Optional[int],
    right: Optional[int],
) -> Optional[bool]:
    if left is None or right is None:
        return None

    return left == right


def safe_median(values: list[float]) -> Optional[float]:
    return median(values) if values else None


def find_unique_file(
    root: Path,
    filename: str,
) -> Path:
    matches = [
        path
        for path in root.rglob(filename)
        if path.is_file()
    ]

    if not matches:
        raise FileNotFoundError(
            f"{filename} tidak ditemukan di {root}"
        )

    if len(matches) > 1:
        joined = "\n".join(
            str(path)
            for path in matches
        )
        raise RuntimeError(
            f"{filename} ditemukan lebih dari satu:\n"
            f"{joined}"
        )

    return matches[0]


def remove_output_directory(
    output_dir: Path,
    *,
    force: bool,
) -> None:
    if output_dir.exists() and any(
        output_dir.iterdir()
    ):
        if not force:
            raise RuntimeError(
                f"Output examination sudah ada: "
                f"{output_dir}. Gunakan --force "
                "hanya untuk membuat ulang output."
            )

        shutil.rmtree(output_dir)

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )


# =========================================================
# VERIFIKASI MASTER DAN WORKING
# =========================================================

def build_hash_inventory(
    root: Path,
) -> list[FileHashRecord]:
    return [
        FileHashRecord(
            relative_path=relative_path(root, path),
            size_bytes=path.stat().st_size,
            sha256=sha256_file(path),
        )
        for path in list_files(root)
    ]


def compare_hash_inventories(
    source: list[FileHashRecord],
    destination: list[FileHashRecord],
) -> list[dict[str, Any]]:
    source_map = {
        record.relative_path: record
        for record in source
    }

    destination_map = {
        record.relative_path: record
        for record in destination
    }

    results: list[dict[str, Any]] = []

    for path in sorted(
        set(source_map) | set(destination_map)
    ):
        source_record = source_map.get(path)
        destination_record = (
            destination_map.get(path)
        )

        if source_record is None:
            status = "EXTRA_IN_WORKING"
            note = "File tidak terdapat pada master."

        elif destination_record is None:
            status = "MISSING_IN_WORKING"
            note = "File tidak terdapat pada working."

        elif (
            source_record.sha256
            != destination_record.sha256
            or source_record.size_bytes
            != destination_record.size_bytes
        ):
            status = "MISMATCH"
            note = "SHA-256 atau ukuran berbeda."

        else:
            status = "MATCH"
            note = ""

        results.append({
            "relative_path": path,
            "master_size_bytes": (
                source_record.size_bytes
                if source_record
                else ""
            ),
            "working_size_bytes": (
                destination_record.size_bytes
                if destination_record
                else ""
            ),
            "master_sha256": (
                source_record.sha256
                if source_record
                else ""
            ),
            "working_sha256": (
                destination_record.sha256
                if destination_record
                else ""
            ),
            "verification": status,
            "verified_at_utc": utc_now(),
            "note": note,
        })

    return results


# =========================================================
# VALIDASI DAN NORMALISASI CSV
# =========================================================

def validate_schema(
    source_name: str,
    path: Path,
    fieldnames: list[str],
    required_columns: set[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for column in sorted(required_columns):
        rows.append({
            "source": source_name,
            "file": str(path),
            "column": column,
            "requirement": "REQUIRED",
            "status": (
                "PRESENT"
                if column in fieldnames
                else "MISSING"
            ),
        })

    for column in sorted(
        set(fieldnames) - required_columns
    ):
        rows.append({
            "source": source_name,
            "file": str(path),
            "column": column,
            "requirement": "OPTIONAL_OR_ADDITIONAL",
            "status": "PRESENT",
        })

    return rows


def normalize_field(
    field: str,
    value: Any,
    *,
    source_file: str,
    record_reference: str,
    issues: list[ValidationIssue],
) -> Any:
    text = "" if value is None else str(value).strip()

    if not text:
        return ""

    if field in TIMESTAMP_FIELDS:
        normalized = canonical_timestamp(text)

        if normalized is None:
            issues.append(
                ValidationIssue(
                    severity="WARNING",
                    category="TIMESTAMP_PARSE",
                    source_file=source_file,
                    record_reference=record_reference,
                    field=field,
                    issue="Timestamp tidak dapat dinormalisasi.",
                    observed_value=text,
                    expected_value="ISO 8601 UTC",
                )
            )
            return text

        return normalized

    if field in INTEGER_FIELDS:
        parsed = parse_int(text)

        if parsed is None:
            issues.append(
                ValidationIssue(
                    severity="WARNING",
                    category="INTEGER_PARSE",
                    source_file=source_file,
                    record_reference=record_reference,
                    field=field,
                    issue="Nilai integer tidak valid.",
                    observed_value=text,
                )
            )
            return text

        return parsed

    if field in FLOAT_FIELDS:
        parsed = parse_float(text)

        if parsed is None:
            issues.append(
                ValidationIssue(
                    severity="WARNING",
                    category="FLOAT_PARSE",
                    source_file=source_file,
                    record_reference=record_reference,
                    field=field,
                    issue="Nilai numerik tidak valid.",
                    observed_value=text,
                )
            )
            return text

        return parsed

    if field in BOOLEAN_FIELDS:
        parsed = parse_bool(text)

        if parsed is None:
            issues.append(
                ValidationIssue(
                    severity="WARNING",
                    category="BOOLEAN_PARSE",
                    source_file=source_file,
                    record_reference=record_reference,
                    field=field,
                    issue="Nilai boolean tidak valid.",
                    observed_value=text,
                    expected_value="TRUE/FALSE",
                )
            )
            return text

        return parsed

    if field in JSON_FIELDS:
        try:
            parsed_json = json.loads(text)
        except json.JSONDecodeError:
            issues.append(
                ValidationIssue(
                    severity="WARNING",
                    category="JSON_PARSE",
                    source_file=source_file,
                    record_reference=record_reference,
                    field=field,
                    issue="JSON embedded tidak valid.",
                    observed_value=text,
                )
            )
            return text

        return parsed_json

    return text


def normalize_rows(
    source_name: str,
    source_path: Path,
    fieldnames: list[str],
    rows: list[dict[str, str]],
    issues: list[ValidationIssue],
) -> list[dict[str, Any]]:
    normalized_rows: list[dict[str, Any]] = []

    for row_number, row in enumerate(
        rows,
        start=2,
    ):
        collection_id = (
            row.get("collection_id", "").strip()
        )

        record_reference = (
            collection_id
            or f"CSV_ROW_{row_number}"
        )

        normalized: dict[str, Any] = {}

        for field in fieldnames:
            normalized[field] = normalize_field(
                field,
                row.get(field),
                source_file=str(source_path),
                record_reference=record_reference,
                issues=issues,
            )

        normalized["_source_csv_row"] = row_number
        normalized_rows.append(normalized)

    return normalized_rows


def validate_collection_sequence(
    source_name: str,
    rows: list[dict[str, Any]],
    source_path: Path,
    issues: list[ValidationIssue],
) -> None:
    sequences = [
        parse_int(row.get("collection_sequence"))
        for row in rows
    ]

    valid_sequences = [
        sequence
        for sequence in sequences
        if sequence is not None
    ]

    if len(valid_sequences) != len(rows):
        issues.append(
            ValidationIssue(
                severity="WARNING",
                category="SEQUENCE",
                source_file=str(source_path),
                record_reference=source_name,
                field="collection_sequence",
                issue=(
                    "Sebagian collection_sequence "
                    "tidak dapat dibaca."
                ),
            )
        )

    if not valid_sequences:
        return

    duplicate_sequences = sorted({
        value
        for value in valid_sequences
        if valid_sequences.count(value) > 1
    })

    if duplicate_sequences:
        issues.append(
            ValidationIssue(
                severity="ERROR",
                category="SEQUENCE_DUPLICATE",
                source_file=str(source_path),
                record_reference=source_name,
                field="collection_sequence",
                issue="Collection sequence duplikat.",
                observed_value=json.dumps(
                    duplicate_sequences
                ),
            )
        )

    sorted_unique = sorted(set(valid_sequences))
    expected = list(
        range(
            sorted_unique[0],
            sorted_unique[-1] + 1,
        )
    )

    missing = sorted(
        set(expected) - set(sorted_unique)
    )

    if missing:
        issues.append(
            ValidationIssue(
                severity="WARNING",
                category="SEQUENCE_GAP",
                source_file=str(source_path),
                record_reference=source_name,
                field="collection_sequence",
                issue="Ditemukan gap collection sequence.",
                observed_value=json.dumps(missing),
            )
        )


def index_rows_by_collection_id(
    source_name: str,
    rows: list[dict[str, Any]],
    source_path: Path,
    issues: list[ValidationIssue],
) -> tuple[
    dict[str, dict[str, Any]],
    list[dict[str, Any]],
]:
    grouped: dict[str, list[dict[str, Any]]] = {}

    for row in rows:
        collection_id = str(
            row.get("collection_id", "")
        ).strip()

        if not collection_id:
            issues.append(
                ValidationIssue(
                    severity="ERROR",
                    category="MISSING_COLLECTION_ID",
                    source_file=str(source_path),
                    record_reference=str(
                        row.get(
                            "_source_csv_row",
                            "",
                        )
                    ),
                    field="collection_id",
                    issue="collection_id kosong.",
                )
            )
            continue

        grouped.setdefault(
            collection_id,
            [],
        ).append(row)

    index: dict[str, dict[str, Any]] = {}
    duplicates: list[dict[str, Any]] = []

    for collection_id, records in grouped.items():
        if len(records) == 1:
            index[collection_id] = records[0]
            continue

        issues.append(
            ValidationIssue(
                severity="ERROR",
                category="DUPLICATE_COLLECTION_ID",
                source_file=str(source_path),
                record_reference=collection_id,
                field="collection_id",
                issue=(
                    f"{source_name} memiliki "
                    f"{len(records)} record dengan "
                    "collection_id yang sama."
                ),
            )
        )

        for record in records:
            duplicates.append({
                "source": source_name,
                "collection_id": collection_id,
                "collection_sequence": (
                    record.get(
                        "collection_sequence",
                        "",
                    )
                ),
                "source_csv_row": record.get(
                    "_source_csv_row",
                    "",
                ),
            })

    return index, duplicates


def build_paired_rows(
    raspi_index: dict[str, dict[str, Any]],
    openplc_index: dict[str, dict[str, Any]],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    paired: list[dict[str, Any]] = []
    unpaired_raspi: list[dict[str, Any]] = []
    unpaired_openplc: list[dict[str, Any]] = []

    all_ids = sorted(
        set(raspi_index) | set(openplc_index),
        key=lambda collection_id: (
            parse_int(
                (
                    raspi_index.get(collection_id)
                    or openplc_index.get(collection_id)
                    or {}
                ).get("collection_sequence")
            )
            or 10**18,
            collection_id,
        ),
    )

    for collection_id in all_ids:
        raspi = raspi_index.get(collection_id)
        openplc = openplc_index.get(collection_id)

        if raspi is None and openplc is not None:
            unpaired_openplc.append(openplc)
            continue

        if openplc is None and raspi is not None:
            unpaired_raspi.append(raspi)
            continue

        if raspi is None or openplc is None:
            continue

        original = parse_int(
            raspi.get(
                "original_bottle_count"
            )
        )
        sent = parse_int(
            raspi.get(
                "sent_bottle_count"
            )
        )
        plc_value = parse_int(
            openplc.get(
                "bottle_count_from_pi"
            )
        )
        total_bottle = parse_int(
            openplc.get("total_bottle")
        )

        raspi_status = str(
            raspi.get("read_status", "")
        ).upper()

        openplc_status = str(
            openplc.get("read_status", "")
        ).upper()

        row = {
            "experiment_id": (
                raspi.get("experiment_id")
                or openplc.get("experiment_id")
            ),
            "scenario": (
                raspi.get("scenario")
                or openplc.get("scenario")
            ),
            "experiment_phase": (
                raspi.get("experiment_phase")
                or openplc.get(
                    "experiment_phase"
                )
            ),
            "collector_session_id": (
                raspi.get(
                    "collector_session_id"
                )
                or openplc.get(
                    "collector_session_id"
                )
            ),
            "collection_id": collection_id,
            "collection_sequence": (
                raspi.get(
                    "collection_sequence"
                )
                or openplc.get(
                    "collection_sequence"
                )
            ),
            "cycle_started_at": (
                raspi.get("cycle_started_at")
                or openplc.get(
                    "cycle_started_at"
                )
            ),
            "cycle_completed_at": (
                raspi.get(
                    "cycle_completed_at"
                )
                or openplc.get(
                    "cycle_completed_at"
                )
            ),
            "acquisition_window_ms": (
                raspi.get(
                    "acquisition_window_ms"
                )
                or openplc.get(
                    "acquisition_window_ms"
                )
            ),
            "sampling_skew_ms": (
                raspi.get("sampling_skew_ms")
                or openplc.get(
                    "sampling_skew_ms"
                )
            ),
            "original_bottle_count": original,
            "sent_bottle_count": sent,
            "bottle_count_from_pi": plc_value,
            "total_bottle": total_bottle,
            "process_state": openplc.get(
                "process_state"
            ),
            "bottle_in_batch": openplc.get(
                "bottle_in_batch"
            ),
            "last_processed_batch_count": (
                openplc.get(
                    "last_processed_batch_count"
                )
            ),
            "bottle_remainder": openplc.get(
                "bottle_remainder"
            ),
            "pusher_output": openplc.get(
                "pusher_output"
            ),
            "ready_for_next_batch": (
                openplc.get(
                    "ready_for_next_batch"
                )
            ),
            "batch_full": openplc.get(
                "batch_full"
            ),
            "raspi_read_status": raspi_status,
            "openplc_read_status": (
                openplc_status
            ),
            "register_read_status": (
                openplc.get(
                    "register_read_status"
                )
            ),
            "coil_read_status": openplc.get(
                "coil_read_status"
            ),
            "send_status": raspi.get(
                "send_status"
            ),
            "source_match": bool_equal(
                original,
                sent,
            ),
            "cross_layer_match": bool_equal(
                sent,
                plc_value,
            ),
            "plc_internal_match": bool_equal(
                plc_value,
                total_bottle,
            ),
            "raspi_acquisition_success": (
                raspi_status == "SUCCESS"
            ),
            "openplc_acquisition_success": (
                openplc_status == "SUCCESS"
            ),
            "pairing_status": "PAIRED",
        }

        paired.append(row)

    return (
        paired,
        unpaired_raspi,
        unpaired_openplc,
    )


# =========================================================
# PARSER PCAP / PCAPNG
# =========================================================

def parse_pcapng_options(
    data: bytes,
    start: int,
    end: int,
    endian: str,
) -> dict[int, list[bytes]]:
    options: dict[int, list[bytes]] = {}
    position = start

    while position + 4 <= end:
        code, length = struct.unpack_from(
            endian + "HH",
            data,
            position,
        )
        position += 4

        value = data[
            position:position + length
        ]

        position += (
            (length + 3) // 4
        ) * 4

        if code == 0:
            break

        options.setdefault(
            code,
            [],
        ).append(value)

    return options


def decode_option_text(
    options: dict[int, list[bytes]],
    code: int,
) -> str:
    values = options.get(code, [])

    if not values:
        return ""

    return values[0].decode(
        "utf-8",
        errors="replace",
    ).rstrip("\x00")


def decode_timestamp_resolution(
    options: dict[int, list[bytes]],
) -> float:
    values = options.get(9, [])

    if not values or not values[0]:
        return 1e-6

    raw = values[0][0]

    if raw & 0x80:
        exponent = raw & 0x7F
        return 2.0 ** (-exponent)

    return 10.0 ** (-raw)


def iter_pcapng_packets(
    path: Path,
) -> Iterator[CapturedPacket]:
    data = path.read_bytes()
    offset = 0
    endian = "<"
    interfaces: dict[int, InterfaceInfo] = {}
    packet_number = 0

    while offset + 12 <= len(data):
        raw_type = struct.unpack_from(
            "<I",
            data,
            offset,
        )[0]

        if raw_type == 0x0A0D0D0A:
            if offset + 16 > len(data):
                break

            byte_order_magic = data[
                offset + 8:offset + 12
            ]

            if byte_order_magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError(
                    f"PCAPNG byte-order magic tidak valid "
                    f"pada offset {offset}."
                )

            block_type, block_length = (
                struct.unpack_from(
                    endian + "II",
                    data,
                    offset,
                )
            )

            interfaces = {}

        else:
            block_type, block_length = (
                struct.unpack_from(
                    endian + "II",
                    data,
                    offset,
                )
            )

        if (
            block_length < 12
            or block_length % 4 != 0
            or offset + block_length > len(data)
        ):
            raise ValueError(
                f"PCAPNG block rusak pada offset "
                f"{offset}, length={block_length}."
            )

        trailing_length = struct.unpack_from(
            endian + "I",
            data,
            offset + block_length - 4,
        )[0]

        if trailing_length != block_length:
            raise ValueError(
                f"PCAPNG block length mismatch "
                f"pada offset {offset}."
            )

        if block_type == 0x00000001:
            link_type, _, snaplen = struct.unpack_from(
                endian + "HHI",
                data,
                offset + 8,
            )

            options = parse_pcapng_options(
                data,
                offset + 16,
                offset + block_length - 4,
                endian,
            )

            interface_id = len(interfaces)

            interfaces[interface_id] = InterfaceInfo(
                interface_id=interface_id,
                link_type=link_type,
                snaplen=snaplen,
                timestamp_resolution=(
                    decode_timestamp_resolution(
                        options
                    )
                ),
                name=decode_option_text(
                    options,
                    2,
                ),
                description=decode_option_text(
                    options,
                    3,
                ),
            )

        elif block_type == 0x00000006:
            (
                interface_id,
                timestamp_high,
                timestamp_low,
                captured_length,
                original_length,
            ) = struct.unpack_from(
                endian + "IIIII",
                data,
                offset + 8,
            )

            packet_start = offset + 28
            packet_end = (
                packet_start
                + captured_length
            )

            if packet_end > (
                offset + block_length - 4
            ):
                raise ValueError(
                    "PCAPNG captured packet melebihi "
                    "ukuran block."
                )

            interface = interfaces.get(
                interface_id,
                InterfaceInfo(
                    interface_id=interface_id,
                    link_type=-1,
                    snaplen=0,
                    timestamp_resolution=1e-6,
                ),
            )

            raw_timestamp = (
                (timestamp_high << 32)
                | timestamp_low
            )

            timestamp_epoch = (
                raw_timestamp
                * interface.timestamp_resolution
            )

            packet_number += 1

            yield CapturedPacket(
                packet_number=packet_number,
                timestamp_epoch=timestamp_epoch,
                captured_length=captured_length,
                original_length=original_length,
                link_type=interface.link_type,
                interface_id=interface_id,
                interface_name=interface.name,
                interface_description=(
                    interface.description
                ),
                packet_data=data[
                    packet_start:packet_end
                ],
            )

        offset += block_length


def iter_classic_pcap_packets(
    path: Path,
) -> Iterator[CapturedPacket]:
    data = path.read_bytes()

    if len(data) < 24:
        raise ValueError("PCAP terlalu pendek.")

    magic = data[:4]

    magic_map = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
        b"\xa1\xb2\xc3\xd4": (">", 1e-6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
        b"\xa1\xb2\x3c\x4d": (">", 1e-9),
    }

    if magic not in magic_map:
        raise ValueError(
            "Magic number PCAP tidak dikenal."
        )

    endian, fraction_resolution = magic_map[
        magic
    ]

    link_type = struct.unpack_from(
        endian + "I",
        data,
        20,
    )[0]

    offset = 24
    packet_number = 0

    while offset + 16 <= len(data):
        (
            timestamp_seconds,
            timestamp_fraction,
            captured_length,
            original_length,
        ) = struct.unpack_from(
            endian + "IIII",
            data,
            offset,
        )
        offset += 16

        packet_end = (
            offset + captured_length
        )

        if packet_end > len(data):
            raise ValueError(
                "PCAP packet melebihi ukuran file."
            )

        packet_number += 1

        yield CapturedPacket(
            packet_number=packet_number,
            timestamp_epoch=(
                timestamp_seconds
                + timestamp_fraction
                * fraction_resolution
            ),
            captured_length=captured_length,
            original_length=original_length,
            link_type=link_type,
            interface_id=0,
            interface_name="",
            interface_description="",
            packet_data=data[offset:packet_end],
        )

        offset = packet_end


def iter_capture_packets(
    path: Path,
) -> Iterator[CapturedPacket]:
    first_four = path.read_bytes()[:4]

    if first_four == b"\x0a\x0d\x0d\x0a":
        yield from iter_pcapng_packets(path)
        return

    yield from iter_classic_pcap_packets(path)


def parse_ethernet_payload(
    packet: bytes,
) -> tuple[Optional[int], bytes, str]:
    if len(packet) < 14:
        return None, b"", "Ethernet frame terlalu pendek."

    ethertype = struct.unpack_from(
        "!H",
        packet,
        12,
    )[0]

    offset = 14

    while ethertype in {
        0x8100,
        0x88A8,
        0x9100,
    }:
        if len(packet) < offset + 4:
            return (
                None,
                b"",
                "VLAN header tidak lengkap.",
            )

        ethertype = struct.unpack_from(
            "!H",
            packet,
            offset + 2,
        )[0]
        offset += 4

    return ethertype, packet[offset:], ""


def parse_null_loopback_payload(
    packet: bytes,
) -> tuple[Optional[int], bytes, str]:
    if len(packet) < 4:
        return (
            None,
            b"",
            "NULL/Loopback header terlalu pendek.",
        )

    family_little = struct.unpack_from(
        "<I",
        packet,
        0,
    )[0]

    family_big = struct.unpack_from(
        ">I",
        packet,
        0,
    )[0]

    families_ipv4 = {2}
    families_ipv6 = {
        10,
        23,
        24,
        28,
        30,
    }

    if (
        family_little in families_ipv4
        or family_big in families_ipv4
    ):
        return 0x0800, packet[4:], ""

    if (
        family_little in families_ipv6
        or family_big in families_ipv6
    ):
        return 0x86DD, packet[4:], ""

    if len(packet) >= 5:
        version = packet[4] >> 4

        if version == 4:
            return 0x0800, packet[4:], (
                "Address family tidak dikenal; "
                "payload dikenali sebagai IPv4."
            )

        if version == 6:
            return 0x86DD, packet[4:], (
                "Address family tidak dikenal; "
                "payload dikenali sebagai IPv6."
            )

    return (
        None,
        b"",
        f"Address family NULL tidak dikenal: "
        f"little={family_little}, big={family_big}.",
    )


def parse_link_layer(
    packet: bytes,
    link_type: int,
) -> tuple[Optional[int], bytes, str]:
    if link_type == 1:
        return parse_ethernet_payload(packet)

    if link_type == 0:
        return parse_null_loopback_payload(
            packet
        )

    if link_type in {101, 228, 229}:
        if not packet:
            return None, b"", "Raw IP packet kosong."

        version = packet[0] >> 4

        if version == 4:
            return 0x0800, packet, ""

        if version == 6:
            return 0x86DD, packet, ""

        return (
            None,
            b"",
            "Raw IP version tidak dikenal.",
        )

    if link_type == 113:
        if len(packet) < 16:
            return (
                None,
                b"",
                "Linux cooked header terlalu pendek.",
            )

        protocol = struct.unpack_from(
            "!H",
            packet,
            14,
        )[0]

        return protocol, packet[16:], ""

    if link_type == 276:
        if len(packet) < 20:
            return (
                None,
                b"",
                "Linux cooked v2 header terlalu pendek.",
            )

        protocol = struct.unpack_from(
            "!H",
            packet,
            0,
        )[0]

        return protocol, packet[20:], ""

    return (
        None,
        b"",
        f"Link type belum didukung: {link_type}.",
    )


def flags_to_text(flags: int) -> str:
    mapping = [
        (0x100, "NS"),
        (0x080, "CWR"),
        (0x040, "ECE"),
        (0x020, "URG"),
        (0x010, "ACK"),
        (0x008, "PSH"),
        (0x004, "RST"),
        (0x002, "SYN"),
        (0x001, "FIN"),
    ]

    values = [
        name
        for mask, name in mapping
        if flags & mask
    ]

    return "|".join(values)


def parse_tcp_segment(
    ip_payload: bytes,
    ip_header_length: int,
    total_ip_length: int,
) -> tuple[
    Optional[int],
    Optional[int],
    Optional[int],
    Optional[int],
    str,
    bytes,
    str,
]:
    if len(ip_payload) < ip_header_length + 20:
        return (
            None,
            None,
            None,
            None,
            "",
            b"",
            "TCP header tidak lengkap.",
        )

    tcp_offset = ip_header_length

    (
        source_port,
        destination_port,
        sequence,
        acknowledgment,
    ) = struct.unpack_from(
        "!HHII",
        ip_payload,
        tcp_offset,
    )

    data_offset_byte = ip_payload[
        tcp_offset + 12
    ]

    tcp_header_length = (
        data_offset_byte >> 4
    ) * 4

    if tcp_header_length < 20:
        return (
            source_port,
            destination_port,
            sequence,
            acknowledgment,
            "",
            b"",
            "TCP data offset tidak valid.",
        )

    flags = (
        ((data_offset_byte & 0x01) << 8)
        | ip_payload[tcp_offset + 13]
    )

    payload_start = (
        tcp_offset + tcp_header_length
    )

    payload_end = min(
        len(ip_payload),
        total_ip_length,
    )

    if payload_start > payload_end:
        payload = b""
        note = "TCP payload offset melebihi packet."
    else:
        payload = ip_payload[
            payload_start:payload_end
        ]
        note = ""

    return (
        source_port,
        destination_port,
        sequence,
        acknowledgment,
        flags_to_text(flags),
        payload,
        note,
    )


def parse_ipv4_packet(
    payload: bytes,
    captured: CapturedPacket,
) -> NetworkPacket:
    base = dict(
        packet_number=captured.packet_number,
        timestamp_epoch=(
            captured.timestamp_epoch
        ),
        timestamp_utc=epoch_to_utc(
            captured.timestamp_epoch
        ),
        interface_id=captured.interface_id,
        interface_name=(
            captured.interface_name
        ),
        interface_description=(
            captured.interface_description
        ),
        link_type=captured.link_type,
        ip_version=4,
        source_ip="",
        destination_ip="",
        protocol=0,
        source_port=None,
        destination_port=None,
        tcp_sequence=None,
        tcp_acknowledgment=None,
        tcp_flags="",
        tcp_payload=b"",
        parse_status="FAILED",
        parse_note="",
    )

    if len(payload) < 20:
        base["parse_note"] = (
            "IPv4 header terlalu pendek."
        )
        return NetworkPacket(**base)

    version = payload[0] >> 4
    ihl = (payload[0] & 0x0F) * 4

    if version != 4 or ihl < 20:
        base["parse_note"] = (
            "IPv4 version/IHL tidak valid."
        )
        return NetworkPacket(**base)

    if len(payload) < ihl:
        base["parse_note"] = (
            "IPv4 options/header tidak lengkap."
        )
        return NetworkPacket(**base)

    total_length = struct.unpack_from(
        "!H",
        payload,
        2,
    )[0]

    protocol = payload[9]

    source_ip = socket.inet_ntoa(
        payload[12:16]
    )
    destination_ip = socket.inet_ntoa(
        payload[16:20]
    )

    flags_fragment = struct.unpack_from(
        "!H",
        payload,
        6,
    )[0]

    fragment_offset = (
        flags_fragment & 0x1FFF
    )

    base.update({
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
    })

    if fragment_offset != 0:
        base["parse_status"] = "PARTIAL"
        base["parse_note"] = (
            "IPv4 non-initial fragment tidak "
            "diparsing sebagai TCP."
        )
        return NetworkPacket(**base)

    if protocol != 6:
        base["parse_status"] = "SUCCESS"
        base["parse_note"] = (
            "Bukan TCP."
        )
        return NetworkPacket(**base)

    (
        source_port,
        destination_port,
        sequence,
        acknowledgment,
        tcp_flags,
        tcp_payload,
        note,
    ) = parse_tcp_segment(
        payload,
        ihl,
        total_length,
    )

    base.update({
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_sequence": sequence,
        "tcp_acknowledgment": acknowledgment,
        "tcp_flags": tcp_flags,
        "tcp_payload": tcp_payload,
        "parse_status": (
            "SUCCESS"
            if source_port is not None
            else "FAILED"
        ),
        "parse_note": note,
    })

    return NetworkPacket(**base)


def walk_ipv6_next_header(
    payload: bytes,
    offset: int,
    next_header: int,
) -> tuple[int, int, str]:
    extension_headers = {
        0,
        43,
        44,
        50,
        51,
        60,
        135,
    }

    current_offset = offset
    current_header = next_header

    for _ in range(12):
        if current_header not in extension_headers:
            return (
                current_header,
                current_offset,
                "",
            )

        if current_header == 44:
            if len(payload) < current_offset + 8:
                return (
                    current_header,
                    current_offset,
                    "IPv6 fragment header tidak lengkap.",
                )

            current_header = payload[
                current_offset
            ]
            current_offset += 8
            continue

        if len(payload) < current_offset + 2:
            return (
                current_header,
                current_offset,
                "IPv6 extension header tidak lengkap.",
            )

        next_value = payload[current_offset]
        header_length_units = payload[
            current_offset + 1
        ]

        if current_header == 51:
            header_length = (
                header_length_units + 2
            ) * 4
        else:
            header_length = (
                header_length_units + 1
            ) * 8

        if len(payload) < (
            current_offset + header_length
        ):
            return (
                current_header,
                current_offset,
                "IPv6 extension length melebihi packet.",
            )

        current_header = next_value
        current_offset += header_length

    return (
        current_header,
        current_offset,
        "Terlalu banyak IPv6 extension header.",
    )


def parse_ipv6_packet(
    payload: bytes,
    captured: CapturedPacket,
) -> NetworkPacket:
    base = dict(
        packet_number=captured.packet_number,
        timestamp_epoch=(
            captured.timestamp_epoch
        ),
        timestamp_utc=epoch_to_utc(
            captured.timestamp_epoch
        ),
        interface_id=captured.interface_id,
        interface_name=(
            captured.interface_name
        ),
        interface_description=(
            captured.interface_description
        ),
        link_type=captured.link_type,
        ip_version=6,
        source_ip="",
        destination_ip="",
        protocol=0,
        source_port=None,
        destination_port=None,
        tcp_sequence=None,
        tcp_acknowledgment=None,
        tcp_flags="",
        tcp_payload=b"",
        parse_status="FAILED",
        parse_note="",
    )

    if len(payload) < 40:
        base["parse_note"] = (
            "IPv6 header terlalu pendek."
        )
        return NetworkPacket(**base)

    if payload[0] >> 4 != 6:
        base["parse_note"] = (
            "IPv6 version tidak valid."
        )
        return NetworkPacket(**base)

    payload_length = struct.unpack_from(
        "!H",
        payload,
        4,
    )[0]

    next_header = payload[6]

    source_ip = str(
        ipaddress.IPv6Address(
            payload[8:24]
        )
    )
    destination_ip = str(
        ipaddress.IPv6Address(
            payload[24:40]
        )
    )

    protocol, tcp_offset, extension_note = (
        walk_ipv6_next_header(
            payload,
            40,
            next_header,
        )
    )

    base.update({
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
    })

    if protocol != 6:
        base["parse_status"] = "SUCCESS"
        base["parse_note"] = (
            extension_note or "Bukan TCP."
        )
        return NetworkPacket(**base)

    if len(payload) < tcp_offset + 20:
        base["parse_note"] = (
            extension_note
            or "TCP header IPv6 tidak lengkap."
        )
        return NetworkPacket(**base)

    (
        source_port,
        destination_port,
        sequence,
        acknowledgment,
    ) = struct.unpack_from(
        "!HHII",
        payload,
        tcp_offset,
    )

    data_offset_byte = payload[
        tcp_offset + 12
    ]

    tcp_header_length = (
        data_offset_byte >> 4
    ) * 4

    flags = (
        ((data_offset_byte & 0x01) << 8)
        | payload[tcp_offset + 13]
    )

    payload_start = (
        tcp_offset + tcp_header_length
    )

    payload_end = min(
        len(payload),
        40 + payload_length,
    )

    tcp_payload = (
        payload[payload_start:payload_end]
        if payload_start <= payload_end
        else b""
    )

    base.update({
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_sequence": sequence,
        "tcp_acknowledgment": acknowledgment,
        "tcp_flags": flags_to_text(flags),
        "tcp_payload": tcp_payload,
        "parse_status": "SUCCESS",
        "parse_note": extension_note,
    })

    return NetworkPacket(**base)


def parse_network_packet(
    captured: CapturedPacket,
) -> NetworkPacket:
    (
        ethertype,
        network_payload,
        link_note,
    ) = parse_link_layer(
        captured.packet_data,
        captured.link_type,
    )

    if ethertype == 0x0800:
        result = parse_ipv4_packet(
            network_payload,
            captured,
        )
    elif ethertype == 0x86DD:
        result = parse_ipv6_packet(
            network_payload,
            captured,
        )
    else:
        result = NetworkPacket(
            packet_number=captured.packet_number,
            timestamp_epoch=(
                captured.timestamp_epoch
            ),
            timestamp_utc=epoch_to_utc(
                captured.timestamp_epoch
            ),
            interface_id=captured.interface_id,
            interface_name=(
                captured.interface_name
            ),
            interface_description=(
                captured.interface_description
            ),
            link_type=captured.link_type,
            ip_version=0,
            source_ip="",
            destination_ip="",
            protocol=0,
            source_port=None,
            destination_port=None,
            tcp_sequence=None,
            tcp_acknowledgment=None,
            tcp_flags="",
            tcp_payload=b"",
            parse_status="UNSUPPORTED",
            parse_note=(
                link_note
                or (
                    f"Ethertype/network protocol "
                    f"tidak didukung: {ethertype}"
                )
            ),
        )

    if link_note:
        result.parse_note = " | ".join(
            part
            for part in (
                link_note,
                result.parse_note,
            )
            if part
        )

    return result


def parse_modbus_adu(
    network: NetworkPacket,
    *,
    pcap_path: Path,
    modbus_port: int,
) -> list[dict[str, Any]]:
    if (
        network.source_port != modbus_port
        and network.destination_port
        != modbus_port
    ):
        return []

    payload = network.tcp_payload

    if not payload:
        return []

    direction = "UNKNOWN"

    if network.destination_port == modbus_port:
        direction = "REQUEST"
    elif network.source_port == modbus_port:
        direction = "RESPONSE"

    events: list[dict[str, Any]] = []
    offset = 0
    adu_index = 0

    while offset + 7 <= len(payload):
        (
            transaction_id,
            protocol_id,
            length,
        ) = struct.unpack_from(
            "!HHH",
            payload,
            offset,
        )

        total_adu_length = 6 + length

        if protocol_id != 0:
            if offset == 0:
                return []
            break

        if length < 2:
            events.append({
                "pcap_file": pcap_path.name,
                "packet_number": (
                    network.packet_number
                ),
                "adu_index": adu_index,
                "timestamp_utc": (
                    network.timestamp_utc
                ),
                "timestamp_epoch": (
                    network.timestamp_epoch
                ),
                "interface_id": (
                    network.interface_id
                ),
                "interface_name": (
                    network.interface_name
                ),
                "interface_description": (
                    network.interface_description
                ),
                "link_type": network.link_type,
                "source_ip": network.source_ip,
                "destination_ip": (
                    network.destination_ip
                ),
                "source_port": network.source_port,
                "destination_port": (
                    network.destination_port
                ),
                "tcp_sequence": (
                    network.tcp_sequence
                ),
                "tcp_acknowledgment": (
                    network.tcp_acknowledgment
                ),
                "tcp_flags": network.tcp_flags,
                "tcp_stream_key": (
                    canonical_tcp_stream_key(
                        network
                    )
                ),
                "direction": direction,
                "transaction_id": (
                    transaction_id
                ),
                "protocol_id": protocol_id,
                "mbap_length": length,
                "unit_id": "",
                "function_code": "",
                "function_name": "",
                "is_exception": "",
                "exception_code": "",
                "register_address": "",
                "quantity": "",
                "register_value": "",
                "register_values": "",
                "coil_value": "",
                "byte_count": "",
                "pdu_hex": "",
                "parse_status": "INCOMPLETE",
                "parse_note": (
                    "MBAP length kurang dari 2."
                ),
            })
            break

        if offset + total_adu_length > len(
            payload
        ):
            events.append({
                "pcap_file": pcap_path.name,
                "packet_number": (
                    network.packet_number
                ),
                "adu_index": adu_index,
                "timestamp_utc": (
                    network.timestamp_utc
                ),
                "timestamp_epoch": (
                    network.timestamp_epoch
                ),
                "interface_id": (
                    network.interface_id
                ),
                "interface_name": (
                    network.interface_name
                ),
                "interface_description": (
                    network.interface_description
                ),
                "link_type": network.link_type,
                "source_ip": network.source_ip,
                "destination_ip": (
                    network.destination_ip
                ),
                "source_port": network.source_port,
                "destination_port": (
                    network.destination_port
                ),
                "tcp_sequence": (
                    network.tcp_sequence
                ),
                "tcp_acknowledgment": (
                    network.tcp_acknowledgment
                ),
                "tcp_flags": network.tcp_flags,
                "tcp_stream_key": (
                    canonical_tcp_stream_key(
                        network
                    )
                ),
                "direction": direction,
                "transaction_id": (
                    transaction_id
                ),
                "protocol_id": protocol_id,
                "mbap_length": length,
                "unit_id": "",
                "function_code": "",
                "function_name": "",
                "is_exception": "",
                "exception_code": "",
                "register_address": "",
                "quantity": "",
                "register_value": "",
                "register_values": "",
                "coil_value": "",
                "byte_count": "",
                "pdu_hex": payload[
                    offset + 7:
                ].hex(),
                "parse_status": "INCOMPLETE",
                "parse_note": (
                    "Modbus ADU tersebar atau "
                    "terpotong pada TCP segment."
                ),
            })
            break

        unit_id = payload[offset + 6]
        pdu = payload[
            offset + 7:
            offset + total_adu_length
        ]

        if not pdu:
            break

        function_code = pdu[0]
        is_exception = (
            function_code & 0x80
        ) != 0

        base_function = (
            function_code & 0x7F
            if is_exception
            else function_code
        )

        event = {
            "pcap_file": pcap_path.name,
            "packet_number": (
                network.packet_number
            ),
            "adu_index": adu_index,
            "timestamp_utc": (
                network.timestamp_utc
            ),
            "timestamp_epoch": (
                network.timestamp_epoch
            ),
            "interface_id": (
                network.interface_id
            ),
            "interface_name": (
                network.interface_name
            ),
            "interface_description": (
                network.interface_description
            ),
            "link_type": network.link_type,
            "source_ip": network.source_ip,
            "destination_ip": (
                network.destination_ip
            ),
            "source_port": network.source_port,
            "destination_port": (
                network.destination_port
            ),
            "tcp_sequence": (
                network.tcp_sequence
            ),
            "tcp_acknowledgment": (
                network.tcp_acknowledgment
            ),
            "tcp_flags": network.tcp_flags,
            "tcp_stream_key": (
                canonical_tcp_stream_key(
                    network
                )
            ),
            "direction": direction,
            "transaction_id": transaction_id,
            "protocol_id": protocol_id,
            "mbap_length": length,
            "unit_id": unit_id,
            "function_code": function_code,
            "function_name": function_name(
                function_code
            ),
            "is_exception": is_exception,
            "exception_code": "",
            "register_address": "",
            "quantity": "",
            "register_value": "",
            "register_values": "",
            "coil_value": "",
            "byte_count": "",
            "pdu_hex": pdu.hex(),
            "parse_status": "SUCCESS",
            "parse_note": "",
        }

        if is_exception:
            event["exception_code"] = (
                pdu[1]
                if len(pdu) >= 2
                else ""
            )

        elif base_function in {1, 2, 3, 4}:
            if direction == "REQUEST":
                if len(pdu) >= 5:
                    (
                        reference,
                        quantity,
                    ) = struct.unpack_from(
                        "!HH",
                        pdu,
                        1,
                    )
                    event[
                        "register_address"
                    ] = reference
                    event["quantity"] = quantity
                else:
                    event["parse_status"] = (
                        "INCOMPLETE"
                    )

            elif direction == "RESPONSE":
                if len(pdu) >= 2:
                    byte_count = pdu[1]
                    event[
                        "byte_count"
                    ] = byte_count

                    data_bytes = pdu[
                        2:2 + byte_count
                    ]

                    if (
                        base_function in {3, 4}
                        and len(data_bytes) % 2
                        == 0
                    ):
                        values = [
                            struct.unpack_from(
                                "!H",
                                data_bytes,
                                position,
                            )[0]
                            for position in range(
                                0,
                                len(data_bytes),
                                2,
                            )
                        ]

                        event[
                            "register_values"
                        ] = values

        elif base_function == 5:
            if len(pdu) >= 5:
                address, value = (
                    struct.unpack_from(
                        "!HH",
                        pdu,
                        1,
                    )
                )
                event[
                    "register_address"
                ] = address
                event["coil_value"] = value
            else:
                event["parse_status"] = (
                    "INCOMPLETE"
                )

        elif base_function == 6:
            if len(pdu) >= 5:
                address, value = (
                    struct.unpack_from(
                        "!HH",
                        pdu,
                        1,
                    )
                )
                event[
                    "register_address"
                ] = address
                event[
                    "register_value"
                ] = value
            else:
                event["parse_status"] = (
                    "INCOMPLETE"
                )

        elif base_function == 15:
            if direction == "REQUEST":
                if len(pdu) >= 6:
                    (
                        address,
                        quantity,
                    ) = struct.unpack_from(
                        "!HH",
                        pdu,
                        1,
                    )
                    event[
                        "register_address"
                    ] = address
                    event[
                        "quantity"
                    ] = quantity
                    event[
                        "byte_count"
                    ] = pdu[5]
            elif len(pdu) >= 5:
                address, quantity = (
                    struct.unpack_from(
                        "!HH",
                        pdu,
                        1,
                    )
                )
                event[
                    "register_address"
                ] = address
                event["quantity"] = quantity

        elif base_function == 16:
            if direction == "REQUEST":
                if len(pdu) >= 6:
                    (
                        address,
                        quantity,
                    ) = struct.unpack_from(
                        "!HH",
                        pdu,
                        1,
                    )

                    byte_count = pdu[5]
                    register_data = pdu[
                        6:6 + byte_count
                    ]

                    values = [
                        struct.unpack_from(
                            "!H",
                            register_data,
                            position,
                        )[0]
                        for position in range(
                            0,
                            len(register_data) - 1,
                            2,
                        )
                    ]

                    event[
                        "register_address"
                    ] = address
                    event["quantity"] = quantity
                    event[
                        "byte_count"
                    ] = byte_count
                    event[
                        "register_values"
                    ] = values

            elif len(pdu) >= 5:
                address, quantity = (
                    struct.unpack_from(
                        "!HH",
                        pdu,
                        1,
                    )
                )
                event[
                    "register_address"
                ] = address
                event["quantity"] = quantity

        events.append(event)

        offset += total_adu_length
        adu_index += 1

    return events


def function_name(
    function_code: int,
) -> str:
    base = function_code & 0x7F

    names = {
        1: "READ_COILS",
        2: "READ_DISCRETE_INPUTS",
        3: "READ_HOLDING_REGISTERS",
        4: "READ_INPUT_REGISTERS",
        5: "WRITE_SINGLE_COIL",
        6: "WRITE_SINGLE_REGISTER",
        15: "WRITE_MULTIPLE_COILS",
        16: "WRITE_MULTIPLE_REGISTERS",
    }

    name = names.get(
        base,
        f"FUNCTION_{base}",
    )

    if function_code & 0x80:
        return f"{name}_EXCEPTION"

    return name


def canonical_tcp_stream_key(
    network: NetworkPacket,
) -> str:
    if (
        network.source_port is None
        or network.destination_port is None
    ):
        return ""

    first = (
        network.source_ip,
        network.source_port,
    )
    second = (
        network.destination_ip,
        network.destination_port,
    )

    endpoints = sorted(
        [first, second],
        key=lambda item: (
            item[0],
            item[1],
        ),
    )

    return (
        f"{endpoints[0][0]}:"
        f"{endpoints[0][1]}<->"
        f"{endpoints[1][0]}:"
        f"{endpoints[1][1]}"
    )


def extract_capture(
    pcap_path: Path,
    *,
    modbus_port: int,
    issues: list[ValidationIssue],
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
]:
    packet_count = 0
    network_parse_failed = 0
    tcp_packet_count = 0
    modbus_events: list[dict[str, Any]] = []
    packet_timestamps: list[float] = []
    modbus_timestamps: list[float] = []
    interface_names: set[str] = set()
    interface_descriptions: set[str] = set()
    link_types: set[int] = set()

    try:
        for captured in iter_capture_packets(
            pcap_path
        ):
            packet_count += 1
            link_types.add(
                captured.link_type
            )

            if captured.interface_name:
                interface_names.add(
                    captured.interface_name
                )

            if captured.interface_description:
                interface_descriptions.add(
                    captured.interface_description
                )

            if (
                captured.timestamp_epoch
                is not None
            ):
                packet_timestamps.append(
                    captured.timestamp_epoch
                )

            network = parse_network_packet(
                captured
            )

            if network.parse_status == "FAILED":
                network_parse_failed += 1

            if network.protocol == 6:
                tcp_packet_count += 1

            packet_events = parse_modbus_adu(
                network,
                pcap_path=pcap_path,
                modbus_port=modbus_port,
            )

            for event in packet_events:
                if isinstance(
                    event.get(
                        "timestamp_epoch"
                    ),
                    (int, float),
                ):
                    modbus_timestamps.append(
                        float(
                            event[
                                "timestamp_epoch"
                            ]
                        )
                    )

            modbus_events.extend(
                packet_events
            )

    except Exception as error:
        issues.append(
            ValidationIssue(
                severity="ERROR",
                category="PCAP_PARSE",
                source_file=str(pcap_path),
                record_reference="FILE",
                field="",
                issue=(
                    f"{type(error).__name__}: "
                    f"{error}"
                ),
            )
        )

        return ({
            "pcap_file": pcap_path.name,
            "pcap_relative_path": relative_path(
                WORKING_DIR,
                pcap_path,
            ),
            "size_bytes": pcap_path.stat().st_size,
            "sha256": sha256_file(pcap_path),
            "parse_status": "FAILED",
            "packet_count": packet_count,
            "tcp_packet_count": tcp_packet_count,
            "modbus_event_count": len(
                modbus_events
            ),
            "fc06_request_count": 0,
            "fc06_response_count": 0,
            "first_packet_timestamp_utc": "",
            "last_packet_timestamp_utc": "",
            "first_modbus_timestamp_utc": "",
            "last_modbus_timestamp_utc": "",
            "interface_names": sorted(
                interface_names
            ),
            "interface_descriptions": sorted(
                interface_descriptions
            ),
            "link_types": sorted(link_types),
            "network_parse_failed_count": (
                network_parse_failed
            ),
            "error_message": (
                f"{type(error).__name__}: "
                f"{error}"
            ),
        }, modbus_events)

    fc06_requests = [
        event
        for event in modbus_events
        if (
            event.get("function_code") == 6
            and event.get("direction")
            == "REQUEST"
        )
    ]

    fc06_responses = [
        event
        for event in modbus_events
        if (
            event.get("function_code") == 6
            and event.get("direction")
            == "RESPONSE"
        )
    ]

    summary = {
        "pcap_file": pcap_path.name,
        "pcap_relative_path": relative_path(
            WORKING_DIR,
            pcap_path,
        ),
        "size_bytes": pcap_path.stat().st_size,
        "sha256": sha256_file(pcap_path),
        "parse_status": "SUCCESS",
        "packet_count": packet_count,
        "tcp_packet_count": tcp_packet_count,
        "modbus_event_count": len(
            modbus_events
        ),
        "fc06_request_count": len(
            fc06_requests
        ),
        "fc06_response_count": len(
            fc06_responses
        ),
        "first_packet_timestamp_utc": (
            epoch_to_utc(
                min(packet_timestamps)
            )
            if packet_timestamps
            else ""
        ),
        "last_packet_timestamp_utc": (
            epoch_to_utc(
                max(packet_timestamps)
            )
            if packet_timestamps
            else ""
        ),
        "first_modbus_timestamp_utc": (
            epoch_to_utc(
                min(modbus_timestamps)
            )
            if modbus_timestamps
            else ""
        ),
        "last_modbus_timestamp_utc": (
            epoch_to_utc(
                max(modbus_timestamps)
            )
            if modbus_timestamps
            else ""
        ),
        "interface_names": sorted(
            interface_names
        ),
        "interface_descriptions": sorted(
            interface_descriptions
        ),
        "link_types": sorted(link_types),
        "network_parse_failed_count": (
            network_parse_failed
        ),
        "error_message": "",
    }

    return summary, modbus_events


# =========================================================
# PHASE DAN TIMELINE
# =========================================================

def normalize_phase_rows(
    path: Path,
    fieldnames: list[str],
    rows: list[dict[str, str]],
    issues: list[ValidationIssue],
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []

    for row_number, row in enumerate(
        rows,
        start=2,
    ):
        timestamp = canonical_timestamp(
            row.get("event_timestamp")
        )

        if timestamp is None:
            issues.append(
                ValidationIssue(
                    severity="WARNING",
                    category="PHASE_TIMESTAMP",
                    source_file=str(path),
                    record_reference=(
                        f"CSV_ROW_{row_number}"
                    ),
                    field="event_timestamp",
                    issue=(
                        "Timestamp phase tidak valid."
                    ),
                    observed_value=str(
                        row.get(
                            "event_timestamp",
                            "",
                        )
                    ),
                )
            )

            timestamp = str(
                row.get(
                    "event_timestamp",
                    "",
                )
            )

        normalized.append({
            "event_timestamp": timestamp,
            "experiment_id": row.get(
                "experiment_id",
                "",
            ),
            "collector_session_id": row.get(
                "collector_session_id",
                "",
            ),
            "event_type": row.get(
                "event_type",
                "",
            ),
            "experiment_phase": row.get(
                "experiment_phase",
                "",
            ),
            "source": row.get(
                "source",
                "",
            ),
            "note": row.get(
                "note",
                "",
            ),
            "_source_csv_row": row_number,
        })

    return normalized


def assign_phase_to_timestamp(
    timestamp_value: Any,
    phase_events: list[dict[str, Any]],
) -> str:
    timestamp = parse_datetime(
        timestamp_value
    )

    if timestamp is None:
        return ""

    selected_phase = ""

    for event in phase_events:
        event_time = parse_datetime(
            event.get("event_timestamp")
        )

        if event_time is None:
            continue

        if event_time <= timestamp:
            selected_phase = str(
                event.get(
                    "experiment_phase",
                    "",
                )
            )
        else:
            break

    return selected_phase


def build_candidate_timeline(
    paired_rows: list[dict[str, Any]],
    phase_events: list[dict[str, Any]],
    modbus_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []

    for event in phase_events:
        timeline.append({
            "timestamp_utc": event.get(
                "event_timestamp"
            ),
            "source_type": "PHASE_LOG",
            "event_type": event.get(
                "event_type"
            ),
            "experiment_phase": event.get(
                "experiment_phase"
            ),
            "collection_id": "",
            "collection_sequence": "",
            "source_ip": "",
            "destination_ip": "",
            "source_port": "",
            "destination_port": "",
            "tcp_stream_key": "",
            "modbus_transaction_id": "",
            "modbus_function_code": "",
            "modbus_register_address": "",
            "modbus_register_value": "",
            "original_bottle_count": "",
            "sent_bottle_count": "",
            "bottle_count_from_pi": "",
            "total_bottle": "",
            "read_status": "",
            "note": event.get("note", ""),
            "provenance_file": (
                "working/metadata/"
                "experiment_event_log.csv"
            ),
            "provenance_record": event.get(
                "_source_csv_row",
                "",
            ),
        })

    for row in paired_rows:
        timeline.append({
            "timestamp_utc": row.get(
                "cycle_completed_at"
            ),
            "source_type": (
                "CROSS_LAYER_COLLECTION"
            ),
            "event_type": (
                "PAIRED_COLLECTION_RECORD"
            ),
            "experiment_phase": row.get(
                "experiment_phase"
            ),
            "collection_id": row.get(
                "collection_id"
            ),
            "collection_sequence": row.get(
                "collection_sequence"
            ),
            "source_ip": "",
            "destination_ip": "",
            "source_port": "",
            "destination_port": "",
            "tcp_stream_key": "",
            "modbus_transaction_id": "",
            "modbus_function_code": "",
            "modbus_register_address": "",
            "modbus_register_value": "",
            "original_bottle_count": (
                row.get(
                    "original_bottle_count"
                )
            ),
            "sent_bottle_count": row.get(
                "sent_bottle_count"
            ),
            "bottle_count_from_pi": row.get(
                "bottle_count_from_pi"
            ),
            "total_bottle": row.get(
                "total_bottle"
            ),
            "read_status": (
                f"raspi={row.get('raspi_read_status', '')};"
                f"openplc={row.get('openplc_read_status', '')}"
            ),
            "note": (
                f"source_match="
                f"{normalize_csv_output(row.get('source_match'))};"
                f"cross_layer_match="
                f"{normalize_csv_output(row.get('cross_layer_match'))};"
                f"plc_internal_match="
                f"{normalize_csv_output(row.get('plc_internal_match'))}"
            ),
            "provenance_file": (
                "working/raw/raspi_evidence.csv"
                " + working/raw/"
                "openplc_evidence.csv"
            ),
            "provenance_record": row.get(
                "collection_sequence"
            ),
        })

    for event in modbus_events:
        function_code = parse_int(
            event.get("function_code")
        )

        if function_code not in {
            5,
            6,
            15,
            16,
        }:
            continue

        timeline.append({
            "timestamp_utc": event.get(
                "timestamp_utc"
            ),
            "source_type": "PCAP_MODBUS",
            "event_type": (
                f"{event.get('direction', '')}_"
                f"{event.get('function_name', '')}"
            ),
            "experiment_phase": (
                assign_phase_to_timestamp(
                    event.get(
                        "timestamp_utc"
                    ),
                    phase_events,
                )
            ),
            "collection_id": "",
            "collection_sequence": "",
            "source_ip": event.get(
                "source_ip"
            ),
            "destination_ip": event.get(
                "destination_ip"
            ),
            "source_port": event.get(
                "source_port"
            ),
            "destination_port": event.get(
                "destination_port"
            ),
            "tcp_stream_key": event.get(
                "tcp_stream_key"
            ),
            "modbus_transaction_id": (
                event.get(
                    "transaction_id"
                )
            ),
            "modbus_function_code": (
                event.get("function_code")
            ),
            "modbus_register_address": (
                event.get(
                    "register_address"
                )
            ),
            "modbus_register_value": (
                event.get(
                    "register_value"
                )
            ),
            "original_bottle_count": "",
            "sent_bottle_count": "",
            "bottle_count_from_pi": "",
            "total_bottle": "",
            "read_status": event.get(
                "parse_status"
            ),
            "note": (
                f"pcap={event.get('pcap_file', '')};"
                f"packet={event.get('packet_number', '')};"
                f"direction={event.get('direction', '')}"
            ),
            "provenance_file": (
                "working/raw/"
                f"{event.get('pcap_file', '')}"
            ),
            "provenance_record": event.get(
                "packet_number"
            ),
        })

    def sort_key(row: dict[str, Any]) -> tuple[
        datetime,
        str,
    ]:
        parsed = parse_datetime(
            row.get("timestamp_utc")
        )

        return (
            parsed
            or datetime.max.replace(
                tzinfo=timezone.utc
            ),
            str(row.get("source_type", "")),
        )

    timeline.sort(key=sort_key)

    for sequence, row in enumerate(
        timeline,
        start=1,
    ):
        row["timeline_sequence"] = sequence

    return timeline


# =========================================================
# SUMMARY DAN MANIFEST OUTPUT
# =========================================================

def count_value(
    rows: list[dict[str, Any]],
    field: str,
    expected: Any,
) -> int:
    return sum(
        1
        for row in rows
        if row.get(field) == expected
    )


def build_output_manifest(
    output_dir: Path,
) -> None:
    manifest_path = (
        output_dir
        / "examination_manifest.csv"
    )

    hash_path = (
        output_dir
        / "examination_manifest.sha256.txt"
    )

    files = [
        path
        for path in list_files(output_dir)
        if path not in {
            manifest_path,
            hash_path,
        }
    ]

    hashed_at = utc_now()

    rows = [
        {
            "relative_path": relative_path(
                output_dir,
                path,
            ),
            "size_bytes": path.stat().st_size,
            "hash_algorithm": "SHA-256",
            "sha256": sha256_file(path),
            "hashed_at_utc": hashed_at,
        }
        for path in files
    ]

    write_csv(
        manifest_path,
        [
            "relative_path",
            "size_bytes",
            "hash_algorithm",
            "sha256",
            "hashed_at_utc",
        ],
        rows,
    )

    hash_path.write_text(
        "SHA-256  "
        f"{sha256_file(manifest_path)}  "
        "examination_manifest.csv\n",
        encoding="utf-8",
    )


def append_chain_of_custody(
    custody_path: Path,
    *,
    operator: str,
    run_id: str,
    status: str,
    output_dir: Path,
) -> None:
    fieldnames = [
        "custody_id",
        "timestamp_utc",
        "person",
        "action",
        "source_location",
        "destination_location",
        "reason",
        "verification_reference",
        "status",
        "notes",
    ]

    if custody_path.exists():
        current_fields, rows = read_csv(
            custody_path
        )

        if current_fields != fieldnames:
            raise ValueError(
                "Schema chain_of_custody.csv "
                "tidak sesuai dengan script."
            )
    else:
        rows = []

    existing_numbers: list[int] = []

    for row in rows:
        value = str(
            row.get("custody_id", "")
        )

        if value.startswith("COC-"):
            parsed = parse_int(
                value.split("-", 1)[1]
            )

            if parsed is not None:
                existing_numbers.append(parsed)

    next_number = (
        max(existing_numbers, default=0)
        + 1
    )

    rows.append({
        "custody_id": (
            f"COC-{next_number:03d}"
        ),
        "timestamp_utc": utc_now(),
        "person": operator,
        "action": "EXAMINATION_COMPLETED",
        "source_location": str(
            WORKING_DIR
        ),
        "destination_location": str(
            output_dir
        ),
        "reason": (
            "Pemeriksaan, normalisasi, pairing, "
            "ekstraksi PCAP, dan penyusunan "
            "candidate timeline."
        ),
        "verification_reference": (
            "analysis/examination/"
            "examination_manifest.csv"
        ),
        "status": status,
        "notes": f"run_id={run_id}",
    })

    write_csv(
        custody_path,
        fieldnames,
        rows,
    )


# =========================================================
# ARGUMEN
# =========================================================

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Melakukan seluruh tahap Examination "
            "pada working copy DFIR."
        )
    )

    parser.add_argument(
        "--operator",
        required=True,
        help=(
            "Nama operator yang menjalankan "
            "Examination."
        ),
    )

    parser.add_argument(
        "--modbus-port",
        type=int,
        default=DEFAULT_MODBUS_PORT,
        help=(
            "Port Modbus TCP. Default: 502."
        ),
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Hapus dan buat ulang folder "
            "analysis/examination."
        ),
    )

    parser.add_argument(
        "--allow-no-pcap",
        action="store_true",
        help=(
            "Izinkan Examination selesai tanpa "
            "PCAP. Default: PCAP wajib."
        ),
    )

    parser.add_argument(
        "--append-custody",
        action="store_true",
        help=(
            "Tambahkan record EXAMINATION_COMPLETED "
            "ke preservation/chain_of_custody.csv."
        ),
    )

    return parser.parse_args()


# =========================================================
# MAIN
# =========================================================

def main() -> int:
    args = parse_arguments()
    run_id = create_run_id()
    started_at = utc_now()
    issues: list[ValidationIssue] = []
    log_lines: list[str] = []

    def log(message: str) -> None:
        print(message)
        log_lines.append(
            f"{utc_now()} {message}"
        )

    try:
        if ANALYSIS_DIR.name.lower() != "analysis":
            raise RuntimeError(
                "Script harus diletakkan di dalam "
                "folder analysis."
            )

        for required_dir in (
            MASTER_RAW_DIR,
            MASTER_METADATA_DIR,
            WORKING_RAW_DIR,
            WORKING_METADATA_DIR,
            PRESERVATION_DIR,
        ):
            if not required_dir.is_dir():
                raise FileNotFoundError(
                    f"Folder wajib tidak ditemukan: "
                    f"{required_dir}"
                )

        remove_output_directory(
            OUTPUT_DIR,
            force=args.force,
        )

        log("=" * 76)
        log(" DFIR EXAMINATION")
        log("=" * 76)
        log(f"Case root : {CASE_ROOT}")
        log(f"Run ID    : {run_id}")
        log(f"Operator  : {args.operator}")

        # -------------------------------------------------
        # 1. Verifikasi working terhadap master
        # -------------------------------------------------

        master_inventory = (
            build_hash_inventory(
                MASTER_DIR
            )
        )

        working_inventory = (
            build_hash_inventory(
                WORKING_DIR
            )
        )

        working_verification = (
            compare_hash_inventories(
                master_inventory,
                working_inventory,
            )
        )

        write_csv(
            OUTPUT_DIR
            / (
                "working_pre_examination_"
                "verification.csv"
            ),
            [
                "relative_path",
                "master_size_bytes",
                "working_size_bytes",
                "master_sha256",
                "working_sha256",
                "verification",
                "verified_at_utc",
                "note",
            ],
            working_verification,
        )

        verification_failures = [
            row
            for row in working_verification
            if row["verification"] != "MATCH"
        ]

        if verification_failures:
            raise RuntimeError(
                "Working copy tidak lagi identik "
                "dengan master. Periksa "
                "working_pre_examination_verification.csv."
            )

        log(
            "[OK] Working copy identik dengan master."
        )

        # -------------------------------------------------
        # 2. Muat metadata dan file utama
        # -------------------------------------------------

        session_manifest_path = (
            find_unique_file(
                WORKING_METADATA_DIR,
                "session_manifest.json",
            )
        )

        session_manifest = json.loads(
            session_manifest_path.read_text(
                encoding="utf-8"
            )
        )

        scenario = str(
            session_manifest.get(
                "scenario",
                CASE_ROOT.name,
            )
        )

        experiment_id = str(
            session_manifest.get(
                "experiment_id",
                "UNSPECIFIED",
            )
        )

        session_id = str(
            session_manifest.get(
                "collector_session_id",
                "UNSPECIFIED",
            )
        )

        raspi_path = find_unique_file(
            WORKING_RAW_DIR,
            "raspi_evidence.csv",
        )

        openplc_path = find_unique_file(
            WORKING_RAW_DIR,
            "openplc_evidence.csv",
        )

        phase_path = find_unique_file(
            WORKING_METADATA_DIR,
            "experiment_event_log.csv",
        )

        (
            raspi_fields,
            raspi_raw_rows,
        ) = read_csv(raspi_path)

        (
            openplc_fields,
            openplc_raw_rows,
        ) = read_csv(openplc_path)

        (
            phase_fields,
            phase_raw_rows,
        ) = read_csv(phase_path)

        # -------------------------------------------------
        # 3. Validasi schema
        # -------------------------------------------------

        schema_rows = [
            *validate_schema(
                "RASPBERRY_PI",
                raspi_path,
                raspi_fields,
                REQUIRED_RASPI_COLUMNS,
            ),
            *validate_schema(
                "OPENPLC",
                openplc_path,
                openplc_fields,
                REQUIRED_OPENPLC_COLUMNS,
            ),
            *validate_schema(
                "PHASE_LOG",
                phase_path,
                phase_fields,
                REQUIRED_PHASE_COLUMNS,
            ),
        ]

        write_csv(
            OUTPUT_DIR
            / "schema_validation.csv",
            [
                "source",
                "file",
                "column",
                "requirement",
                "status",
            ],
            schema_rows,
        )

        missing_required = [
            row
            for row in schema_rows
            if (
                row["requirement"] == "REQUIRED"
                and row["status"] == "MISSING"
            )
        ]

        if missing_required:
            raise RuntimeError(
                "Kolom wajib tidak lengkap. "
                "Periksa schema_validation.csv."
            )

        log("[OK] Schema wajib tersedia.")

        # -------------------------------------------------
        # 4. Normalisasi
        # -------------------------------------------------

        normalized_raspi = normalize_rows(
            "RASPBERRY_PI",
            raspi_path,
            raspi_fields,
            raspi_raw_rows,
            issues,
        )

        normalized_openplc = normalize_rows(
            "OPENPLC",
            openplc_path,
            openplc_fields,
            openplc_raw_rows,
            issues,
        )

        validate_collection_sequence(
            "RASPBERRY_PI",
            normalized_raspi,
            raspi_path,
            issues,
        )

        validate_collection_sequence(
            "OPENPLC",
            normalized_openplc,
            openplc_path,
            issues,
        )

        write_csv(
            OUTPUT_DIR
            / "normalized_raspi.csv",
            [
                *raspi_fields,
                "_source_csv_row",
            ],
            normalized_raspi,
        )

        write_csv(
            OUTPUT_DIR
            / "normalized_openplc.csv",
            [
                *openplc_fields,
                "_source_csv_row",
            ],
            normalized_openplc,
        )

        log(
            f"[OK] Normalisasi selesai: "
            f"raspi={len(normalized_raspi)}, "
            f"openplc={len(normalized_openplc)}."
        )

        # -------------------------------------------------
        # 5. Index, duplicate, dan pairing
        # -------------------------------------------------

        (
            raspi_index,
            raspi_duplicates,
        ) = index_rows_by_collection_id(
            "RASPBERRY_PI",
            normalized_raspi,
            raspi_path,
            issues,
        )

        (
            openplc_index,
            openplc_duplicates,
        ) = index_rows_by_collection_id(
            "OPENPLC",
            normalized_openplc,
            openplc_path,
            issues,
        )

        duplicate_rows = [
            *raspi_duplicates,
            *openplc_duplicates,
        ]

        write_csv(
            OUTPUT_DIR
            / "duplicate_collection_ids.csv",
            [
                "source",
                "collection_id",
                "collection_sequence",
                "source_csv_row",
            ],
            duplicate_rows,
        )

        (
            paired_rows,
            unpaired_raspi,
            unpaired_openplc,
        ) = build_paired_rows(
            raspi_index,
            openplc_index,
        )

        write_csv(
            OUTPUT_DIR
            / "paired_cross_layer_evidence.csv",
            PAIR_FIELDS,
            paired_rows,
        )

        write_csv(
            OUTPUT_DIR
            / "unpaired_raspi.csv",
            [
                *raspi_fields,
                "_source_csv_row",
            ],
            unpaired_raspi,
        )

        write_csv(
            OUTPUT_DIR
            / "unpaired_openplc.csv",
            [
                *openplc_fields,
                "_source_csv_row",
            ],
            unpaired_openplc,
        )

        if unpaired_raspi:
            issues.append(
                ValidationIssue(
                    severity="ERROR",
                    category="PAIRING",
                    source_file=str(raspi_path),
                    record_reference="FILE",
                    field="collection_id",
                    issue=(
                        f"{len(unpaired_raspi)} "
                        "record Raspberry Pi tidak "
                        "memiliki pasangan OpenPLC."
                    ),
                )
            )

        if unpaired_openplc:
            issues.append(
                ValidationIssue(
                    severity="ERROR",
                    category="PAIRING",
                    source_file=str(openplc_path),
                    record_reference="FILE",
                    field="collection_id",
                    issue=(
                        f"{len(unpaired_openplc)} "
                        "record OpenPLC tidak memiliki "
                        "pasangan Raspberry Pi."
                    ),
                )
            )

        log(
            f"[OK] Pairing selesai: "
            f"paired={len(paired_rows)}, "
            f"unpaired_raspi={len(unpaired_raspi)}, "
            f"unpaired_openplc="
            f"{len(unpaired_openplc)}."
        )

        # -------------------------------------------------
        # 6. Phase extraction
        # -------------------------------------------------

        phase_events = normalize_phase_rows(
            phase_path,
            phase_fields,
            phase_raw_rows,
            issues,
        )

        phase_events.sort(
            key=lambda row: (
                parse_datetime(
                    row.get(
                        "event_timestamp"
                    )
                )
                or datetime.max.replace(
                    tzinfo=timezone.utc
                )
            )
        )

        write_csv(
            OUTPUT_DIR
            / "phase_events.csv",
            [
                "event_timestamp",
                "experiment_id",
                "collector_session_id",
                "event_type",
                "experiment_phase",
                "source",
                "note",
                "_source_csv_row",
            ],
            phase_events,
        )

        log(
            f"[OK] Phase event diekstrak: "
            f"{len(phase_events)}."
        )

        # -------------------------------------------------
        # 7. PCAP extraction
        # -------------------------------------------------

        pcap_files = [
            path
            for path in list_files(
                WORKING_RAW_DIR
            )
            if path.suffix.lower()
            in {".pcap", ".pcapng"}
        ]

        if not pcap_files and not args.allow_no_pcap:
            raise FileNotFoundError(
                "Tidak ditemukan file PCAP/PCAPNG "
                "pada working/raw."
            )

        pcap_summaries: list[
            dict[str, Any]
        ] = []

        modbus_events: list[
            dict[str, Any]
        ] = []

        for pcap_path in pcap_files:
            summary, events = extract_capture(
                pcap_path,
                modbus_port=args.modbus_port,
                issues=issues,
            )

            pcap_summaries.append(summary)
            modbus_events.extend(events)

        pcap_summary_fields = [
            "pcap_file",
            "pcap_relative_path",
            "size_bytes",
            "sha256",
            "parse_status",
            "packet_count",
            "tcp_packet_count",
            "modbus_event_count",
            "fc06_request_count",
            "fc06_response_count",
            "first_packet_timestamp_utc",
            "last_packet_timestamp_utc",
            "first_modbus_timestamp_utc",
            "last_modbus_timestamp_utc",
            "interface_names",
            "interface_descriptions",
            "link_types",
            "network_parse_failed_count",
            "error_message",
        ]

        write_csv(
            OUTPUT_DIR / "pcap_summary.csv",
            pcap_summary_fields,
            pcap_summaries,
        )

        modbus_event_fields = [
            "pcap_file",
            "packet_number",
            "adu_index",
            "timestamp_utc",
            "timestamp_epoch",
            "interface_id",
            "interface_name",
            "interface_description",
            "link_type",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "tcp_sequence",
            "tcp_acknowledgment",
            "tcp_flags",
            "tcp_stream_key",
            "direction",
            "transaction_id",
            "protocol_id",
            "mbap_length",
            "unit_id",
            "function_code",
            "function_name",
            "is_exception",
            "exception_code",
            "register_address",
            "quantity",
            "register_value",
            "register_values",
            "coil_value",
            "byte_count",
            "pdu_hex",
            "parse_status",
            "parse_note",
        ]

        write_csv(
            OUTPUT_DIR
            / "modbus_events.csv",
            modbus_event_fields,
            modbus_events,
        )

        write_events = [
            event
            for event in modbus_events
            if parse_int(
                event.get("function_code")
            )
            in {5, 6, 15, 16}
        ]

        write_csv(
            OUTPUT_DIR
            / "modbus_write_events.csv",
            modbus_event_fields,
            write_events,
        )

        log(
            f"[OK] PCAP diekstrak: "
            f"files={len(pcap_files)}, "
            f"modbus_events={len(modbus_events)}, "
            f"write_events={len(write_events)}."
        )

        # -------------------------------------------------
        # 8. Candidate timeline
        # -------------------------------------------------

        timeline = build_candidate_timeline(
            paired_rows,
            phase_events,
            modbus_events,
        )

        write_csv(
            OUTPUT_DIR
            / "candidate_timeline.csv",
            TIMELINE_FIELDS,
            timeline,
        )

        log(
            f"[OK] Candidate timeline dibuat: "
            f"{len(timeline)} event."
        )

        # -------------------------------------------------
        # 9. Validation issues
        # -------------------------------------------------

        write_csv(
            OUTPUT_DIR
            / "validation_issues.csv",
            [
                "severity",
                "category",
                "source_file",
                "record_reference",
                "field",
                "issue",
                "observed_value",
                "expected_value",
            ],
            (
                issue.__dict__
                for issue in issues
            ),
        )

        critical_issues = [
            issue
            for issue in issues
            if issue.severity == "ERROR"
        ]

        pcap_failures = [
            row
            for row in pcap_summaries
            if row.get(
                "parse_status"
            ) != "SUCCESS"
        ]

        if pcap_failures:
            critical_issues.extend(
                ValidationIssue(
                    severity="ERROR",
                    category="PCAP_PARSE",
                    source_file=str(
                        row.get(
                            "pcap_relative_path",
                            "",
                        )
                    ),
                    record_reference="FILE",
                    field="",
                    issue=str(
                        row.get(
                            "error_message",
                            "PCAP parse gagal.",
                        )
                    ),
                )
                for row in pcap_failures
            )

        examination_status = (
            "READY_FOR_ANALYSIS"
            if not critical_issues
            else "REQUIRES_REVIEW"
        )

        # -------------------------------------------------
        # 10. Summary
        # -------------------------------------------------

        sampling_skews = [
            value
            for value in (
                parse_float(
                    row.get(
                        "sampling_skew_ms"
                    )
                )
                for row in paired_rows
            )
            if value is not None
        ]

        source_ages = [
            value
            for value in (
                parse_float(
                    row.get("source_age_ms")
                )
                for row in normalized_raspi
            )
            if value is not None
        ]

        fc06_requests = [
            event
            for event in modbus_events
            if (
                parse_int(
                    event.get(
                        "function_code"
                    )
                )
                == 6
                and event.get("direction")
                == "REQUEST"
            )
        ]

        fc06_responses = [
            event
            for event in modbus_events
            if (
                parse_int(
                    event.get(
                        "function_code"
                    )
                )
                == 6
                and event.get("direction")
                == "RESPONSE"
            )
        ]

        phase_counts: dict[str, int] = {}

        for row in paired_rows:
            phase = str(
                row.get(
                    "experiment_phase",
                    "",
                )
            )

            phase_counts[phase] = (
                phase_counts.get(phase, 0)
                + 1
            )

        summary = {
            "examination_schema_version": (
                EXAMINATION_SCHEMA_VERSION
            ),
            "run_id": run_id,
            "started_at_utc": started_at,
            "completed_at_utc": utc_now(),
            "operator": args.operator,
            "case_root": str(CASE_ROOT),
            "scenario": scenario,
            "experiment_id": experiment_id,
            "collector_session_id": session_id,
            "input": {
                "master_directory": str(
                    MASTER_DIR
                ),
                "working_directory": str(
                    WORKING_DIR
                ),
                "working_verified_against_master": True,
                "pcap_files": [
                    relative_path(
                        WORKING_DIR,
                        path,
                    )
                    for path in pcap_files
                ],
            },
            "records": {
                "raspi": len(
                    normalized_raspi
                ),
                "openplc": len(
                    normalized_openplc
                ),
                "paired": len(paired_rows),
                "unpaired_raspi": len(
                    unpaired_raspi
                ),
                "unpaired_openplc": len(
                    unpaired_openplc
                ),
                "duplicate_collection_id_records": (
                    len(duplicate_rows)
                ),
                "phase_events": len(
                    phase_events
                ),
                "candidate_timeline_events": (
                    len(timeline)
                ),
            },
            "factual_checks": {
                "source_match_true": (
                    count_value(
                        paired_rows,
                        "source_match",
                        True,
                    )
                ),
                "source_match_false": (
                    count_value(
                        paired_rows,
                        "source_match",
                        False,
                    )
                ),
                "cross_layer_match_true": (
                    count_value(
                        paired_rows,
                        "cross_layer_match",
                        True,
                    )
                ),
                "cross_layer_match_false": (
                    count_value(
                        paired_rows,
                        "cross_layer_match",
                        False,
                    )
                ),
                "plc_internal_match_true": (
                    count_value(
                        paired_rows,
                        "plc_internal_match",
                        True,
                    )
                ),
                "plc_internal_match_false": (
                    count_value(
                        paired_rows,
                        "plc_internal_match",
                        False,
                    )
                ),
                "raspi_acquisition_success": (
                    count_value(
                        paired_rows,
                        "raspi_acquisition_success",
                        True,
                    )
                ),
                "openplc_acquisition_success": (
                    count_value(
                        paired_rows,
                        "openplc_acquisition_success",
                        True,
                    )
                ),
            },
            "timing": {
                "median_sampling_skew_ms": (
                    safe_median(
                        sampling_skews
                    )
                ),
                "median_source_age_ms": (
                    safe_median(
                        source_ages
                    )
                ),
                "phase_record_counts": (
                    phase_counts
                ),
            },
            "pcap": {
                "file_count": len(
                    pcap_files
                ),
                "packet_count": sum(
                    int(
                        row.get(
                            "packet_count",
                            0,
                        )
                        or 0
                    )
                    for row in pcap_summaries
                ),
                "modbus_event_count": (
                    len(modbus_events)
                ),
                "write_event_count": (
                    len(write_events)
                ),
                "fc06_request_count": (
                    len(fc06_requests)
                ),
                "fc06_response_count": (
                    len(fc06_responses)
                ),
            },
            "validation": {
                "issue_count": len(issues),
                "error_count": sum(
                    1
                    for issue in issues
                    if issue.severity == "ERROR"
                ),
                "warning_count": sum(
                    1
                    for issue in issues
                    if issue.severity == "WARNING"
                ),
            },
            "examination_status": (
                examination_status
            ),
            "method_note": (
                "Output ini merupakan hasil "
                "Examination/derived evidence. "
                "Kesimpulan insiden dibuat pada "
                "tahap Analysis."
            ),
        }

        write_json(
            OUTPUT_DIR
            / "examination_summary.json",
            summary,
        )

        write_json(
            OUTPUT_DIR
            / "examination_run.json",
            {
                "run_id": run_id,
                "script_path": str(
                    SCRIPT_PATH
                ),
                "script_sha256": sha256_file(
                    SCRIPT_PATH
                ),
                "python_version": sys.version,
                "host": socket.gethostname(),
                "operator": args.operator,
                "started_at_utc": started_at,
                "completed_at_utc": utc_now(),
                "arguments": vars(args),
                "status": examination_status,
            },
        )

        log(
            f"[STATUS] {examination_status}"
        )

        log_path = (
            OUTPUT_DIR
            / "examination_log.txt"
        )

        log_path.write_text(
            "\n".join(log_lines) + "\n",
            encoding="utf-8",
        )

        build_output_manifest(
            OUTPUT_DIR
        )

        if args.append_custody:
            append_chain_of_custody(
                PRESERVATION_DIR
                / "chain_of_custody.csv",
                operator=args.operator,
                run_id=run_id,
                status=examination_status,
                output_dir=OUTPUT_DIR,
            )

        print("=" * 76)
        print(
            f"[SUCCESS] Examination selesai: "
            f"{examination_status}"
        )
        print(f"Output: {OUTPUT_DIR}")
        print("=" * 76)

        return (
            0
            if examination_status
            == "READY_FOR_ANALYSIS"
            else 2
        )

    except Exception as error:
        OUTPUT_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        failure_text = (
            "\n".join(log_lines)
            + "\n"
            + f"{utc_now()} [FATAL] "
            + f"{type(error).__name__}: "
            + f"{error}\n\n"
            + traceback.format_exc()
        )

        (
            OUTPUT_DIR
            / "examination_log.txt"
        ).write_text(
            failure_text,
            encoding="utf-8",
        )

        write_json(
            OUTPUT_DIR
            / "examination_run.json",
            {
                "run_id": run_id,
                "script_path": str(
                    SCRIPT_PATH
                ),
                "script_sha256": (
                    sha256_file(SCRIPT_PATH)
                ),
                "python_version": sys.version,
                "host": socket.gethostname(),
                "operator": args.operator,
                "started_at_utc": started_at,
                "completed_at_utc": utc_now(),
                "arguments": vars(args),
                "status": "FAILED",
                "error_type": (
                    type(error).__name__
                ),
                "error_message": str(error),
            },
        )

        print(
            f"[FATAL] {type(error).__name__}: "
            f"{error}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())
