#!/usr/bin/env python3
"""
analyze_testbed.py

Cross-scenario Analysis + initial Reporting untuk testbed DFIR
Raspberry Pi – Modbus TCP – OpenPLC.

Input utama adalah output Examination untuk:
- BASELINE
- PERLAKUAN_1_FDI

Script melakukan:
1. Verifikasi integritas output Examination.
2. Validasi status READY_FOR_ANALYSIS.
3. Analisis integrity per layer dan per fase.
4. Analisis availability akuisisi.
5. Penentuan technical attack window dari FC06 HR1024=value 1000.
6. Perhitungan propagation, persistence, dan recovery.
7. Korelasi source-network-control.
8. Perbandingan Baseline vs Perlakuan 1.
9. Penyusunan final incident timeline.
10. Pembuatan findings, summary, report Markdown/HTML, dan manifest SHA-256.

Tidak memerlukan library eksternal.

Contoh pemakaian auto-discovery (script diletakkan di DFIR/analysis/):

    py analyze_testbed.py --operator "Yunan Yuga Pratama"

Contoh pemakaian path eksplisit:

    py analyze_testbed.py `
      --operator "Yunan Yuga Pratama" `
      --baseline-examination "...\\BASELINE\\collector-...\\analysis\\examination" `
      --treatment-examination "...\\PERLAKUAN_1_FDI\\collector-...\\analysis\\examination" `
      --output "...\\DFIR\\analysis\\results\\BASELINE_vs_P1"
"""

from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import html
import json
import math
import shutil
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
DEFAULT_TARGET_REGISTER = 1024
DEFAULT_ATTACK_VALUE = 1000
DEFAULT_STABLE_RECORDS = 3
DEFAULT_CORRELATION_WINDOW_SECONDS = 2.5

REQUIRED_EXAMINATION_FILES = {
    "working_pre_examination_verification.csv",
    "validation_issues.csv",
    "paired_cross_layer_evidence.csv",
    "phase_events.csv",
    "pcap_summary.csv",
    "modbus_write_events.csv",
    "candidate_timeline.csv",
    "examination_summary.json",
    "examination_manifest.csv",
    "examination_manifest.sha256.txt",
}


@dataclass(frozen=True)
class ScenarioInput:
    label: str
    examination_dir: Path
    summary: dict[str, Any]
    paired: list[dict[str, str]]
    phase_events: list[dict[str, str]]
    pcap_summary: list[dict[str, str]]
    modbus_writes: list[dict[str, str]]
    candidate_timeline: list[dict[str, str]]
    preservation_notes: list[str]


@dataclass(frozen=True)
class AttackWindow:
    request_count: int
    response_count: int
    first_request: Optional[datetime]
    last_request: Optional[datetime]
    duration_seconds: Optional[float]
    mean_interval_seconds: Optional[float]
    median_interval_seconds: Optional[float]
    min_interval_seconds: Optional[float]
    max_interval_seconds: Optional[float]


@dataclass(frozen=True)
class RecoveryMetrics:
    first_false_observation: Optional[datetime]
    last_false_observation: Optional[datetime]
    first_normal_after_attack: Optional[datetime]
    stable_recovery_start: Optional[datetime]
    stable_recovery_confirmed_at: Optional[datetime]
    propagation_delay_seconds: Optional[float]
    false_value_persistence_seconds: Optional[float]
    first_normal_delay_seconds: Optional[float]
    stable_recovery_start_delay_seconds: Optional[float]
    stable_recovery_confirmation_seconds: Optional[float]
    false_observation_count: int
    stable_record_requirement: int


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        result = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def format_datetime(value: Optional[datetime]) -> str:
    if value is None:
        return ""
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


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
            return int(number) if number.is_integer() else None
        except ValueError:
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


def percent(numerator: int, denominator: int) -> Optional[float]:
    if denominator <= 0:
        return None
    return numerator / denominator * 100.0


def format_number(value: Any, decimals: int = 3) -> str:
    if value is None or value == "":
        return "N/A"
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return "N/A"
        return f"{value:.{decimals}f}"
    return str(value)


def format_percent(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value:.2f}%"


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"Header CSV tidak ditemukan: {path}")
        return list(reader.fieldnames), list(reader)


def write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: normalize_output(row.get(field)) for field in fieldnames})


def normalize_output(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (list, dict, tuple)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return value


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def ensure_output_dir(path: Path, force: bool) -> None:
    if path.exists() and any(path.iterdir()):
        if not force:
            raise RuntimeError(
                f"Folder output tidak kosong: {path}. Gunakan --force untuk membuat ulang."
            )
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def relative_or_absolute(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


# =========================================================
# DISCOVERY DAN VALIDASI INPUT
# =========================================================


def find_latest_examination(dfir_root: Path, scenario_folder: str) -> Path:
    base = dfir_root / "evidence" / scenario_folder
    candidates = [
        path
        for path in base.glob("collector-*/analysis/examination")
        if path.is_dir()
    ]
    if not candidates:
        raise FileNotFoundError(
            f"Tidak ditemukan examination untuk {scenario_folder} di {base}"
        )
    return max(candidates, key=lambda path: path.stat().st_mtime)


def verify_manifest_hash(examination_dir: Path) -> list[str]:
    issues: list[str] = []
    manifest_path = examination_dir / "examination_manifest.csv"
    manifest_hash_path = examination_dir / "examination_manifest.sha256.txt"

    hash_text = manifest_hash_path.read_text(encoding="utf-8", errors="replace").strip()
    tokens = hash_text.split()
    expected_manifest_hash = ""
    for token in tokens:
        if len(token) == 64 and all(char in "0123456789abcdefABCDEF" for char in token):
            expected_manifest_hash = token.lower()
            break

    if not expected_manifest_hash:
        issues.append("Hash examination_manifest.csv tidak dapat dibaca.")
    elif sha256_file(manifest_path) != expected_manifest_hash:
        issues.append("SHA-256 examination_manifest.csv tidak cocok.")

    _, rows = read_csv(manifest_path)
    for row in rows:
        relative_path = row.get("relative_path", "").replace("\\", "/")
        expected_hash = row.get("sha256", "").strip().lower()
        expected_size = parse_int(row.get("size_bytes"))
        target = examination_dir / Path(relative_path)
        if not target.is_file():
            issues.append(f"File manifest tidak ditemukan: {relative_path}")
            continue
        if expected_size is not None and target.stat().st_size != expected_size:
            issues.append(f"Ukuran file berubah: {relative_path}")
        if expected_hash and sha256_file(target) != expected_hash:
            issues.append(f"SHA-256 file berubah: {relative_path}")
    return issues


def load_preservation_notes(examination_dir: Path) -> list[str]:
    session_root = examination_dir.parent.parent.parent
    path = session_root / "preservation" / "preservation_notes.txt"
    if not path.is_file():
        return []
    lines: list[str] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("-"):
            value = stripped.lstrip("-").strip()
            if value and value not in lines:
                lines.append(value)
    return lines


def load_scenario(label: str, examination_dir: Path) -> ScenarioInput:
    examination_dir = examination_dir.resolve()
    missing = sorted(
        name for name in REQUIRED_EXAMINATION_FILES if not (examination_dir / name).is_file()
    )
    if missing:
        raise FileNotFoundError(
            f"Output Examination {label} tidak lengkap: {', '.join(missing)}"
        )

    manifest_issues = verify_manifest_hash(examination_dir)
    if manifest_issues:
        raise RuntimeError(
            f"Integritas output Examination {label} gagal: " + " | ".join(manifest_issues)
        )

    summary = json.loads(
        (examination_dir / "examination_summary.json").read_text(encoding="utf-8")
    )
    if summary.get("examination_status") != "READY_FOR_ANALYSIS":
        raise RuntimeError(
            f"{label} belum READY_FOR_ANALYSIS: {summary.get('examination_status')}"
        )

    _, pre_verify = read_csv(examination_dir / "working_pre_examination_verification.csv")
    failures = [row for row in pre_verify if row.get("verification") != "MATCH"]
    if failures:
        raise RuntimeError(f"Working verification {label} tidak seluruhnya MATCH.")

    _, validation_rows = read_csv(examination_dir / "validation_issues.csv")
    errors = [row for row in validation_rows if row.get("severity", "").upper() == "ERROR"]
    if errors:
        raise RuntimeError(f"{label} memiliki validation ERROR pada Examination.")

    _, pcap_rows = read_csv(examination_dir / "pcap_summary.csv")
    pcap_failures = [row for row in pcap_rows if row.get("parse_status") != "SUCCESS"]
    if pcap_failures:
        raise RuntimeError(f"PCAP {label} tidak seluruhnya berhasil diparsing.")

    _, paired = read_csv(examination_dir / "paired_cross_layer_evidence.csv")
    _, phases = read_csv(examination_dir / "phase_events.csv")
    _, writes = read_csv(examination_dir / "modbus_write_events.csv")
    _, timeline = read_csv(examination_dir / "candidate_timeline.csv")

    return ScenarioInput(
        label=label,
        examination_dir=examination_dir,
        summary=summary,
        paired=paired,
        phase_events=phases,
        pcap_summary=pcap_rows,
        modbus_writes=writes,
        candidate_timeline=timeline,
        preservation_notes=load_preservation_notes(examination_dir),
    )


# =========================================================
# METRIK SCENARIO
# =========================================================


def phase_order(phase: str) -> tuple[int, str]:
    order = {
        "BASELINE": 0,
        "PRE_ATTACK": 1,
        "ATTACK": 2,
        "RECOVERY": 3,
        "POST_RECOVERY": 4,
    }
    return order.get(phase, 99), phase


def build_integrity_rows(scenario: ScenarioInput) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    grouped["ALL"].extend(scenario.paired)
    for row in scenario.paired:
        grouped[row.get("experiment_phase", "UNSPECIFIED")].append(row)

    output: list[dict[str, Any]] = []
    for phase, rows in sorted(grouped.items(), key=lambda item: phase_order(item[0])):
        total = len(rows)
        source_true = sum(parse_bool(row.get("source_match")) is True for row in rows)
        source_false = sum(parse_bool(row.get("source_match")) is False for row in rows)
        cross_true = sum(parse_bool(row.get("cross_layer_match")) is True for row in rows)
        cross_false = sum(parse_bool(row.get("cross_layer_match")) is False for row in rows)
        plc_true = sum(parse_bool(row.get("plc_internal_match")) is True for row in rows)
        plc_false = sum(parse_bool(row.get("plc_internal_match")) is False for row in rows)
        output.append({
            "scenario": scenario.summary.get("scenario", scenario.label),
            "phase": phase,
            "record_count": total,
            "source_match_count": source_true,
            "source_mismatch_count": source_false,
            "source_integrity_rate_pct": percent(source_true, total),
            "cross_layer_match_count": cross_true,
            "cross_layer_mismatch_count": cross_false,
            "cross_layer_integrity_rate_pct": percent(cross_true, total),
            "plc_internal_match_count": plc_true,
            "plc_internal_mismatch_count": plc_false,
            "plc_internal_consistency_rate_pct": percent(plc_true, total),
        })
    return output


def calculate_sequence_gaps(rows: list[dict[str, str]]) -> tuple[int, list[int]]:
    values = sorted({value for value in (parse_int(row.get("collection_sequence")) for row in rows) if value is not None})
    if not values:
        return 0, []
    expected = set(range(values[0], values[-1] + 1))
    missing = sorted(expected - set(values))
    return len(missing), missing


def build_availability_rows(scenario: ScenarioInput) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    grouped["ALL"].extend(scenario.paired)
    for row in scenario.paired:
        grouped[row.get("experiment_phase", "UNSPECIFIED")].append(row)

    output: list[dict[str, Any]] = []
    for phase, rows in sorted(grouped.items(), key=lambda item: phase_order(item[0])):
        total = len(rows)
        raspi_success = sum(parse_bool(row.get("raspi_acquisition_success")) is True for row in rows)
        openplc_success = sum(parse_bool(row.get("openplc_acquisition_success")) is True for row in rows)
        paired = sum(row.get("pairing_status") == "PAIRED" for row in rows)
        gaps, gap_values = calculate_sequence_gaps(rows)
        sampling = [value for value in (parse_float(row.get("sampling_skew_ms")) for row in rows) if value is not None]
        output.append({
            "scenario": scenario.summary.get("scenario", scenario.label),
            "phase": phase,
            "collection_cycle_count": total,
            "raspi_success_count": raspi_success,
            "raspi_failure_count": total - raspi_success,
            "raspi_availability_rate_pct": percent(raspi_success, total),
            "openplc_success_count": openplc_success,
            "openplc_failure_count": total - openplc_success,
            "openplc_availability_rate_pct": percent(openplc_success, total),
            "paired_record_count": paired,
            "paired_record_rate_pct": percent(paired, total),
            "sequence_gap_count": gaps,
            "sequence_gap_values": gap_values,
            "median_sampling_skew_ms": statistics.median(sampling) if sampling else None,
            "max_sampling_skew_ms": max(sampling) if sampling else None,
        })
    return output


def filter_attack_events(
    scenario: ScenarioInput,
    target_register: int,
    attack_value: int,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    matching: list[dict[str, str]] = []
    for row in scenario.modbus_writes:
        if (
            parse_int(row.get("function_code")) == 6
            and parse_int(row.get("register_address")) == target_register
            and parse_int(row.get("register_value")) == attack_value
            and row.get("parse_status") == "SUCCESS"
        ):
            matching.append(row)
    requests = [row for row in matching if row.get("direction") == "REQUEST"]
    responses = [row for row in matching if row.get("direction") == "RESPONSE"]
    requests.sort(key=lambda row: parse_datetime(row.get("timestamp_utc")) or datetime.max.replace(tzinfo=timezone.utc))
    responses.sort(key=lambda row: parse_datetime(row.get("timestamp_utc")) or datetime.max.replace(tzinfo=timezone.utc))
    return requests, responses


def calculate_attack_window(requests: list[dict[str, str]], responses: list[dict[str, str]]) -> AttackWindow:
    timestamps = [time for time in (parse_datetime(row.get("timestamp_utc")) for row in requests) if time is not None]
    intervals = [
        (timestamps[index] - timestamps[index - 1]).total_seconds()
        for index in range(1, len(timestamps))
    ]
    first = timestamps[0] if timestamps else None
    last = timestamps[-1] if timestamps else None
    duration = (last - first).total_seconds() if first and last else None
    return AttackWindow(
        request_count=len(requests),
        response_count=len(responses),
        first_request=first,
        last_request=last,
        duration_seconds=duration,
        mean_interval_seconds=statistics.mean(intervals) if intervals else None,
        median_interval_seconds=statistics.median(intervals) if intervals else None,
        min_interval_seconds=min(intervals) if intervals else None,
        max_interval_seconds=max(intervals) if intervals else None,
    )


def row_time(row: dict[str, str]) -> Optional[datetime]:
    return parse_datetime(row.get("cycle_completed_at"))


def is_false_observation(row: dict[str, str], attack_value: int) -> bool:
    plc_value = parse_int(row.get("bottle_count_from_pi"))
    return (
        plc_value == attack_value
        or parse_bool(row.get("cross_layer_match")) is False
    )


def is_normal_observation(row: dict[str, str], attack_value: int) -> bool:
    return (
        parse_bool(row.get("raspi_acquisition_success")) is True
        and parse_bool(row.get("openplc_acquisition_success")) is True
        and parse_bool(row.get("cross_layer_match")) is True
        and parse_int(row.get("bottle_count_from_pi")) != attack_value
    )


def calculate_recovery(
    treatment: ScenarioInput,
    attack: AttackWindow,
    attack_value: int,
    stable_records: int,
) -> RecoveryMetrics:
    ordered = sorted(
        [row for row in treatment.paired if row_time(row) is not None],
        key=lambda row: row_time(row) or datetime.max.replace(tzinfo=timezone.utc),
    )
    false_rows = [row for row in ordered if is_false_observation(row, attack_value)]
    false_times = [row_time(row) for row in false_rows if row_time(row) is not None]
    first_false = false_times[0] if false_times else None
    last_false = false_times[-1] if false_times else None

    first_normal: Optional[datetime] = None
    stable_start: Optional[datetime] = None
    stable_confirmed: Optional[datetime] = None

    if attack.last_request is not None:
        post_attack = [row for row in ordered if (row_time(row) or datetime.min.replace(tzinfo=timezone.utc)) > attack.last_request]
        for row in post_attack:
            if is_normal_observation(row, attack_value):
                first_normal = row_time(row)
                break

        for start_index in range(len(post_attack)):
            candidate = post_attack[start_index:start_index + stable_records]
            if len(candidate) < stable_records:
                break
            if all(is_normal_observation(row, attack_value) for row in candidate):
                stable_start = row_time(candidate[0])
                stable_confirmed = row_time(candidate[-1])
                break

    return RecoveryMetrics(
        first_false_observation=first_false,
        last_false_observation=last_false,
        first_normal_after_attack=first_normal,
        stable_recovery_start=stable_start,
        stable_recovery_confirmed_at=stable_confirmed,
        propagation_delay_seconds=(first_false - attack.first_request).total_seconds() if first_false and attack.first_request else None,
        false_value_persistence_seconds=(last_false - first_false).total_seconds() if first_false and last_false else None,
        first_normal_delay_seconds=(first_normal - attack.last_request).total_seconds() if first_normal and attack.last_request else None,
        stable_recovery_start_delay_seconds=(stable_start - attack.last_request).total_seconds() if stable_start and attack.last_request else None,
        stable_recovery_confirmation_seconds=(stable_confirmed - attack.last_request).total_seconds() if stable_confirmed and attack.last_request else None,
        false_observation_count=len(false_rows),
        stable_record_requirement=stable_records,
    )


def build_correlation_rows(
    treatment: ScenarioInput,
    attack_requests: list[dict[str, str]],
    attack_value: int,
    correlation_window_seconds: float,
) -> list[dict[str, Any]]:
    request_pairs = [
        (time, row)
        for row in attack_requests
        for time in [parse_datetime(row.get("timestamp_utc"))]
        if time is not None
    ]
    request_pairs.sort(key=lambda item: item[0])
    request_times = [item[0] for item in request_pairs]

    rows: list[dict[str, Any]] = []
    observations = sorted(
        [row for row in treatment.paired if is_false_observation(row, attack_value) and row_time(row) is not None],
        key=lambda row: row_time(row) or datetime.max.replace(tzinfo=timezone.utc),
    )
    for index, observation in enumerate(observations, start=1):
        observed_at = row_time(observation)
        assert observed_at is not None
        position = bisect.bisect_right(request_times, observed_at) - 1
        request_row: Optional[dict[str, str]] = None
        request_at: Optional[datetime] = None
        if position >= 0:
            request_at, request_row = request_pairs[position]
        delay = (observed_at - request_at).total_seconds() if request_at else None
        correlated = delay is not None and 0 <= delay <= correlation_window_seconds
        rows.append({
            "correlation_id": f"COR-P1-{index:03d}",
            "observation_timestamp_utc": format_datetime(observed_at),
            "collection_id": observation.get("collection_id", ""),
            "collection_sequence": observation.get("collection_sequence", ""),
            "experiment_phase": observation.get("experiment_phase", ""),
            "source_original_value": parse_int(observation.get("original_bottle_count")),
            "source_sent_value": parse_int(observation.get("sent_bottle_count")),
            "network_write_timestamp_utc": format_datetime(request_at),
            "network_packet_number": request_row.get("packet_number", "") if request_row else "",
            "network_transaction_id": request_row.get("transaction_id", "") if request_row else "",
            "network_function_code": parse_int(request_row.get("function_code")) if request_row else None,
            "network_register_address": parse_int(request_row.get("register_address")) if request_row else None,
            "network_register_value": parse_int(request_row.get("register_value")) if request_row else None,
            "control_observed_value": parse_int(observation.get("bottle_count_from_pi")),
            "control_total_bottle": parse_int(observation.get("total_bottle")),
            "network_to_control_delay_seconds": delay,
            "source_match": parse_bool(observation.get("source_match")),
            "cross_layer_match": parse_bool(observation.get("cross_layer_match")),
            "plc_internal_match": parse_bool(observation.get("plc_internal_match")),
            "correlation_window_seconds": correlation_window_seconds,
            "correlation_status": "CORRELATED" if correlated else "UNRESOLVED",
            "evidence_chain": "SOURCE_NORMAL -> FC06_WRITE -> OPENPLC_FALSE_VALUE" if correlated else "REVIEW_REQUIRED",
        })
    return rows


# =========================================================
# COMPARISON, TIMELINE, FINDINGS
# =========================================================


def all_phase_row(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return next(row for row in rows if row.get("phase") == "ALL")


def attack_phase_row(rows: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    return next((row for row in rows if row.get("phase") == "ATTACK"), None)


def build_comparison_rows(
    baseline_integrity: list[dict[str, Any]],
    treatment_integrity: list[dict[str, Any]],
    baseline_availability: list[dict[str, Any]],
    treatment_availability: list[dict[str, Any]],
    baseline_attack: AttackWindow,
    treatment_attack: AttackWindow,
    recovery: RecoveryMetrics,
) -> list[dict[str, Any]]:
    bi = all_phase_row(baseline_integrity)
    ti = all_phase_row(treatment_integrity)
    ta = attack_phase_row(treatment_integrity)
    ba = all_phase_row(baseline_availability)
    t_av = all_phase_row(treatment_availability)
    metrics = [
        ("Source integrity rate (overall)", bi.get("source_integrity_rate_pct"), ti.get("source_integrity_rate_pct"), "%", "original == sent"),
        ("Cross-layer integrity rate (overall)", bi.get("cross_layer_integrity_rate_pct"), ti.get("cross_layer_integrity_rate_pct"), "%", "sent == OpenPLC"),
        ("Cross-layer integrity rate (ATTACK)", None, ta.get("cross_layer_integrity_rate_pct") if ta else None, "%", "Operator ATTACK phase"),
        ("PLC internal consistency rate", bi.get("plc_internal_consistency_rate_pct"), ti.get("plc_internal_consistency_rate_pct"), "%", "OpenPLC input == total"),
        ("Raspberry acquisition availability", ba.get("raspi_availability_rate_pct"), t_av.get("raspi_availability_rate_pct"), "%", "Successful read cycles"),
        ("OpenPLC acquisition availability", ba.get("openplc_availability_rate_pct"), t_av.get("openplc_availability_rate_pct"), "%", "Successful read cycles"),
        ("Configured FDI FC06 request count", baseline_attack.request_count, treatment_attack.request_count, "request", "FC06 target register/value"),
        ("Configured false-value observations", 0, recovery.false_observation_count, "record", "OpenPLC value or cross-layer mismatch"),
        ("Technical attack duration", None, treatment_attack.duration_seconds, "seconds", "First-to-last configured FDI request"),
        ("Propagation delay", None, recovery.propagation_delay_seconds, "seconds", "First write to first false observation"),
        ("Stable recovery confirmation", None, recovery.stable_recovery_confirmation_seconds, "seconds", "Last write to Nth normal record"),
    ]
    return [
        {
            "metric": metric,
            "baseline_value": baseline_value,
            "treatment_value": treatment_value,
            "unit": unit,
            "definition": definition,
        }
        for metric, baseline_value, treatment_value, unit, definition in metrics
    ]


def build_incident_timeline(
    treatment: ScenarioInput,
    attack: AttackWindow,
    recovery: RecoveryMetrics,
    target_register: int,
    attack_value: int,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for phase in treatment.phase_events:
        events.append({
            "timestamp_utc": phase.get("event_timestamp", ""),
            "event_category": "OPERATOR_PHASE",
            "event_name": phase.get("experiment_phase", ""),
            "source": "phase_events.csv",
            "value": "",
            "details": phase.get("note", ""),
        })
    significant = [
        (attack.first_request, "NETWORK", "FIRST_CONFIGURED_FDI_WRITE", attack_value, f"FC06 HR{target_register}"),
        (recovery.first_false_observation, "CONTROL", "FIRST_FALSE_VALUE_OBSERVED", attack_value, "First collector observation"),
        (recovery.last_false_observation, "CONTROL", "LAST_FALSE_VALUE_OBSERVED", attack_value, "Last collector observation"),
        (attack.last_request, "NETWORK", "LAST_CONFIGURED_FDI_WRITE", attack_value, f"FC06 HR{target_register}"),
        (recovery.first_normal_after_attack, "CONTROL", "FIRST_NORMAL_AFTER_ATTACK", "normal", "Cross-layer match restored once"),
        (recovery.stable_recovery_start, "CONTROL", "STABLE_RECOVERY_START", "normal", "First record in stable normal streak"),
        (recovery.stable_recovery_confirmed_at, "CONTROL", "STABLE_RECOVERY_CONFIRMED", "normal", f"Confirmed after {recovery.stable_record_requirement} consecutive records"),
    ]
    for timestamp, category, name, value, details in significant:
        if timestamp is not None:
            events.append({
                "timestamp_utc": format_datetime(timestamp),
                "event_category": category,
                "event_name": name,
                "source": "modbus_write_events.csv" if category == "NETWORK" else "paired_cross_layer_evidence.csv",
                "value": value,
                "details": details,
            })
    events.sort(key=lambda row: parse_datetime(row.get("timestamp_utc")) or datetime.max.replace(tzinfo=timezone.utc))
    for index, row in enumerate(events, start=1):
        row["timeline_sequence"] = index
    return events


def build_findings(
    baseline_integrity: list[dict[str, Any]],
    treatment_integrity: list[dict[str, Any]],
    treatment_availability: list[dict[str, Any]],
    attack: AttackWindow,
    recovery: RecoveryMetrics,
    correlations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ti = all_phase_row(treatment_integrity)
    ta = attack_phase_row(treatment_integrity)
    tav = all_phase_row(treatment_availability)
    findings: list[dict[str, Any]] = []

    findings.append({
        "finding_id": "F-01",
        "title": "Source-layer integrity",
        "status": "SUPPORTED" if ti.get("source_mismatch_count") == 0 else "IMPACT_OBSERVED",
        "statement": (
            "Nilai original dan nilai yang dikirim Raspberry Pi tetap konsisten pada seluruh paired record."
            if ti.get("source_mismatch_count") == 0
            else "Ditemukan perbedaan antara nilai original dan nilai yang dikirim pada source layer."
        ),
        "evidence": ["integrity_analysis.csv", "paired_cross_layer_evidence.csv"],
    })

    attack_mismatch = ta.get("cross_layer_mismatch_count") if ta else 0
    findings.append({
        "finding_id": "F-02",
        "title": "Cross-layer integrity impact",
        "status": "IMPACT_OBSERVED" if attack_mismatch else "NOT_OBSERVED",
        "statement": (
            f"Pada fase ATTACK terdapat {attack_mismatch} record dengan sent_bottle_count berbeda dari bottle_count_from_pi."
        ),
        "evidence": ["integrity_analysis.csv", "cross_layer_correlation.csv"],
    })

    findings.append({
        "finding_id": "F-03",
        "title": "Network evidence of configured FDI",
        "status": "SUPPORTED" if attack.request_count > 0 else "NOT_OBSERVED",
        "statement": (
            f"PCAP memuat {attack.request_count} FC06 request yang menulis configured FDI value ke target register."
        ),
        "evidence": ["attack_window_analysis.csv", "modbus_write_events.csv"],
    })

    raspi_rate = tav.get("raspi_availability_rate_pct")
    plc_rate = tav.get("openplc_availability_rate_pct")
    availability_supported = raspi_rate == 100.0 and plc_rate == 100.0
    findings.append({
        "finding_id": "F-04",
        "title": "Acquisition availability",
        "status": "MAINTAINED" if availability_supported else "DEGRADED",
        "statement": (
            "Collector tetap memperoleh data Raspberry Pi dan OpenPLC pada seluruh siklus Perlakuan 1."
            if availability_supported
            else "Sebagian siklus akuisisi Raspberry Pi atau OpenPLC gagal."
        ),
        "evidence": ["availability_analysis.csv"],
    })

    findings.append({
        "finding_id": "F-05",
        "title": "Recovery",
        "status": "OBSERVED" if recovery.stable_recovery_confirmed_at else "NOT_CONFIRMED",
        "statement": (
            f"Stable recovery dikonfirmasi setelah {format_number(recovery.stable_recovery_confirmation_seconds)} detik dari FC06 configured FDI terakhir."
            if recovery.stable_recovery_confirmed_at
            else "Stable recovery belum dapat dikonfirmasi dari evidence yang tersedia."
        ),
        "evidence": ["recovery_analysis.csv", "final_incident_timeline.csv"],
    })

    correlated_count = sum(row.get("correlation_status") == "CORRELATED" for row in correlations)
    findings.append({
        "finding_id": "F-06",
        "title": "Cross-layer evidence correlation",
        "status": "SUPPORTED" if correlated_count else "REQUIRES_REVIEW",
        "statement": (
            f"Sebanyak {correlated_count} false-value observation dapat dikaitkan dengan FC06 write sebelumnya dalam correlation window."
        ),
        "evidence": ["cross_layer_correlation.csv"],
    })

    return findings


# =========================================================
# REPORT
# =========================================================


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    def cell(value: Any) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ")
    output = [
        "| " + " | ".join(cell(header) for header in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    output.extend("| " + " | ".join(cell(value) for value in row) + " |" for row in rows)
    return "\n".join(output)


def generate_markdown_report(
    baseline: ScenarioInput,
    treatment: ScenarioInput,
    baseline_integrity: list[dict[str, Any]],
    treatment_integrity: list[dict[str, Any]],
    baseline_availability: list[dict[str, Any]],
    treatment_availability: list[dict[str, Any]],
    attack: AttackWindow,
    recovery: RecoveryMetrics,
    comparison: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    limitations: list[str],
    framework_status: str,
    target_register: int,
    attack_value: int,
) -> str:
    ti_all = all_phase_row(treatment_integrity)
    ta = attack_phase_row(treatment_integrity)
    tav = all_phase_row(treatment_availability)
    lines = [
        "# Laporan Analysis dan Reporting DFIR Cross-Layer",
        "",
        f"**Status pipeline:** `{framework_status}`  ",
        f"**Baseline:** `{baseline.summary.get('collector_session_id', '')}`  ",
        f"**Perlakuan 1:** `{treatment.summary.get('collector_session_id', '')}`  ",
        f"**Dibuat:** `{utc_now()}`",
        "",
        "## Ruang lingkup",
        "",
        "Laporan ini membandingkan kondisi Baseline dan Perlakuan 1 False Data Injection pada testbed Raspberry Pi–Modbus TCP–OpenPLC. Input analisis berasal dari output Examination yang telah berstatus `READY_FOR_ANALYSIS` dan lolos verifikasi SHA-256.",
        "",
        "## Temuan utama",
        "",
        f"- Source integrity Perlakuan 1: **{format_percent(ti_all.get('source_integrity_rate_pct'))}**.",
        f"- Cross-layer integrity Perlakuan 1 secara keseluruhan: **{format_percent(ti_all.get('cross_layer_integrity_rate_pct'))}**.",
        f"- Cross-layer integrity pada fase ATTACK: **{format_percent(ta.get('cross_layer_integrity_rate_pct') if ta else None)}**.",
        f"- Raspberry acquisition availability: **{format_percent(tav.get('raspi_availability_rate_pct'))}**.",
        f"- OpenPLC acquisition availability: **{format_percent(tav.get('openplc_availability_rate_pct'))}**.",
        f"- Configured FDI traffic: **{attack.request_count} FC06 request** ke HR{target_register} dengan nilai {attack_value}.",
        f"- Technical attack duration: **{format_number(attack.duration_seconds)} detik**.",
        f"- Propagation delay: **{format_number(recovery.propagation_delay_seconds)} detik**.",
        f"- Stable recovery confirmation: **{format_number(recovery.stable_recovery_confirmation_seconds)} detik** setelah write terakhir.",
        "",
        "## Integrity per fase",
        "",
        markdown_table(
            ["Scenario", "Phase", "Records", "Source rate", "Cross-layer rate", "PLC consistency"],
            [
                [
                    row["scenario"], row["phase"], row["record_count"],
                    format_percent(row["source_integrity_rate_pct"]),
                    format_percent(row["cross_layer_integrity_rate_pct"]),
                    format_percent(row["plc_internal_consistency_rate_pct"]),
                ]
                for row in [*baseline_integrity, *treatment_integrity]
            ],
        ),
        "",
        "## Availability per fase",
        "",
        markdown_table(
            ["Scenario", "Phase", "Cycles", "Raspi availability", "OpenPLC availability", "Sequence gaps"],
            [
                [
                    row["scenario"], row["phase"], row["collection_cycle_count"],
                    format_percent(row["raspi_availability_rate_pct"]),
                    format_percent(row["openplc_availability_rate_pct"]),
                    row["sequence_gap_count"],
                ]
                for row in [*baseline_availability, *treatment_availability]
            ],
        ),
        "",
        "## Technical attack window dan recovery",
        "",
        markdown_table(
            ["Metric", "Value"],
            [
                ["First configured FDI request", format_datetime(attack.first_request)],
                ["Last configured FDI request", format_datetime(attack.last_request)],
                ["FC06 request count", attack.request_count],
                ["FC06 response count", attack.response_count],
                ["Mean write interval", f"{format_number(attack.mean_interval_seconds)} s"],
                ["First false observation", format_datetime(recovery.first_false_observation)],
                ["Last false observation", format_datetime(recovery.last_false_observation)],
                ["First normal after attack", format_datetime(recovery.first_normal_after_attack)],
                ["Stable recovery start", format_datetime(recovery.stable_recovery_start)],
                ["Stable recovery confirmed", format_datetime(recovery.stable_recovery_confirmed_at)],
                ["Stable confirmation delay", f"{format_number(recovery.stable_recovery_confirmation_seconds)} s"],
            ],
        ),
        "",
        "## Baseline versus Perlakuan 1",
        "",
        markdown_table(
            ["Metric", "Baseline", "Perlakuan 1", "Unit"],
            [
                [row["metric"], format_number(row["baseline_value"]), format_number(row["treatment_value"]), row["unit"]]
                for row in comparison
            ],
        ),
        "",
        "## Findings",
        "",
    ]
    for finding in findings:
        lines.extend([
            f"### {finding['finding_id']} — {finding['title']}",
            "",
            f"**Status:** `{finding['status']}`",
            "",
            finding["statement"],
            "",
            "Evidence: " + ", ".join(f"`{item}`" for item in finding["evidence"]),
            "",
        ])
    lines.extend([
        "## Significant incident timeline",
        "",
        markdown_table(
            ["UTC", "Category", "Event", "Value", "Source"],
            [
                [row["timestamp_utc"], row["event_category"], row["event_name"], row["value"], row["source"]]
                for row in timeline
            ],
        ),
        "",
        "## Keterbatasan",
        "",
    ])
    if limitations:
        lines.extend(f"- {item}" for item in limitations)
    else:
        lines.append("- Tidak ada keterbatasan tambahan yang berhasil diekstrak secara otomatis.")
    lines.extend([
        "",
        "## Kesimpulan metodologis",
        "",
        "Pipeline Collection–Preservation–Examination–Analysis–Reporting telah dijalankan secara end-to-end untuk Baseline dan Perlakuan 1 pada testbed yang diuji. Klaim ini terbatas pada implementasi dan demonstrasi di testbed serta skenario tersebut; hasil ini bukan validasi universal untuk seluruh lingkungan OT.",
        "",
        "## Traceability",
        "",
        "Seluruh angka pada laporan berasal dari file CSV/JSON Analysis. File output Analysis dilindungi oleh `analysis_manifest.csv` dan `analysis_manifest.sha256.txt`.",
        "",
    ])
    return "\n".join(lines)


def markdown_to_html(markdown_text: str, title: str) -> str:
    # Renderer minimal dan deterministik untuk report yang dihasilkan script sendiri.
    lines = markdown_text.splitlines()
    body: list[str] = []
    in_ul = False
    in_table = False
    table_rows: list[list[str]] = []

    def flush_ul() -> None:
        nonlocal in_ul
        if in_ul:
            body.append("</ul>")
            in_ul = False

    def flush_table() -> None:
        nonlocal in_table, table_rows
        if not in_table:
            return
        if table_rows:
            headers = table_rows[0]
            data_rows = table_rows[2:] if len(table_rows) > 1 else []
            body.append("<table><thead><tr>" + "".join(f"<th>{html.escape(cell)}</th>" for cell in headers) + "</tr></thead><tbody>")
            for row in data_rows:
                body.append("<tr>" + "".join(f"<td>{html.escape(cell)}</td>" for cell in row) + "</tr>")
            body.append("</tbody></table>")
        in_table = False
        table_rows = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            flush_ul()
            in_table = True
            table_rows.append([cell.strip() for cell in stripped.strip("|").split("|")])
            continue
        flush_table()
        if stripped.startswith("# "):
            flush_ul(); body.append(f"<h1>{html.escape(stripped[2:])}</h1>")
        elif stripped.startswith("## "):
            flush_ul(); body.append(f"<h2>{html.escape(stripped[3:])}</h2>")
        elif stripped.startswith("### "):
            flush_ul(); body.append(f"<h3>{html.escape(stripped[4:])}</h3>")
        elif stripped.startswith("- "):
            if not in_ul:
                body.append("<ul>"); in_ul = True
            body.append(f"<li>{html.escape(stripped[2:])}</li>")
        elif not stripped:
            flush_ul()
        else:
            flush_ul()
            escaped = html.escape(stripped)
            escaped = escaped.replace("`", "")
            body.append(f"<p>{escaped}</p>")
    flush_table(); flush_ul()

    return f"""<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
body{{font-family:Arial,sans-serif;line-height:1.55;max-width:1100px;margin:36px auto;padding:0 24px;color:#1f2937}}
h1,h2,h3{{color:#111827}} table{{border-collapse:collapse;width:100%;margin:16px 0 28px}} th,td{{border:1px solid #d1d5db;padding:8px;text-align:left;vertical-align:top}} th{{background:#f3f4f6}} code{{background:#f3f4f6;padding:2px 4px}} .note{{color:#4b5563}}
</style></head><body>{''.join(body)}</body></html>"""


# =========================================================
# OUTPUT MANIFEST
# =========================================================


def build_analysis_manifest(output_dir: Path) -> None:
    manifest = output_dir / "analysis_manifest.csv"
    hash_file = output_dir / "analysis_manifest.sha256.txt"
    rows = []
    for path in sorted(output_dir.rglob("*")):
        if not path.is_file() or path in {manifest, hash_file}:
            continue
        rows.append({
            "relative_path": path.relative_to(output_dir).as_posix(),
            "size_bytes": path.stat().st_size,
            "hash_algorithm": "SHA-256",
            "sha256": sha256_file(path),
            "hashed_at_utc": utc_now(),
        })
    write_csv(
        manifest,
        ["relative_path", "size_bytes", "hash_algorithm", "sha256", "hashed_at_utc"],
        rows,
    )
    hash_file.write_text(
        f"SHA-256  {sha256_file(manifest)}  analysis_manifest.csv\n",
        encoding="utf-8",
    )


# =========================================================
# CLI DAN MAIN
# =========================================================


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cross-scenario Analysis dan Reporting untuk Baseline vs Perlakuan 1.")
    parser.add_argument("--operator", required=True)
    parser.add_argument("--dfir-root", type=Path, default=None)
    parser.add_argument("--baseline-examination", type=Path, default=None)
    parser.add_argument("--treatment-examination", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--target-register", type=int, default=DEFAULT_TARGET_REGISTER)
    parser.add_argument("--attack-value", type=int, default=DEFAULT_ATTACK_VALUE)
    parser.add_argument("--stable-records", type=int, default=DEFAULT_STABLE_RECORDS)
    parser.add_argument("--correlation-window-seconds", type=float, default=DEFAULT_CORRELATION_WINDOW_SECONDS)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_id = create_run_id()
    started_at = utc_now()
    log_lines: list[str] = []

    def log(message: str) -> None:
        print(message)
        log_lines.append(f"{utc_now()} {message}")

    try:
        if args.stable_records < 1:
            raise ValueError("--stable-records minimal 1.")
        if args.correlation_window_seconds <= 0:
            raise ValueError("--correlation-window-seconds harus lebih dari 0.")

        dfir_root = (args.dfir_root or SCRIPT_PATH.parent.parent).resolve()
        baseline_dir = (
            args.baseline_examination.resolve()
            if args.baseline_examination
            else find_latest_examination(dfir_root, "BASELINE")
        )
        treatment_dir = (
            args.treatment_examination.resolve()
            if args.treatment_examination
            else find_latest_examination(dfir_root, "PERLAKUAN_1_FDI")
        )
        output_dir = (
            args.output.resolve()
            if args.output
            else (dfir_root / "analysis" / "results" / "BASELINE_vs_PERLAKUAN_1_FDI")
        )
        ensure_output_dir(output_dir, args.force)

        log("=" * 78)
        log(" DFIR CROSS-SCENARIO ANALYSIS + REPORTING")
        log("=" * 78)
        log(f"Run ID               : {run_id}")
        log(f"Operator             : {args.operator}")
        log(f"Baseline Examination : {baseline_dir}")
        log(f"P1 Examination       : {treatment_dir}")
        log(f"Output               : {output_dir}")

        baseline = load_scenario("BASELINE", baseline_dir)
        treatment = load_scenario("PERLAKUAN_1_FDI", treatment_dir)
        log("[OK] Kedua output Examination valid dan READY_FOR_ANALYSIS.")

        baseline_integrity = build_integrity_rows(baseline)
        treatment_integrity = build_integrity_rows(treatment)
        integrity_rows = [*baseline_integrity, *treatment_integrity]
        write_csv(
            output_dir / "integrity_analysis.csv",
            [
                "scenario", "phase", "record_count",
                "source_match_count", "source_mismatch_count", "source_integrity_rate_pct",
                "cross_layer_match_count", "cross_layer_mismatch_count", "cross_layer_integrity_rate_pct",
                "plc_internal_match_count", "plc_internal_mismatch_count", "plc_internal_consistency_rate_pct",
            ],
            integrity_rows,
        )

        baseline_availability = build_availability_rows(baseline)
        treatment_availability = build_availability_rows(treatment)
        availability_rows = [*baseline_availability, *treatment_availability]
        write_csv(
            output_dir / "availability_analysis.csv",
            [
                "scenario", "phase", "collection_cycle_count",
                "raspi_success_count", "raspi_failure_count", "raspi_availability_rate_pct",
                "openplc_success_count", "openplc_failure_count", "openplc_availability_rate_pct",
                "paired_record_count", "paired_record_rate_pct",
                "sequence_gap_count", "sequence_gap_values",
                "median_sampling_skew_ms", "max_sampling_skew_ms",
            ],
            availability_rows,
        )
        log("[OK] Integrity dan availability dihitung per scenario dan fase.")

        baseline_requests, baseline_responses = filter_attack_events(
            baseline, args.target_register, args.attack_value
        )
        treatment_requests, treatment_responses = filter_attack_events(
            treatment, args.target_register, args.attack_value
        )
        baseline_attack = calculate_attack_window(baseline_requests, baseline_responses)
        treatment_attack = calculate_attack_window(treatment_requests, treatment_responses)
        if treatment_attack.request_count == 0:
            raise RuntimeError(
                f"Tidak ditemukan FC06 request HR{args.target_register}={args.attack_value} pada Perlakuan 1."
            )

        attack_rows = [
            {
                "scenario": treatment.summary.get("scenario", "PERLAKUAN_1_FDI"),
                "target_register": args.target_register,
                "attack_value": args.attack_value,
                "request_count": treatment_attack.request_count,
                "response_count": treatment_attack.response_count,
                "first_request_timestamp_utc": format_datetime(treatment_attack.first_request),
                "last_request_timestamp_utc": format_datetime(treatment_attack.last_request),
                "technical_attack_duration_seconds": treatment_attack.duration_seconds,
                "mean_request_interval_seconds": treatment_attack.mean_interval_seconds,
                "median_request_interval_seconds": treatment_attack.median_interval_seconds,
                "min_request_interval_seconds": treatment_attack.min_interval_seconds,
                "max_request_interval_seconds": treatment_attack.max_interval_seconds,
                "definition": "Technical attack window uses first and last matching FC06 request in PCAP.",
            }
        ]
        write_csv(
            output_dir / "attack_window_analysis.csv",
            [
                "scenario", "target_register", "attack_value", "request_count", "response_count",
                "first_request_timestamp_utc", "last_request_timestamp_utc",
                "technical_attack_duration_seconds", "mean_request_interval_seconds",
                "median_request_interval_seconds", "min_request_interval_seconds",
                "max_request_interval_seconds", "definition",
            ],
            attack_rows,
        )

        recovery = calculate_recovery(
            treatment,
            treatment_attack,
            args.attack_value,
            args.stable_records,
        )
        recovery_rows = [{
            "scenario": treatment.summary.get("scenario", "PERLAKUAN_1_FDI"),
            "first_false_observation_utc": format_datetime(recovery.first_false_observation),
            "last_false_observation_utc": format_datetime(recovery.last_false_observation),
            "false_observation_count": recovery.false_observation_count,
            "propagation_delay_seconds": recovery.propagation_delay_seconds,
            "false_value_persistence_seconds": recovery.false_value_persistence_seconds,
            "first_normal_after_attack_utc": format_datetime(recovery.first_normal_after_attack),
            "first_normal_delay_seconds": recovery.first_normal_delay_seconds,
            "stable_record_requirement": recovery.stable_record_requirement,
            "stable_recovery_start_utc": format_datetime(recovery.stable_recovery_start),
            "stable_recovery_start_delay_seconds": recovery.stable_recovery_start_delay_seconds,
            "stable_recovery_confirmed_at_utc": format_datetime(recovery.stable_recovery_confirmed_at),
            "stable_recovery_confirmation_seconds": recovery.stable_recovery_confirmation_seconds,
            "definition": "Recovery is confirmed after N consecutive normal cross-layer records after the last matching FC06 request.",
        }]
        write_csv(
            output_dir / "recovery_analysis.csv",
            [
                "scenario", "first_false_observation_utc", "last_false_observation_utc",
                "false_observation_count", "propagation_delay_seconds", "false_value_persistence_seconds",
                "first_normal_after_attack_utc", "first_normal_delay_seconds",
                "stable_record_requirement", "stable_recovery_start_utc",
                "stable_recovery_start_delay_seconds", "stable_recovery_confirmed_at_utc",
                "stable_recovery_confirmation_seconds", "definition",
            ],
            recovery_rows,
        )
        log("[OK] Technical attack window, propagation, persistence, dan recovery dihitung.")

        correlations = build_correlation_rows(
            treatment,
            treatment_requests,
            args.attack_value,
            args.correlation_window_seconds,
        )
        write_csv(
            output_dir / "cross_layer_correlation.csv",
            [
                "correlation_id", "observation_timestamp_utc", "collection_id", "collection_sequence",
                "experiment_phase", "source_original_value", "source_sent_value",
                "network_write_timestamp_utc", "network_packet_number", "network_transaction_id",
                "network_function_code", "network_register_address", "network_register_value",
                "control_observed_value", "control_total_bottle", "network_to_control_delay_seconds",
                "source_match", "cross_layer_match", "plc_internal_match",
                "correlation_window_seconds", "correlation_status", "evidence_chain",
            ],
            correlations,
        )

        comparison = build_comparison_rows(
            baseline_integrity,
            treatment_integrity,
            baseline_availability,
            treatment_availability,
            baseline_attack,
            treatment_attack,
            recovery,
        )
        write_csv(
            output_dir / "baseline_comparison.csv",
            ["metric", "baseline_value", "treatment_value", "unit", "definition"],
            comparison,
        )

        incident_timeline = build_incident_timeline(
            treatment,
            treatment_attack,
            recovery,
            args.target_register,
            args.attack_value,
        )
        write_csv(
            output_dir / "final_incident_timeline.csv",
            ["timeline_sequence", "timestamp_utc", "event_category", "event_name", "source", "value", "details"],
            incident_timeline,
        )
        log("[OK] Cross-layer correlation, comparison, dan final timeline dibuat.")

        findings = build_findings(
            baseline_integrity,
            treatment_integrity,
            treatment_availability,
            treatment_attack,
            recovery,
            correlations,
        )
        write_json(output_dir / "findings.json", findings)

        limitations = []
        for note in [*baseline.preservation_notes, *treatment.preservation_notes]:
            if note not in limitations:
                limitations.append(note)
        if baseline.pcap_summary:
            baseline_last_pcap = parse_datetime(baseline.pcap_summary[0].get("last_packet_timestamp_utc"))
            baseline_last_record = max(
                (time for time in (row_time(row) for row in baseline.paired) if time is not None),
                default=None,
            )
            if baseline_last_pcap and baseline_last_record and baseline_last_pcap < baseline_last_record:
                limitations.append("Baseline PCAP berakhir sebelum collection session selesai sehingga coverage network tidak mencakup seluruh record collector.")
        limitations.append("Kesimpulan berlaku untuk testbed dan skenario yang dievaluasi, bukan validasi universal seluruh lingkungan OT.")

        framework_status = "END_TO_END_ADAPTATION_DEMONSTRATED_FOR_CURRENT_TESTBED"
        summary_payload = {
            "analysis_run_id": run_id,
            "operator": args.operator,
            "started_at_utc": started_at,
            "completed_at_utc": utc_now(),
            "framework_adaptation_status": framework_status,
            "scope": "BASELINE and PERLAKUAN_1_FDI on current Raspberry Pi–Modbus TCP–OpenPLC testbed",
            "inputs": {
                "baseline_examination": str(baseline_dir),
                "treatment_examination": str(treatment_dir),
                "baseline_session_id": baseline.summary.get("collector_session_id"),
                "treatment_session_id": treatment.summary.get("collector_session_id"),
                "baseline_examination_status": baseline.summary.get("examination_status"),
                "treatment_examination_status": treatment.summary.get("examination_status"),
            },
            "configured_fdi": {
                "function_code": 6,
                "target_register": args.target_register,
                "attack_value": args.attack_value,
                "request_count": treatment_attack.request_count,
                "response_count": treatment_attack.response_count,
                "first_request_utc": format_datetime(treatment_attack.first_request),
                "last_request_utc": format_datetime(treatment_attack.last_request),
                "duration_seconds": treatment_attack.duration_seconds,
            },
            "recovery": recovery.__dict__ | {
                "first_false_observation": format_datetime(recovery.first_false_observation),
                "last_false_observation": format_datetime(recovery.last_false_observation),
                "first_normal_after_attack": format_datetime(recovery.first_normal_after_attack),
                "stable_recovery_start": format_datetime(recovery.stable_recovery_start),
                "stable_recovery_confirmed_at": format_datetime(recovery.stable_recovery_confirmed_at),
            },
            "correlation": {
                "total_false_observations": len(correlations),
                "correlated_observations": sum(row.get("correlation_status") == "CORRELATED" for row in correlations),
                "correlation_window_seconds": args.correlation_window_seconds,
            },
            "findings": findings,
            "limitations": limitations,
            "claim_boundary": "Successful end-to-end adaptation and demonstration for the evaluated testbed; not universal OT validation.",
        }
        write_json(output_dir / "analysis_summary.json", summary_payload)

        report_md = generate_markdown_report(
            baseline,
            treatment,
            baseline_integrity,
            treatment_integrity,
            baseline_availability,
            treatment_availability,
            treatment_attack,
            recovery,
            comparison,
            findings,
            incident_timeline,
            limitations,
            framework_status,
            args.target_register,
            args.attack_value,
        )
        (output_dir / "analysis_report.md").write_text(report_md, encoding="utf-8")
        (output_dir / "analysis_report.html").write_text(
            markdown_to_html(report_md, "Laporan Analysis DFIR Cross-Layer"),
            encoding="utf-8",
        )

        write_json(
            output_dir / "analysis_run.json",
            {
                "run_id": run_id,
                "script_path": str(SCRIPT_PATH),
                "script_sha256": sha256_file(SCRIPT_PATH),
                "python_version": sys.version,
                "host": socket.gethostname(),
                "operator": args.operator,
                "arguments": vars(args),
                "started_at_utc": started_at,
                "completed_at_utc": utc_now(),
                "status": "ANALYSIS_AND_INITIAL_REPORTING_COMPLETE",
            },
        )

        log(f"[STATUS] {framework_status}")
        log("[OK] Report Markdown dan HTML berhasil dibuat.")
        (output_dir / "analysis_log.txt").write_text("\n".join(log_lines) + "\n", encoding="utf-8")
        build_analysis_manifest(output_dir)

        print("=" * 78)
        print("[SUCCESS] Analysis dan initial Reporting selesai.")
        print(f"Output : {output_dir}")
        print(f"Status : {framework_status}")
        print("=" * 78)
        return 0

    except Exception as error:
        try:
            fallback_root = args.output.resolve() if args.output else SCRIPT_PATH.parent / "analysis_failed"
            fallback_root.mkdir(parents=True, exist_ok=True)
            (fallback_root / "analysis_failure.log").write_text(
                "\n".join(log_lines)
                + f"\n{utc_now()} [FATAL] {type(error).__name__}: {error}\n\n"
                + traceback.format_exc(),
                encoding="utf-8",
            )
        except Exception:
            pass
        print(f"[FATAL] {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
