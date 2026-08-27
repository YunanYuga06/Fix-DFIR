#!/usr/bin/env python3
"""
collector.py

Cross-layer raw evidence collector untuk testbed PAMSIMAS:
ThingsBoard mock/telemetry -> Raspberry Pi -> HTTP state proxy -> Collector
Raspberry Pi              -> Modbus/TCP -> OpenPLC controller
OpenPLC                   -> Modbus TCP read-only -> Collector

Raspberry Pi TIDAK dibaca dari file lokal pada Collector Laptop.
State selalu diambil melalui endpoint:

    http://192.168.100.122:5020/state

Acuan metodologis:
- NIST SP 800-86:
  collection terkontrol, provenance, timestamp, dan preservation evidence.
- NISTIR 8428:
  routine collection OT, synchronized timeline, process monitoring,
  dan baseline comparison.

Catatan:
- Script ini merupakan adaptasi teknis untuk testbed laboratorium.
- Collector hanya membaca dan menyimpan raw evidence.
- Collector tidak mengubah register OpenPLC.
- Collector tidak mendeteksi serangan.
- Analisis Integrity/Availability dilakukan oleh script analysis terpisah.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request


# =========================================================
# IMPORT PYMODBUS
# =========================================================

ModbusTcpClient: Any = None
PYMODBUS_IMPORT_ERROR: Optional[Exception] = None

try:
    # PyModbus versi baru
    from pymodbus.client import ModbusTcpClient  # type: ignore[assignment]
except ImportError:
    try:
        # PyModbus versi lama
        from pymodbus.client.sync import ModbusTcpClient  # type: ignore[assignment]
    except ImportError as exc:
        PYMODBUS_IMPORT_ERROR = exc


# =========================================================
# KONFIGURASI DEFAULT
# =========================================================

DEFAULT_RASPI_IP = "192.168.100.135"
DEFAULT_RASPI_PORT = 5020
DEFAULT_RASPI_PATH = "/state"

DEFAULT_OPENPLC_IP = "192.168.100.132"
DEFAULT_OPENPLC_PORT = 502
DEFAULT_UNIT_ID = 1

DEFAULT_HTTP_TIMEOUT = 3.0
DEFAULT_MODBUS_TIMEOUT = 3.0
DEFAULT_POLL_INTERVAL = 1.0

DEFAULT_SCENARIO = "BASELINE"
DEFAULT_PHASE = "BASELINE"
DEFAULT_NTP_REFERENCE = "Collector Laptop Local NTP Server"

# OpenPLC register mapping sesuai PAMSIMAS_BASELINE_THINGSBOARD_MOCK.st:
# %MW0 -> HR1024 : OdoMeter_FromPi
# %MW1 -> HR1025 : FlowRate_x1000_FromPi
# %MW2 -> HR1026 : Volume_x10000_FromPi
# %MW3 -> HR1027 : PaymentStatus_FromPi
# %MW4 -> HR1028 : Sequence_FromPi
# %MW5 -> HR1029 : ObservedValveRaw_FromPi
# %MW6 -> HR1030 : NodeId_FromPi
# %MW7 -> HR1031 : OdoMeter_Processed
# %MW8 -> HR1032 : ProcessState
# %MW9 -> HR1033 : ValveReason
HOLDING_REGISTER_START = 1024
HOLDING_REGISTER_COUNT = 10

# %QX0.0 -> Coil 0 : ValveCommand
# %QX0.1 -> Coil 1 : AbnormalUsage
# %QX0.2 -> Coil 2 : PaymentBlocked
COIL_START = 0
COIL_COUNT = 3

FLOW_RATE_SCALE = 1000
VOLUME_SCALE = 10000

SCHEMA_VERSION = "4.0-pamsimas-thingsboard-http-proxy"

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
DEFAULT_OUTPUT_ROOT = SCRIPT_DIRECTORY / "evidence"


# =========================================================
# KOLOM CSV
# =========================================================

COMMON_FIELDS = [
    "experiment_id",
    "scenario",
    "experiment_phase",
    "phase_source",
    "collector_session_id",
    "collection_id",
    "collection_sequence",
    "collector_host",
    "collector_started_at",
    "cycle_started_at",
    "cycle_completed_at",
    "acquisition_window_ms",
    "sampling_skew_ms",
]

RASPI_FIELDS = [
    *COMMON_FIELDS,
    "raspi_read_started_at",
    "raspi_read_finished_at",
    "raspi_read_duration_ms",
    "source_layer",
    "source_device",
    "source_endpoint",
    "acquisition_method",
    "read_status",
    "http_status_code",
    "error_type",
    "error_message",
    "raw_state_sha256",
    "raw_state_size_bytes",
    "source_updated_at",
    "source_updated_at_epoch_ms",
    "source_age_ms",
    "state_schema_version",
    "sender_session_id",
    "sender_started_at",
    "sender_pid",
    "state_sequence",
    "event_type",
    "sender_state",
    "source_mode",
    "thingsboard_raw",
    "thingsboard_timestamp_ms",
    "raspi_received_at",
    "node_id",
    "node_timestamp",
    "ntp_timestamp",
    "original_odo_meter_litre",
    "sent_odo_meter_litre",
    "original_flow_rate_lpm",
    "sent_flow_rate_x1000",
    "original_volume_litre",
    "sent_volume_x10000",
    "observed_valve_raw",
    "observed_valve_open",
    "original_payment_status",
    "sent_payment_status",
    "source_sequence",
    "abnormal_odo_threshold_litre",
    "expected_abnormal_usage",
    "expected_payment_block",
    "expected_valve_command_open",
    "send_status",
    "sender_error_message",
    "protocol",
    "target_device",
    "target_ip",
    "target_port",
    "target_unit_id",
    "tb_valve_open_value",
    "state_file",
    "register_mapping",
]

OPENPLC_FIELDS = [
    *COMMON_FIELDS,
    "openplc_read_started_at",
    "openplc_read_finished_at",
    "openplc_read_duration_ms",
    "source_layer",
    "source_device",
    "source_endpoint",
    "acquisition_method",
    "read_status",
    "register_read_status",
    "coil_read_status",
    "error_type",
    "error_message",
    "openplc_ip",
    "openplc_port",
    "unit_id",
    "holding_register_start",
    "holding_register_count",
    "coil_start",
    "coil_count",
    "odo_meter_from_pi",
    "flow_rate_x1000_from_pi",
    "flow_rate_lpm_decoded",
    "volume_x10000_from_pi",
    "volume_litre_decoded",
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
    "raw_registers_unsigned",
    "raw_registers_signed",
    "raw_coils",
]

EVENT_FIELDS = [
    "event_timestamp",
    "experiment_id",
    "collector_session_id",
    "event_type",
    "experiment_phase",
    "source",
    "note",
]

HASH_FIELDS = [
    "relative_path",
    "size_bytes",
    "modified_at_utc",
    "hash_algorithm",
    "sha256",
    "hashed_at_utc",
]


# =========================================================
# UTILITAS WAKTU, ID, HASH, DAN FILE
# =========================================================

def utc_now() -> str:
    """Timestamp ISO 8601 UTC dengan resolusi milidetik."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def parse_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def timestamp_to_epoch_ms(value: Any) -> Optional[int]:
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    return int(parsed.timestamp() * 1000)


def elapsed_ms(start_monotonic: float) -> float:
    """Menghitung durasi memakai monotonic clock."""
    return round(
        (time.monotonic() - start_monotonic) * 1000,
        3,
    )


def calculate_source_age_ms(
    source_timestamp: Any,
    collector_timestamp: str,
) -> Optional[float]:
    """
    Menghitung umur state Raspberry Pi ketika selesai dibaca collector.

    Nilai negatif tidak dipaksa menjadi nol karena dapat menunjukkan
    clock offset atau sinkronisasi NTP yang belum benar.
    """
    source_time = parse_timestamp(source_timestamp)
    collector_time = parse_timestamp(collector_timestamp)

    if source_time is None or collector_time is None:
        return None

    return round(
        (collector_time - source_time).total_seconds() * 1000,
        3,
    )


def create_id(prefix: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    return f"{prefix}-{timestamp}-{uuid.uuid4().hex[:8]}"


def sanitize_name(value: str) -> str:
    cleaned = "".join(
        character
        if character.isalnum() or character in "-_"
        else "_"
        for character in value.strip()
    )
    return cleaned or "UNSPECIFIED"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file_handle:
        while True:
            chunk = file_handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def file_modified_at_utc(path: Path) -> str:
    return (
        datetime.fromtimestamp(
            path.stat().st_mtime,
            tz=timezone.utc,
        )
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def normalize_csv_value(value: Any) -> Any:
    if value is None:
        return ""

    if isinstance(value, bool):
        return str(value).upper()

    if isinstance(value, (list, tuple, dict)):
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        )

    return value


def append_csv_row(
    path: Path,
    fieldnames: list[str],
    row: dict[str, Any],
) -> None:
    """
    Append satu record, flush, dan fsync.

    Tujuannya agar record tidak hanya tertahan pada buffer aplikasi.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    file_exists = path.exists() and path.stat().st_size > 0

    normalized_row = {
        field: normalize_csv_value(row.get(field))
        for field in fieldnames
    }

    with path.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(normalized_row)
        csv_file.flush()
        os.fsync(csv_file.fileno())


def write_json_atomic(
    path: Path,
    data: dict[str, Any],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(
        f".{path.name}.tmp"
    )

    payload = json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        default=str,
    ) + "\n"

    with temporary_path.open(
        "w",
        encoding="utf-8",
    ) as file_handle:
        file_handle.write(payload)
        file_handle.flush()
        os.fsync(file_handle.fileno())

    os.replace(temporary_path, path)


# =========================================================
# SNAPSHOT STATUS SINKRONISASI WAKTU
# =========================================================

def run_command(
    command: list[str],
) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        output = (
            (result.stdout or "")
            + (result.stderr or "")
        )
        return result.returncode, output.strip()

    except (OSError, subprocess.SubprocessError) as error:
        return 127, f"{type(error).__name__}: {error}"


def save_time_sync_snapshot(
    output_file: Path,
    ntp_reference: str,
) -> None:
    """
    Menyimpan status sinkronisasi waktu Collector Laptop.

    Script tidak mengubah konfigurasi NTP.
    """
    lines = [
        "TIME SYNCHRONIZATION SNAPSHOT",
        f"captured_at_utc={utc_now()}",
        f"collector_host={socket.gethostname()}",
        f"platform={platform.platform()}",
        f"ntp_reference={ntp_reference}",
        "",
    ]

    if os.name == "nt":
        commands = [
            ["w32tm", "/query", "/status", "/verbose"],
            ["w32tm", "/query", "/source"],
        ]
    else:
        commands = [
            ["chronyc", "tracking"],
            ["chronyc", "sources", "-v"],
            ["timedatectl", "show-timesync", "--all"],
            ["timedatectl", "status"],
        ]

    executed = False

    for command in commands:
        if shutil.which(command[0]) is None:
            continue

        executed = True
        return_code, output = run_command(command)

        lines.extend([
            f"$ {' '.join(command)}",
            f"return_code={return_code}",
            output or "(no output)",
            "",
        ])

    if not executed:
        lines.extend([
            "No supported time synchronization command found.",
            "Document NTP status manually if required.",
            "",
        ])

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    output_file.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


# =========================================================
# FASE EKSPERIMEN
# =========================================================

def read_experiment_phase(
    default_phase: str,
    phase_file: Optional[Path],
) -> tuple[str, str, Optional[str]]:
    """
    Mendukung:
    1. File JSON:
       {
         "phase": "ATTACK",
         "updated_at": "...",
         "note": "..."
       }

    2. File teks satu baris:
       ATTACK
    """
    if phase_file is None:
        return default_phase, "command_line", None

    try:
        raw_text = phase_file.read_text(
            encoding="utf-8"
        ).strip()

        if not raw_text:
            raise ValueError("Phase file kosong")

        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError:
            payload = None

        if isinstance(payload, dict):
            phase = str(
                payload.get(
                    "phase",
                    default_phase,
                )
            ).strip()

            note = payload.get("note")

            return (
                phase or default_phase,
                str(phase_file),
                str(note) if note else None,
            )

        return (
            raw_text.splitlines()[0].strip(),
            str(phase_file),
            None,
        )

    except (OSError, ValueError) as error:
        return (
            default_phase,
            f"{phase_file} (fallback)",
            (
                f"PHASE_FILE_ERROR: "
                f"{type(error).__name__}: {error}"
            ),
        )


# =========================================================
# RASPBERRY PI — HTTP PROXY ONLY
# =========================================================

def build_raspi_state_url(
    raspi_ip: str,
    raspi_port: int,
    raspi_path: str,
) -> str:
    return (
        f"http://{raspi_ip}:{raspi_port}"
        f"{raspi_path}"
    )


def read_raspberry_pi_state(
    state_url: str,
    timeout: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Mengambil state Raspberry Pi melalui HTTP GET.

    Contoh endpoint:
        http://192.168.100.122:5020/state

    Tidak ada pembacaan file lokal dan tidak ada fallback lokal.
    """
    read_started_at = utc_now()
    started_monotonic = time.monotonic()

    http_request = urllib_request.Request(
        state_url,
        method="GET",
        headers={
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "User-Agent": (
                f"dfir-collector/{SCHEMA_VERSION}"
            ),
        },
    )

    try:
        with urllib_request.urlopen(
            http_request,
            timeout=timeout,
        ) as response:
            raw_bytes = response.read()
            http_status_code = getattr(
                response,
                "status",
                None,
            )

        read_finished_at = utc_now()

        state = json.loads(
            raw_bytes.decode("utf-8")
        )

        if not isinstance(state, dict):
            raise ValueError(
                "Root JSON Raspberry Pi harus "
                "berupa object"
            )

        metadata = {
            "raspi_read_started_at": read_started_at,
            "raspi_read_finished_at": read_finished_at,
            "raspi_read_duration_ms": elapsed_ms(
                started_monotonic
            ),
            "read_status": "SUCCESS",
            "http_status_code": http_status_code,
            "error_type": None,
            "error_message": None,
            "raw_state_sha256": sha256_bytes(
                raw_bytes
            ),
            "raw_state_size_bytes": len(raw_bytes),
            "source_age_ms": calculate_source_age_ms(
                state.get("updated_at"),
                read_finished_at,
            ),
        }

        return state, metadata

    except urllib_error.HTTPError as error:
        error_type = "HTTP_ERROR"
        error_message = (
            f"HTTP {error.code}: {error.reason}"
        )
        http_status_code = error.code

    except urllib_error.URLError as error:
        reason = getattr(
            error,
            "reason",
            error,
        )

        if isinstance(reason, TimeoutError):
            error_type = "HTTP_TIMEOUT"
        else:
            error_type = "HTTP_CONNECTION_ERROR"

        error_message = str(reason)
        http_status_code = None

    except TimeoutError as error:
        error_type = "HTTP_TIMEOUT"
        error_message = str(error)
        http_status_code = None

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        error_type = "INVALID_JSON"
        error_message = (
            f"{type(error).__name__}: {error}"
        )
        http_status_code = None

    except OSError as error:
        error_type = "HTTP_IO_ERROR"
        error_message = (
            f"{type(error).__name__}: {error}"
        )
        http_status_code = None

    read_finished_at = utc_now()

    return {}, {
        "raspi_read_started_at": read_started_at,
        "raspi_read_finished_at": read_finished_at,
        "raspi_read_duration_ms": elapsed_ms(
            started_monotonic
        ),
        "read_status": "FAILED",
        "http_status_code": http_status_code,
        "error_type": error_type,
        "error_message": error_message,
        "raw_state_sha256": None,
        "raw_state_size_bytes": None,
        "source_age_ms": None,
    }


def build_raspi_record(
    state: dict[str, Any],
    metadata: dict[str, Any],
    common: dict[str, Any],
    state_url: str,
) -> dict[str, Any]:
    source_updated_at = state.get("updated_at")

    return {
        **common,
        "raspi_read_started_at": metadata.get("raspi_read_started_at"),
        "raspi_read_finished_at": metadata.get("raspi_read_finished_at"),
        "raspi_read_duration_ms": metadata.get("raspi_read_duration_ms"),
        "source_layer": state.get("source_layer", "raspberry_pi_bridge"),
        "source_device": state.get("source_device", "raspberry_pi"),
        "source_endpoint": state_url,
        "acquisition_method": "http_get_json_read_only",
        "read_status": metadata.get("read_status"),
        "http_status_code": metadata.get("http_status_code"),
        "error_type": metadata.get("error_type"),
        "error_message": metadata.get("error_message"),
        "raw_state_sha256": metadata.get("raw_state_sha256"),
        "raw_state_size_bytes": metadata.get("raw_state_size_bytes"),
        "source_updated_at": source_updated_at,
        "source_updated_at_epoch_ms": timestamp_to_epoch_ms(source_updated_at),
        "source_age_ms": metadata.get("source_age_ms"),
        "state_schema_version": state.get("state_schema_version"),
        "sender_session_id": state.get("sender_session_id"),
        "sender_started_at": state.get("sender_started_at"),
        "sender_pid": state.get("sender_pid"),
        "state_sequence": state.get("state_sequence"),
        "event_type": state.get("event_type"),
        "sender_state": state.get("sender_state"),
        "source_mode": state.get("source_mode"),
        "thingsboard_raw": state.get("thingsboard_raw"),
        "thingsboard_timestamp_ms": state.get("thingsboard_timestamp_ms"),
        "raspi_received_at": state.get("raspi_received_at"),
        "node_id": state.get("node_id"),
        "node_timestamp": state.get("node_timestamp"),
        "ntp_timestamp": state.get("ntp_timestamp"),
        "original_odo_meter_litre": state.get("original_odo_meter_litre"),
        "sent_odo_meter_litre": state.get("sent_odo_meter_litre"),
        "original_flow_rate_lpm": state.get("original_flow_rate_lpm"),
        "sent_flow_rate_x1000": state.get("sent_flow_rate_x1000"),
        "original_volume_litre": state.get("original_volume_litre"),
        "sent_volume_x10000": state.get("sent_volume_x10000"),
        "observed_valve_raw": state.get("observed_valve_raw"),
        "observed_valve_open": state.get("observed_valve_open"),
        "original_payment_status": state.get("original_payment_status"),
        "sent_payment_status": state.get("sent_payment_status"),
        "source_sequence": state.get("source_sequence"),
        "abnormal_odo_threshold_litre": state.get(
            "abnormal_odo_threshold_litre"
        ),
        "expected_abnormal_usage": state.get("expected_abnormal_usage"),
        "expected_payment_block": state.get("expected_payment_block"),
        "expected_valve_command_open": state.get(
            "expected_valve_command_open"
        ),
        "send_status": state.get("send_status"),
        "sender_error_message": state.get("sender_error_message"),
        "protocol": state.get("protocol"),
        "target_device": state.get("target_device"),
        "target_ip": state.get("target_ip"),
        "target_port": state.get("target_port"),
        "target_unit_id": state.get("target_unit_id"),
        "tb_valve_open_value": state.get("tb_valve_open_value"),
        "state_file": state.get("state_file"),
        "register_mapping": state.get("register_mapping"),
    }


# =========================================================
# PYMODBUS COMPATIBILITY
# =========================================================

def ensure_pymodbus_available() -> None:
    if ModbusTcpClient is None:
        raise RuntimeError(
            "PyModbus belum terpasang pada interpreter "
            "Python ini. Jalankan:\n"
            "python -m pip install pymodbus\n"
            f"Import error: {PYMODBUS_IMPORT_ERROR}"
        )


def create_modbus_client(
    host: str,
    port: int,
    timeout: float,
) -> Any:
    ensure_pymodbus_available()

    try:
        return ModbusTcpClient(
            host=host,
            port=port,
            timeout=timeout,
        )
    except TypeError:
        return ModbusTcpClient(
            host=host,
            port=port,
        )


def call_modbus_read(
    method: Any,
    *,
    address: int,
    count: int,
    unit_id: int,
) -> Any:
    """
    Menangani variasi API PyModbus.

    Versi baru:
        method(
            address=...,
            count=...,
            device_id=...
        )

    Versi lain:
        slave=...
        unit=...
    """
    attempts = [
        {
            "address": address,
            "count": count,
            "device_id": unit_id,
        },
        {
            "address": address,
            "count": count,
            "slave": unit_id,
        },
        {
            "address": address,
            "count": count,
            "unit": unit_id,
        },
        {
            "address": address,
            "count": count,
        },
    ]

    last_type_error: Optional[TypeError] = None

    for kwargs in attempts:
        try:
            return method(**kwargs)
        except TypeError as error:
            last_type_error = error

    # Fallback versi lama yang memakai positional address/count.
    positional_attempts = [
        ((address, count), {"slave": unit_id}),
        ((address, count), {"unit": unit_id}),
        ((address, count), {}),
    ]

    for args, kwargs in positional_attempts:
        try:
            return method(*args, **kwargs)
        except TypeError as error:
            last_type_error = error

    if last_type_error is not None:
        raise last_type_error

    raise RuntimeError(
        "Tidak dapat memanggil method read PyModbus"
    )


def response_is_error(
    response: Any,
) -> bool:
    if response is None:
        return True

    checker = getattr(
        response,
        "isError",
        None,
    )

    if callable(checker):
        try:
            return bool(checker())
        except Exception:
            return True

    return False


def unsigned_to_signed_16(
    value: int,
) -> int:
    return (
        value - 65536
        if value >= 32768
        else value
    )


# =========================================================
# OPENPLC — MODBUS READ-ONLY
# =========================================================

def read_openplc(
    client: Any,
    *,
    openplc_ip: str,
    openplc_port: int,
    unit_id: int,
) -> dict[str, Any]:
    read_started_at = utc_now()
    started_monotonic = time.monotonic()

    register_read_status = "FAILED"
    coil_read_status = "FAILED"

    error_types: list[str] = []
    error_messages: list[str] = []

    registers_unsigned: list[int] = []
    registers_signed: list[int] = []
    coils: list[bool] = []

    try:
        connected = client.connect()

        if connected is False:
            raise ConnectionError(
                "Gagal terhubung ke OpenPLC "
                f"{openplc_ip}:{openplc_port}"
            )

        register_response = call_modbus_read(
            client.read_holding_registers,
            address=HOLDING_REGISTER_START,
            count=HOLDING_REGISTER_COUNT,
            unit_id=unit_id,
        )

        if response_is_error(register_response):
            error_types.append("MODBUS_REGISTER_READ_ERROR")
            error_messages.append(repr(register_response))
        else:
            register_values = getattr(register_response, "registers", None)

            if (
                register_values is None
                or len(register_values) < HOLDING_REGISTER_COUNT
            ):
                error_types.append("MODBUS_REGISTER_INCOMPLETE")
                error_messages.append(
                    "Jumlah register lebih sedikit dari permintaan"
                )
            else:
                registers_unsigned = [
                    int(value)
                    for value in register_values[:HOLDING_REGISTER_COUNT]
                ]
                registers_signed = [
                    unsigned_to_signed_16(value)
                    for value in registers_unsigned
                ]
                register_read_status = "SUCCESS"

        coil_response = call_modbus_read(
            client.read_coils,
            address=COIL_START,
            count=COIL_COUNT,
            unit_id=unit_id,
        )

        if response_is_error(coil_response):
            error_types.append("MODBUS_COIL_READ_ERROR")
            error_messages.append(repr(coil_response))
        else:
            coil_values = getattr(coil_response, "bits", None)

            if coil_values is None or len(coil_values) < COIL_COUNT:
                error_types.append("MODBUS_COIL_INCOMPLETE")
                error_messages.append(
                    "Jumlah coil lebih sedikit dari permintaan"
                )
            else:
                coils = [bool(value) for value in coil_values[:COIL_COUNT]]
                coil_read_status = "SUCCESS"

    except TimeoutError as error:
        error_types.append("MODBUS_TIMEOUT")
        error_messages.append(str(error))
        try:
            client.close()
        except Exception:
            pass

    except (ConnectionError, OSError) as error:
        error_types.append("MODBUS_CONNECTION_ERROR")
        error_messages.append(str(error))
        try:
            client.close()
        except Exception:
            pass

    except Exception as error:
        error_types.append("MODBUS_UNEXPECTED_ERROR")
        error_messages.append(f"{type(error).__name__}: {error}")
        try:
            client.close()
        except Exception:
            pass

    if register_read_status == "SUCCESS" and coil_read_status == "SUCCESS":
        read_status = "SUCCESS"
    elif register_read_status == "SUCCESS" or coil_read_status == "SUCCESS":
        read_status = "PARTIAL"
    else:
        read_status = "FAILED"

    def register(index: int) -> Optional[int]:
        return registers_signed[index] if len(registers_signed) > index else None

    def coil(index: int) -> Optional[bool]:
        return coils[index] if len(coils) > index else None

    flow_rate_raw = register(1)
    volume_raw = register(2)

    read_finished_at = utc_now()

    return {
        "openplc_read_started_at": read_started_at,
        "openplc_read_finished_at": read_finished_at,
        "openplc_read_duration_ms": elapsed_ms(started_monotonic),
        "read_status": read_status,
        "register_read_status": register_read_status,
        "coil_read_status": coil_read_status,
        "error_type": "|".join(dict.fromkeys(error_types)) or None,
        "error_message": " | ".join(error_messages) or None,
        "raw_registers_unsigned": registers_unsigned,
        "raw_registers_signed": registers_signed,
        "raw_coils": coils,
        "odo_meter_from_pi": register(0),
        "flow_rate_x1000_from_pi": flow_rate_raw,
        "flow_rate_lpm_decoded": (
            round(flow_rate_raw / FLOW_RATE_SCALE, 6)
            if flow_rate_raw is not None
            else None
        ),
        "volume_x10000_from_pi": volume_raw,
        "volume_litre_decoded": (
            round(volume_raw / VOLUME_SCALE, 6)
            if volume_raw is not None
            else None
        ),
        "payment_status_from_pi": register(3),
        "source_sequence_from_pi": register(4),
        "observed_valve_raw_from_pi": register(5),
        "node_id_from_pi": register(6),
        "odo_meter_processed": register(7),
        "process_state": register(8),
        "valve_reason": register(9),
        "valve_command": coil(0),
        "abnormal_usage": coil(1),
        "payment_blocked": coil(2),
    }


def build_openplc_record(
    snapshot: dict[str, Any],
    common: dict[str, Any],
    *,
    openplc_ip: str,
    openplc_port: int,
    unit_id: int,
) -> dict[str, Any]:
    return {
        **common,
        "openplc_read_started_at": snapshot.get("openplc_read_started_at"),
        "openplc_read_finished_at": snapshot.get("openplc_read_finished_at"),
        "openplc_read_duration_ms": snapshot.get("openplc_read_duration_ms"),
        "source_layer": "openplc_controller",
        "source_device": openplc_ip,
        "source_endpoint": f"modbus://{openplc_ip}:{openplc_port}",
        "acquisition_method": "modbus_tcp_read_only",
        "read_status": snapshot.get("read_status"),
        "register_read_status": snapshot.get("register_read_status"),
        "coil_read_status": snapshot.get("coil_read_status"),
        "error_type": snapshot.get("error_type"),
        "error_message": snapshot.get("error_message"),
        "openplc_ip": openplc_ip,
        "openplc_port": openplc_port,
        "unit_id": unit_id,
        "holding_register_start": HOLDING_REGISTER_START,
        "holding_register_count": HOLDING_REGISTER_COUNT,
        "coil_start": COIL_START,
        "coil_count": COIL_COUNT,
        "odo_meter_from_pi": snapshot.get("odo_meter_from_pi"),
        "flow_rate_x1000_from_pi": snapshot.get("flow_rate_x1000_from_pi"),
        "flow_rate_lpm_decoded": snapshot.get("flow_rate_lpm_decoded"),
        "volume_x10000_from_pi": snapshot.get("volume_x10000_from_pi"),
        "volume_litre_decoded": snapshot.get("volume_litre_decoded"),
        "payment_status_from_pi": snapshot.get("payment_status_from_pi"),
        "source_sequence_from_pi": snapshot.get("source_sequence_from_pi"),
        "observed_valve_raw_from_pi": snapshot.get(
            "observed_valve_raw_from_pi"
        ),
        "node_id_from_pi": snapshot.get("node_id_from_pi"),
        "odo_meter_processed": snapshot.get("odo_meter_processed"),
        "process_state": snapshot.get("process_state"),
        "valve_reason": snapshot.get("valve_reason"),
        "valve_command": snapshot.get("valve_command"),
        "abnormal_usage": snapshot.get("abnormal_usage"),
        "payment_blocked": snapshot.get("payment_blocked"),
        "raw_registers_unsigned": snapshot.get("raw_registers_unsigned"),
        "raw_registers_signed": snapshot.get("raw_registers_signed"),
        "raw_coils": snapshot.get("raw_coils"),
    }


# =========================================================
# SESSION MANIFEST DAN HASH MANIFEST
# =========================================================

def build_session_manifest(
    args: argparse.Namespace,
    *,
    state_url: str,
    collector_session_id: str,
    collector_started_at: str,
    script_hash: str,
    session_directory: Path,
) -> dict[str, Any]:
    return {
        "manifest_schema_version": "1.0",
        "collector_schema_version": SCHEMA_VERSION,
        "framework_basis": {
            "NIST_SP_800_86": (
                "Controlled collection, provenance, "
                "acquisition metadata, and evidence "
                "integrity verification."
            ),
            "NISTIR_8428": (
                "OT routine collection, synchronized "
                "timeline, process monitoring, and "
                "baseline comparison."
            ),
        },
        "scope_note": (
            "Technical adaptation for a laboratory "
            "testbed; not a certification of NIST "
            "compliance."
        ),
        "experiment_id": args.experiment_id,
        "scenario": args.scenario,
        "collector_session_id": (
            collector_session_id
        ),
        "collector_started_at": (
            collector_started_at
        ),
        "collector_completed_at": None,
        "collector_host": socket.gethostname(),
        "collector_script": str(
            Path(__file__).resolve()
        ),
        "collector_script_sha256": script_hash,
        "python_version": sys.version,
        "platform": platform.platform(),
        "time_format": "ISO 8601 UTC",
        "duration_clock": "time.monotonic",
        "ntp_reference": args.ntp_reference,
        "raspberry_pi": {
            "ip": args.raspi_ip,
            "port": args.raspi_port,
            "path": args.raspi_path,
            "state_url": state_url,
            "acquisition_method": (
                "HTTP GET JSON read-only"
            ),
            "local_file_fallback": False,
        },
        "openplc": {
            "ip": args.openplc_ip,
            "port": args.openplc_port,
            "unit_id": args.unit_id,
            "acquisition_method": (
                "Modbus TCP read-only"
            ),
            "holding_register_start": (
                HOLDING_REGISTER_START
            ),
            "holding_register_count": (
                HOLDING_REGISTER_COUNT
            ),
            "coil_start": COIL_START,
            "coil_count": COIL_COUNT,
            "register_map": {
                "HR1024": "odo_meter_from_pi",
                "HR1025": "flow_rate_x1000_from_pi",
                "HR1026": "volume_x10000_from_pi",
                "HR1027": "payment_status_from_pi",
                "HR1028": "source_sequence_from_pi",
                "HR1029": "observed_valve_raw_from_pi",
                "HR1030": "node_id_from_pi",
                "HR1031": "odo_meter_processed",
                "HR1032": "process_state",
                "HR1033": "valve_reason",
            },
            "coil_map": {
                "coil_0": "valve_command",
                "coil_1": "abnormal_usage",
                "coil_2": "payment_blocked",
            },
            "scaling": {
                "flow_rate": "raw / 1000 = L/min",
                "volume": "raw / 10000 = litre",
            },
        },
        "collection": {
            "poll_interval_seconds": (
                args.poll_interval
            ),
            "http_timeout_seconds": (
                args.http_timeout
            ),
            "modbus_timeout_seconds": (
                args.modbus_timeout
            ),
            "phase_file": (
                str(args.phase_file)
                if args.phase_file
                else None
            ),
            "max_cycles": args.max_cycles,
        },
        "pcap_reference": (
            str(args.pcap_file)
            if args.pcap_file
            else None
        ),
        "session_directory": str(
            session_directory
        ),
        "preservation_note": (
            "SHA-256 calculated after acquisition "
            "files are closed. Create a separate "
            "read-only master evidence and working "
            "copy before analysis."
        ),
    }


def build_hash_manifest(
    session_directory: Path,
    manifest_path: Path,
) -> None:
    files = sorted(
        path
        for path in session_directory.rglob("*")
        if path.is_file()
        and path.resolve()
        != manifest_path.resolve()
    )

    for path in files:
        append_csv_row(
            manifest_path,
            HASH_FIELDS,
            {
                "relative_path": str(
                    path.relative_to(
                        session_directory
                    )
                ).replace("\\", "/"),
                "size_bytes": path.stat().st_size,
                "modified_at_utc": (
                    file_modified_at_utc(path)
                ),
                "hash_algorithm": "SHA-256",
                "sha256": sha256_file(path),
                "hashed_at_utc": utc_now(),
            },
        )


# =========================================================
# LOOP COLLECTOR
# =========================================================

STOP_REQUESTED = False


def request_stop(
    signum: int,
    _frame: Any,
) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True

    print(
        f"\n[INFO] Signal {signum} diterima. "
        "Collector akan menutup sesi secara "
        "terkontrol..."
    )


def run_collector(
    args: argparse.Namespace,
) -> Path:
    ensure_pymodbus_available()

    state_url = build_raspi_state_url(
        args.raspi_ip,
        args.raspi_port,
        args.raspi_path,
    )

    collector_session_id = create_id(
        "collector"
    )
    collector_started_at = utc_now()
    collector_host = socket.gethostname()

    session_directory = (
        args.output_root.resolve()
        / sanitize_name(args.scenario)
        / collector_session_id
    )

    raw_directory = (
        session_directory / "raw"
    )
    metadata_directory = (
        session_directory / "metadata"
    )

    raspi_csv_path = (
        raw_directory / "raspi_evidence.csv"
    )
    openplc_csv_path = (
        raw_directory / "openplc_evidence.csv"
    )
    event_log_path = (
        metadata_directory
        / "experiment_event_log.csv"
    )
    session_manifest_path = (
        metadata_directory
        / "session_manifest.json"
    )
    time_sync_before_path = (
        metadata_directory
        / "time_sync_before.txt"
    )
    time_sync_after_path = (
        metadata_directory
        / "time_sync_after.txt"
    )
    hash_manifest_path = (
        metadata_directory
        / "hash_manifest.csv"
    )

    raw_directory.mkdir(
        parents=True,
        exist_ok=True,
    )
    metadata_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    script_hash = sha256_file(
        Path(__file__).resolve()
    )

    session_manifest = build_session_manifest(
        args,
        state_url=state_url,
        collector_session_id=collector_session_id,
        collector_started_at=collector_started_at,
        script_hash=script_hash,
        session_directory=session_directory,
    )

    write_json_atomic(
        session_manifest_path,
        session_manifest,
    )

    if not args.skip_time_sync_snapshot:
        save_time_sync_snapshot(
            time_sync_before_path,
            args.ntp_reference,
        )

    modbus_client = create_modbus_client(
        args.openplc_ip,
        args.openplc_port,
        args.modbus_timeout,
    )

    collection_sequence = 0
    last_phase: Optional[str] = None

    print("=" * 74)
    print(
        " CROSS-LAYER DFIR COLLECTOR PAMSIMAS "
        "- THINGSBOARD MOCK / RASPBERRY PI / OPENPLC"
    )
    print("=" * 74)
    print(f"Raspberry Pi : {state_url}")
    print(
        f"OpenPLC      : "
        f"{args.openplc_ip}:"
        f"{args.openplc_port}"
    )
    print(f"Scenario     : {args.scenario}")
    print(f"Phase        : {args.phase}")
    print(
        f"Poll interval: "
        f"{args.poll_interval} detik"
    )
    print(f"Output       : {session_directory}")
    print("=" * 74)
    print("Tekan CTRL+C untuk berhenti.\n")

    try:
        while not STOP_REQUESTED:
            cycle_monotonic = time.monotonic()
            cycle_started_at = utc_now()

            (
                experiment_phase,
                phase_source,
                phase_note,
            ) = read_experiment_phase(
                args.phase,
                args.phase_file,
            )

            if experiment_phase != last_phase:
                append_csv_row(
                    event_log_path,
                    EVENT_FIELDS,
                    {
                        "event_timestamp": utc_now(),
                        "experiment_id": (
                            args.experiment_id
                        ),
                        "collector_session_id": (
                            collector_session_id
                        ),
                        "event_type": (
                            "EXPERIMENT_PHASE_CHANGED"
                        ),
                        "experiment_phase": (
                            experiment_phase
                        ),
                        "source": phase_source,
                        "note": phase_note,
                    },
                )

                last_phase = experiment_phase

            collection_sequence += 1

            collection_id = (
                f"{collector_session_id}"
                f"-COL-"
                f"{collection_sequence:06d}"
            )

            # RASPBERRY PI SELALU DIBACA VIA HTTP.
            raspi_state, raspi_metadata = (
                read_raspberry_pi_state(
                    state_url,
                    args.http_timeout,
                )
            )

            openplc_snapshot = read_openplc(
                modbus_client,
                openplc_ip=args.openplc_ip,
                openplc_port=args.openplc_port,
                unit_id=args.unit_id,
            )

            cycle_completed_at = utc_now()
            acquisition_window_ms = elapsed_ms(
                cycle_monotonic
            )

            raspi_finished = parse_timestamp(
                raspi_metadata.get(
                    "raspi_read_finished_at"
                )
            )

            openplc_finished = parse_timestamp(
                openplc_snapshot.get(
                    "openplc_read_finished_at"
                )
            )

            if (
                raspi_finished is not None
                and openplc_finished is not None
            ):
                sampling_skew_ms = round(
                    (
                        openplc_finished
                        - raspi_finished
                    ).total_seconds() * 1000,
                    3,
                )
            else:
                sampling_skew_ms = None

            common_metadata = {
                "experiment_id": (
                    args.experiment_id
                ),
                "scenario": args.scenario,
                "experiment_phase": (
                    experiment_phase
                ),
                "phase_source": phase_source,
                "collector_session_id": (
                    collector_session_id
                ),
                "collection_id": collection_id,
                "collection_sequence": (
                    collection_sequence
                ),
                "collector_host": collector_host,
                "collector_started_at": (
                    collector_started_at
                ),
                "cycle_started_at": (
                    cycle_started_at
                ),
                "cycle_completed_at": (
                    cycle_completed_at
                ),
                "acquisition_window_ms": (
                    acquisition_window_ms
                ),
                "sampling_skew_ms": (
                    sampling_skew_ms
                ),
            }

            raspi_record = build_raspi_record(
                raspi_state,
                raspi_metadata,
                common_metadata,
                state_url,
            )

            openplc_record = (
                build_openplc_record(
                    openplc_snapshot,
                    common_metadata,
                    openplc_ip=(
                        args.openplc_ip
                    ),
                    openplc_port=(
                        args.openplc_port
                    ),
                    unit_id=args.unit_id,
                )
            )

            append_csv_row(
                raspi_csv_path,
                RASPI_FIELDS,
                raspi_record,
            )

            append_csv_row(
                openplc_csv_path,
                OPENPLC_FIELDS,
                openplc_record,
            )

            valve_label = (
                "OPEN"
                if openplc_record["valve_command"] is True
                else "CLOSED"
                if openplc_record["valve_command"] is False
                else "UNKNOWN"
            )

            print(
                f"[{collection_id}] "
                f"phase={experiment_phase} | "
                f"raspi={raspi_record['read_status']} | "
                f"sent_odo={raspi_record['sent_odo_meter_litre']} | "
                f"openplc={openplc_record['read_status']} | "
                f"plc_odo={openplc_record['odo_meter_from_pi']} | "
                f"state={openplc_record['process_state']} | "
                f"valve={valve_label} | "
                f"skew={sampling_skew_ms} ms"
            )

            if (
                args.max_cycles is not None
                and collection_sequence
                >= args.max_cycles
            ):
                print(
                    "[INFO] max_cycles tercapai."
                )
                break

            remaining_seconds = (
                args.poll_interval
                - (
                    time.monotonic()
                    - cycle_monotonic
                )
            )

            if remaining_seconds > 0:
                time.sleep(
                    remaining_seconds
                )

    except KeyboardInterrupt:
        print(
            "\n[INFO] Collector dihentikan "
            "melalui keyboard."
        )

    finally:
        try:
            modbus_client.close()
        except Exception:
            pass

        if not args.skip_time_sync_snapshot:
            save_time_sync_snapshot(
                time_sync_after_path,
                args.ntp_reference,
            )

        session_manifest[
            "collector_completed_at"
        ] = utc_now()

        session_manifest[
            "total_collection_cycles"
        ] = collection_sequence

        write_json_atomic(
            session_manifest_path,
            session_manifest,
        )

        # Dilakukan setelah raw CSV dan metadata selesai ditulis.
        build_hash_manifest(
            session_directory,
            hash_manifest_path,
        )

        print("\n[INFO] Collection selesai.")
        print(
            f"[INFO] Session directory : "
            f"{session_directory}"
        )
        print(
            f"[INFO] Raspberry evidence: "
            f"{raspi_csv_path}"
        )
        print(
            f"[INFO] OpenPLC evidence   : "
            f"{openplc_csv_path}"
        )
        print(
            f"[INFO] Session manifest   : "
            f"{session_manifest_path}"
        )
        print(
            f"[INFO] Hash manifest      : "
            f"{hash_manifest_path}"
        )

    return session_directory


# =========================================================
# ARGUMENT PARSER
# =========================================================

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Collector read-only PAMSIMAS yang mengambil "
            "telemetry state Raspberry Pi melalui "
            "http://192.168.100.122:5020/state "
            "dan membaca OpenPLC melalui "
            "Modbus TCP."
        )
    )

    parser.add_argument(
        "--experiment-id",
        default=create_id("EXP"),
        help=(
            "ID eksperimen. Default dibuat "
            "otomatis."
        ),
    )

    parser.add_argument(
        "--scenario",
        default=DEFAULT_SCENARIO,
        help=(
            "Contoh: BASELINE atau "
            "PERLAKUAN_1_FDI."
        ),
    )

    parser.add_argument(
        "--phase",
        default=DEFAULT_PHASE,
        help=(
            "Contoh: BASELINE, PRE_ATTACK, "
            "ATTACK, RECOVERY, POST_RECOVERY."
        ),
    )

    parser.add_argument(
        "--phase-file",
        type=Path,
        help=(
            "File JSON/teks untuk mengubah "
            "fase ketika collector berjalan."
        ),
    )

    # Raspberry Pi selalu melalui HTTP.
    parser.add_argument(
        "--raspi-ip",
        default=DEFAULT_RASPI_IP,
        help=(
            "IP Raspberry Pi. "
            f"Default: {DEFAULT_RASPI_IP}"
        ),
    )

    parser.add_argument(
        "--raspi-port",
        type=int,
        default=DEFAULT_RASPI_PORT,
        help=(
            "Port state_proxy.py. "
            f"Default: {DEFAULT_RASPI_PORT}"
        ),
    )

    parser.add_argument(
        "--raspi-path",
        default=DEFAULT_RASPI_PATH,
        help=(
            "Path endpoint state. "
            f"Default: {DEFAULT_RASPI_PATH}"
        ),
    )

    parser.add_argument(
        "--http-timeout",
        type=float,
        default=DEFAULT_HTTP_TIMEOUT,
        help=(
            "Timeout HTTP dalam detik. "
            f"Default: {DEFAULT_HTTP_TIMEOUT}"
        ),
    )

    parser.add_argument(
        "--openplc-ip",
        default=DEFAULT_OPENPLC_IP,
        help=(
            "IP OpenPLC. "
            f"Default: {DEFAULT_OPENPLC_IP}"
        ),
    )

    parser.add_argument(
        "--openplc-port",
        type=int,
        default=DEFAULT_OPENPLC_PORT,
        help=(
            "Port Modbus TCP. "
            f"Default: {DEFAULT_OPENPLC_PORT}"
        ),
    )

    parser.add_argument(
        "--unit-id",
        type=int,
        default=DEFAULT_UNIT_ID,
        help=(
            "Modbus Unit ID. "
            f"Default: {DEFAULT_UNIT_ID}"
        ),
    )

    parser.add_argument(
        "--modbus-timeout",
        type=float,
        default=DEFAULT_MODBUS_TIMEOUT,
        help=(
            "Timeout Modbus dalam detik. "
            f"Default: {DEFAULT_MODBUS_TIMEOUT}"
        ),
    )

    parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help=(
            "Interval collection dalam detik. "
            f"Default: {DEFAULT_POLL_INTERVAL}"
        ),
    )

    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help=(
            "Root folder evidence. "
            f"Default: {DEFAULT_OUTPUT_ROOT}"
        ),
    )

    parser.add_argument(
        "--pcap-file",
        type=Path,
        help=(
            "Path PCAP/PCAPNG untuk dicatat "
            "sebagai referensi pada manifest. "
            "Collector tidak memulai Wireshark."
        ),
    )

    parser.add_argument(
        "--ntp-reference",
        default=DEFAULT_NTP_REFERENCE,
        help=(
            "Label referensi NTP pada manifest."
        ),
    )

    parser.add_argument(
        "--skip-time-sync-snapshot",
        action="store_true",
        help=(
            "Lewati snapshot status waktu OS."
        ),
    )

    parser.add_argument(
        "--max-cycles",
        type=int,
        help=(
            "Berhenti setelah sejumlah siklus. "
            "Berguna untuk pengujian."
        ),
    )

    args = parser.parse_args()

    if args.raspi_port <= 0:
        parser.error(
            "--raspi-port harus lebih besar dari 0"
        )

    if not args.raspi_path.startswith("/"):
        parser.error(
            "--raspi-path harus diawali '/'"
        )

    if args.http_timeout <= 0:
        parser.error(
            "--http-timeout harus lebih besar dari 0"
        )

    if args.openplc_port <= 0:
        parser.error(
            "--openplc-port harus lebih besar dari 0"
        )

    if args.unit_id < 0:
        parser.error(
            "--unit-id tidak boleh negatif"
        )

    if args.modbus_timeout <= 0:
        parser.error(
            "--modbus-timeout harus lebih besar dari 0"
        )

    if args.poll_interval <= 0:
        parser.error(
            "--poll-interval harus lebih besar dari 0"
        )

    if (
        args.max_cycles is not None
        and args.max_cycles <= 0
    ):
        parser.error(
            "--max-cycles harus lebih besar dari 0"
        )

    if args.phase_file is not None:
        args.phase_file = (
            args.phase_file.resolve()
        )

    if args.pcap_file is not None:
        args.pcap_file = (
            args.pcap_file.resolve()
        )

    args.output_root = (
        args.output_root.resolve()
    )

    return args


def main() -> int:
    signal.signal(
        signal.SIGINT,
        request_stop,
    )

    if hasattr(signal, "SIGTERM"):
        signal.signal(
            signal.SIGTERM,
            request_stop,
        )

    args = parse_arguments()

    try:
        run_collector(args)
        return 0

    except Exception as error:
        print(
            f"[FATAL] "
            f"{type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
