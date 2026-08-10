#!/usr/bin/env python3
"""
preserve_case.py

Script preservation generik untuk satu skenario DFIR.

Letakkan file ini di dalam folder:

    evidence/<nama_skenario>/preservation/preserve_case.py

Struktur yang diharapkan:

    evidence/<nama_skenario>/
    ├── raw/
    ├── metadata/
    ├── master/
    ├── working/
    ├── preservation/
    │   └── preserve_case.py
    └── analysis/

Script akan:
1. Memverifikasi isi raw terhadap hash_manifest.csv dari collector.
2. Membuat preservation_manifest.csv.
3. Menyalin raw ke master dan memverifikasi SHA-256.
4. Menjadikan file master read-only.
5. Menyalin master ke working dan memverifikasi SHA-256.
6. Membuat evidence inventory, chain of custody, capture metadata,
   dan preservation notes.
7. Membuat folder analysis jika belum tersedia.

Script hanya memakai Python standard library.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import json
import os
import shutil
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


SCRIPT_PATH = Path(__file__).resolve()
PRESERVATION_DIR = SCRIPT_PATH.parent
CASE_ROOT = PRESERVATION_DIR.parent

# Struktur collector asli:
# CASE_ROOT/
# ├── raw/
# ├── metadata/
# ├── preservation/
# ├── master/
# ├── working/
# └── analysis/
RAW_DIR = CASE_ROOT / "raw"
METADATA_DIR = CASE_ROOT / "metadata"
MASTER_DIR = CASE_ROOT / "master"
WORKING_DIR = CASE_ROOT / "working"
ANALYSIS_DIR = CASE_ROOT / "analysis"

GENERATED_FILES = {
    "evidence_inventory.csv",
    "source_hash_verification.csv",
    "master_hash_verification.csv",
    "working_hash_verification.csv",
    "preservation_manifest.csv",
    "preservation_manifest.sha256.txt",
    "chain_of_custody.csv",
    "preservation_notes.txt",
    "capture_metadata.json",
    "preservation_run.json",
}


@dataclass(frozen=True)
class FileRecord:
    relative_path: str
    size_bytes: int
    modified_at_utc: str
    sha256: str


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def normalize_relative_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./")


def relative_path(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file_handle:
        while True:
            chunk = file_handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def modified_at_utc(path: Path) -> str:
    return (
        datetime.fromtimestamp(
            path.stat().st_mtime,
            tz=timezone.utc,
        )
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def list_files(root: Path) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
    )


def build_inventory(root: Path) -> list[FileRecord]:
    records: list[FileRecord] = []

    for path in list_files(root):
        records.append(
            FileRecord(
                relative_path=relative_path(root, path),
                size_bytes=path.stat().st_size,
                modified_at_utc=modified_at_utc(path),
                sha256=sha256_file(path),
            )
        )

    return records


def build_collection_inventory() -> list[FileRecord]:
    """
    Membuat inventory gabungan dari raw/ dan metadata/
    dengan path relatif tetap mempertahankan prefix folder.
    """
    records: list[FileRecord] = []

    for root_name, root_path in (
        ("raw", RAW_DIR),
        ("metadata", METADATA_DIR),
    ):
        for path in list_files(root_path):
            records.append(
                FileRecord(
                    relative_path=(
                        f"{root_name}/"
                        f"{relative_path(root_path, path)}"
                    ),
                    size_bytes=path.stat().st_size,
                    modified_at_utc=modified_at_utc(path),
                    sha256=sha256_file(path),
                )
            )

    return sorted(
        records,
        key=lambda record: record.relative_path,
    )


def write_csv(
    path: Path,
    fieldnames: list[str],
    rows: Iterable[dict[str, Any]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="", encoding="utf-8-sig") as file_handle:
        writer = csv.DictWriter(
            file_handle,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            default=str,
        ) + "\n",
        encoding="utf-8",
    )


def find_unique_file(root: Path, filename: str) -> Path:
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
        joined = "\n".join(str(path) for path in matches)
        raise RuntimeError(
            f"Ditemukan lebih dari satu {filename}. "
            f"Lokasi ambigu:\n{joined}"
        )

    return matches[0]


def load_session_manifest() -> tuple[Path, dict[str, Any]]:
    # Prioritaskan struktur collector asli: metadata/session_manifest.json.
    preferred = METADATA_DIR / "session_manifest.json"

    if preferred.is_file():
        path = preferred
    else:
        # Fallback untuk struktur yang sudah dirapikan menjadi satu folder.
        path = find_unique_file(CASE_ROOT, "session_manifest.json")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"Gagal membaca session manifest: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise ValueError(
            "session_manifest.json harus berisi JSON object."
        )

    return path, payload


def resolve_manifest_entry(
    manifest_relative_path: str,
) -> tuple[Path, str]:
    """
    Mencari file yang dirujuk oleh hash_manifest.csv.

    Prioritas:
    1. Path relatif persis di bawah raw/.
    2. Path setelah awalan raw/ atau metadata/ dihapus.
    3. Pencarian basename unik.

    Fallback basename dibutuhkan bila output collector dirapikan ke dalam
    satu folder raw. Perubahan lokasi dicatat sebagai PATH_RELOCATED.
    """
    normalized = normalize_relative_path(
        manifest_relative_path
    )

    candidates: list[tuple[Path, str]] = [
        (
            CASE_ROOT / Path(normalized),
            "EXACT_UNDER_CASE_ROOT",
        ),
        (
            RAW_DIR / Path(normalized),
            "EXACT_UNDER_RAW",
        ),
        (
            METADATA_DIR / Path(normalized),
            "EXACT_UNDER_METADATA",
        ),
    ]

    parts = Path(normalized).parts

    if parts and parts[0].lower() in {
        "raw",
        "metadata",
    }:
        stripped = Path(*parts[1:])

        candidates.append(
            (
                RAW_DIR / stripped,
                "PREFIX_REMOVED",
            )
        )

        candidates.append(
            (
                RAW_DIR / parts[0] / stripped,
                "COLLECTOR_STRUCTURE_PRESERVED",
            )
        )

    seen: set[Path] = set()

    for candidate, method in candidates:
        candidate = candidate.resolve()

        if candidate in seen:
            continue

        seen.add(candidate)

        if candidate.is_file():
            return candidate, method

    basename = Path(normalized).name

    basename_matches = [
        path
        for search_root in (RAW_DIR, METADATA_DIR)
        for path in search_root.rglob(basename)
        if path.is_file()
    ]

    if len(basename_matches) == 1:
        return basename_matches[0], "BASENAME_UNIQUE_PATH_RELOCATED"

    if len(basename_matches) > 1:
        joined = "\n".join(
            str(path)
            for path in basename_matches
        )
        raise RuntimeError(
            f"Path manifest '{manifest_relative_path}' "
            f"tidak ditemukan secara persis dan basename "
            f"'{basename}' ambigu:\n{joined}"
        )

    raise FileNotFoundError(
        f"File manifest tidak ditemukan: "
        f"{manifest_relative_path}"
    )


def verify_collector_hash_manifest(
    manifest_path: Path,
) -> list[dict[str, Any]]:
    with manifest_path.open(
        "r",
        newline="",
        encoding="utf-8-sig",
    ) as file_handle:
        rows = list(csv.DictReader(file_handle))

    required_fields = {
        "relative_path",
        "size_bytes",
        "sha256",
    }

    if not rows:
        raise ValueError(
            "hash_manifest.csv tidak berisi record."
        )

    if not required_fields.issubset(rows[0].keys()):
        raise ValueError(
            "hash_manifest.csv tidak memiliki kolom "
            "relative_path, size_bytes, dan sha256."
        )

    results: list[dict[str, Any]] = []

    for row in rows:
        manifest_relative = row["relative_path"]
        expected_hash = row["sha256"].strip().lower()
        expected_size = int(row["size_bytes"])

        try:
            actual_path, resolution = (
                resolve_manifest_entry(
                    manifest_relative
                )
            )

            actual_hash = sha256_file(actual_path)
            actual_size = actual_path.stat().st_size

            verification = (
                "MATCH"
                if (
                    actual_hash == expected_hash
                    and actual_size == expected_size
                )
                else "MISMATCH"
            )

            error_message = ""

        except Exception as error:
            actual_path = None
            resolution = "FAILED"
            actual_hash = ""
            actual_size = ""
            verification = "MISSING_OR_AMBIGUOUS"
            error_message = (
                f"{type(error).__name__}: {error}"
            )

        results.append({
            "manifest_relative_path": manifest_relative,
            "actual_relative_path": (
                relative_path(CASE_ROOT, actual_path)
                if actual_path is not None
                else ""
            ),
            "path_resolution": resolution,
            "expected_size_bytes": expected_size,
            "actual_size_bytes": actual_size,
            "expected_sha256": expected_hash,
            "actual_sha256": actual_hash,
            "verification": verification,
            "verified_at_utc": utc_now(),
            "error_message": error_message,
        })

    return results


def ensure_empty_destination(
    path: Path,
    *,
    force: bool,
) -> None:
    if path.exists() and any(path.iterdir()):
        if not force:
            raise RuntimeError(
                f"Folder {path} tidak kosong. "
                "Gunakan --force hanya bila salinan lama "
                "memang boleh dibuat ulang."
            )

        shutil.rmtree(path)

    path.mkdir(parents=True, exist_ok=True)


def copy_directory_contents(
    source: Path,
    destination: Path,
) -> None:
    for source_path in source.iterdir():
        destination_path = (
            destination / source_path.name
        )

        if source_path.is_dir():
            shutil.copytree(
                source_path,
                destination_path,
                copy_function=shutil.copy2,
            )
        else:
            shutil.copy2(
                source_path,
                destination_path,
            )


def compare_inventories(
    source_inventory: list[FileRecord],
    destination_inventory: list[FileRecord],
    *,
    source_label: str,
    destination_label: str,
) -> list[dict[str, Any]]:
    source_map = {
        record.relative_path: record
        for record in source_inventory
    }

    destination_map = {
        record.relative_path: record
        for record in destination_inventory
    }

    all_paths = sorted(
        set(source_map) | set(destination_map)
    )

    results: list[dict[str, Any]] = []

    for path in all_paths:
        source_record = source_map.get(path)
        destination_record = (
            destination_map.get(path)
        )

        if source_record is None:
            verification = "EXTRA_IN_DESTINATION"
            note = (
                f"File tidak terdapat pada "
                f"{source_label}."
            )

        elif destination_record is None:
            verification = "MISSING_IN_DESTINATION"
            note = (
                f"File tidak terdapat pada "
                f"{destination_label}."
            )

        elif (
            source_record.sha256
            != destination_record.sha256
            or source_record.size_bytes
            != destination_record.size_bytes
        ):
            verification = "MISMATCH"
            note = "Hash atau ukuran file berbeda."

        else:
            verification = "MATCH"
            note = ""

        results.append({
            "relative_path": path,
            "source_label": source_label,
            "destination_label": destination_label,
            "source_size_bytes": (
                source_record.size_bytes
                if source_record
                else ""
            ),
            "destination_size_bytes": (
                destination_record.size_bytes
                if destination_record
                else ""
            ),
            "source_sha256": (
                source_record.sha256
                if source_record
                else ""
            ),
            "destination_sha256": (
                destination_record.sha256
                if destination_record
                else ""
            ),
            "verification": verification,
            "verified_at_utc": utc_now(),
            "note": note,
        })

    return results


def set_file_read_only(path: Path) -> None:
    """
    Menjadikan file read-only sebagai kontrol tambahan.

    SHA-256 dan chain of custody tetap menjadi kontrol utama.
    """
    if os.name == "nt":
        FILE_ATTRIBUTE_READONLY = 0x01

        result = ctypes.windll.kernel32.SetFileAttributesW(
            str(path),
            FILE_ATTRIBUTE_READONLY,
        )

        if result == 0:
            raise OSError(
                f"Gagal menjadikan read-only: {path}"
            )

    else:
        path.chmod(
            stat.S_IRUSR
            | stat.S_IRGRP
            | stat.S_IROTH
        )


def clear_file_read_only(path: Path) -> None:
    if os.name == "nt":
        FILE_ATTRIBUTE_NORMAL = 0x80

        ctypes.windll.kernel32.SetFileAttributesW(
            str(path),
            FILE_ATTRIBUTE_NORMAL,
        )

    else:
        path.chmod(
            stat.S_IRUSR
            | stat.S_IWUSR
            | stat.S_IRGRP
            | stat.S_IROTH
        )


def classify_evidence(path: str) -> tuple[str, str, str]:
    lower_path = path.lower()
    filename = Path(path).name.lower()

    if filename == "raspi_evidence.csv":
        return (
            "raw_source",
            "Raspberry Pi via HTTP state proxy",
            "PRIMARY_SOURCE",
        )

    if filename == "openplc_evidence.csv":
        return (
            "raw_control",
            "OpenPLC via Modbus TCP read-only",
            "PRIMARY_CONTROL",
        )

    if filename.endswith(
        (".pcap", ".pcapng")
    ):
        return (
            "raw_network",
            "Wireshark/Npcap",
            "NETWORK_EVIDENCE",
        )

    if filename == "hash_manifest.csv":
        return (
            "integrity_metadata",
            "Collector",
            "ORIGINAL_HASH_MANIFEST",
        )

    if any(
        token in filename
        for token in (
            "session_manifest",
            "experiment_event_log",
            "time_sync_before",
            "time_sync_after",
        )
    ):
        return (
            "collection_metadata",
            "Collector",
            "SUPPORTING_METADATA",
        )

    if "metadata/" in lower_path:
        return (
            "collection_metadata",
            "Collector",
            "SUPPORTING_METADATA",
        )

    return (
        "supporting_file",
        "Collection session",
        "SUPPORTING",
    )


def create_evidence_inventory(
    inventory: list[FileRecord],
    *,
    scenario: str,
    session_id: str,
) -> list[dict[str, Any]]:
    safe_scenario = (
        scenario.upper().replace(" ", "_")
    )

    rows: list[dict[str, Any]] = []

    for index, record in enumerate(
        inventory,
        start=1,
    ):
        category, source, role = (
            classify_evidence(
                record.relative_path
            )
        )

        rows.append({
            "evidence_id": (
                f"EVD-{safe_scenario}-{index:03d}"
            ),
            "relative_path": record.relative_path,
            "category": category,
            "source": source,
            "evidence_role": role,
            "scenario": scenario,
            "collector_session_id": session_id,
            "size_bytes": record.size_bytes,
            "sha256": record.sha256,
            "status": "PRESERVED",
            "notes": "",
        })

    return rows


def detect_time_sync_notes() -> list[str]:
    notes: list[str] = []

    for name in (
        "time_sync_before.txt",
        "time_sync_after.txt",
    ):
        matches = list(
            RAW_DIR.rglob(name)
        )

        if len(matches) != 1:
            continue

        text = matches[0].read_text(
            encoding="utf-8",
            errors="replace",
        )

        if (
            "not synchronized" in text.lower()
            or "local cmos clock" in text.lower()
        ):
            notes.append(
                f"{name} menunjukkan clock belum "
                "tersinkron dan/atau menggunakan "
                "Local CMOS Clock."
            )

        if "access is denied" in text.lower():
            notes.append(
                f"{name} memuat error Access is denied "
                "pada pemeriksaan Windows Time."
            )

    return notes


def create_capture_metadata(
    *,
    scenario: str,
    capture_interface: str,
    capture_filter: str,
    capture_role: str,
) -> dict[str, Any]:
    capture_files = [
        path
        for path in list_files(RAW_DIR)
        if path.suffix.lower()
        in {".pcap", ".pcapng"}
    ]

    return {
        "created_at_utc": utc_now(),
        "scenario": scenario,
        "capture_interface": (
            capture_interface
            or "UNSPECIFIED"
        ),
        "capture_filter": (
            capture_filter
            or "UNSPECIFIED"
        ),
        "capture_role": (
            capture_role
            or "UNSPECIFIED"
        ),
        "capture_files": [
            {
                "relative_path": (
                    relative_path(
                        RAW_DIR,
                        path,
                    )
                ),
                "size_bytes": (
                    path.stat().st_size
                ),
                "sha256": sha256_file(path),
            }
            for path in capture_files
        ],
        "note": (
            "Interface, capture filter, dan role "
            "berasal dari parameter operator; "
            "script tidak menebaknya dari isi PCAP."
        ),
    }


def remove_generated_files_for_force() -> None:
    for filename in GENERATED_FILES:
        path = PRESERVATION_DIR / filename

        if path.exists():
            clear_file_read_only(path)
            path.unlink()


def validate_case_structure() -> None:
    if PRESERVATION_DIR.name.lower() != "preservation":
        raise RuntimeError(
            "Script harus diletakkan di dalam folder "
            "bernama preservation."
        )

    if not RAW_DIR.is_dir():
        raise FileNotFoundError(
            f"Folder raw tidak ditemukan: {RAW_DIR}"
        )

    if not METADATA_DIR.is_dir():
        raise FileNotFoundError(
            f"Folder metadata tidak ditemukan: {METADATA_DIR}"
        )

    PRESERVATION_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )
    ANALYSIS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Membuat master, working copy, dan "
            "dokumen preservation untuk satu "
            "skenario DFIR."
        )
    )

    parser.add_argument(
        "--operator",
        required=True,
        help="Nama orang yang melakukan preservation.",
    )

    parser.add_argument(
        "--capture-interface",
        default="",
        help=(
            "Contoh: Wi-Fi atau "
            "Npcap Loopback Adapter."
        ),
    )

    parser.add_argument(
        "--capture-filter",
        default="tcp port 502",
        help="Capture filter yang digunakan.",
    )

    parser.add_argument(
        "--capture-role",
        default="",
        help=(
            "Peran PCAP dalam evidence."
        ),
    )

    parser.add_argument(
        "--note",
        action="append",
        default=[],
        help=(
            "Catatan tambahan. Dapat dipakai "
            "lebih dari satu kali."
        ),
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Hapus dan buat ulang master, working, "
            "serta record yang dihasilkan script."
        ),
    )

    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    validate_case_structure()

    if args.force:
        remove_generated_files_for_force()

    session_manifest_path, session_manifest = (
        load_session_manifest()
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

    preferred_hash_manifest = (
        METADATA_DIR / "hash_manifest.csv"
    )

    if preferred_hash_manifest.is_file():
        hash_manifest_path = preferred_hash_manifest
    else:
        hash_manifest_path = find_unique_file(
            CASE_ROOT,
            "hash_manifest.csv",
        )

    print("=" * 72)
    print(" DFIR PRESERVATION")
    print("=" * 72)
    print(f"Case root   : {CASE_ROOT}")
    print(f"Scenario    : {scenario}")
    print(f"Experiment  : {experiment_id}")
    print(f"Session ID  : {session_id}")
    print(f"Operator    : {args.operator}")
    print("=" * 72)

    # -----------------------------------------------------
    # 1. Verifikasi raw terhadap hash manifest collector
    # -----------------------------------------------------

    source_verification = (
        verify_collector_hash_manifest(
            hash_manifest_path
        )
    )

    write_csv(
        PRESERVATION_DIR
        / "source_hash_verification.csv",
        [
            "manifest_relative_path",
            "actual_relative_path",
            "path_resolution",
            "expected_size_bytes",
            "actual_size_bytes",
            "expected_sha256",
            "actual_sha256",
            "verification",
            "verified_at_utc",
            "error_message",
        ],
        source_verification,
    )

    source_failures = [
        row
        for row in source_verification
        if row["verification"] != "MATCH"
    ]

    if source_failures:
        print(
            "[FAILED] Verifikasi raw terhadap "
            "collector hash manifest gagal."
        )
        print(
            "Periksa preservation/"
            "source_hash_verification.csv"
        )
        return 1

    print("[OK] Raw sesuai collector hash manifest.")

    # -----------------------------------------------------
    # 2. Preservation manifest dan evidence inventory
    # -----------------------------------------------------

    raw_inventory = build_collection_inventory()
    manifest_created_at = utc_now()

    write_csv(
        PRESERVATION_DIR
        / "preservation_manifest.csv",
        [
            "relative_path",
            "size_bytes",
            "modified_at_utc",
            "hash_algorithm",
            "sha256",
            "hashed_at_utc",
        ],
        (
            {
                "relative_path": record.relative_path,
                "size_bytes": record.size_bytes,
                "modified_at_utc": (
                    record.modified_at_utc
                ),
                "hash_algorithm": "SHA-256",
                "sha256": record.sha256,
                "hashed_at_utc": (
                    manifest_created_at
                ),
            }
            for record in raw_inventory
        ),
    )

    preservation_manifest_path = (
        PRESERVATION_DIR
        / "preservation_manifest.csv"
    )

    preservation_manifest_hash = sha256_file(
        preservation_manifest_path
    )

    (
        PRESERVATION_DIR
        / "preservation_manifest.sha256.txt"
    ).write_text(
        "SHA-256  "
        f"{preservation_manifest_hash}  "
        "preservation_manifest.csv\n",
        encoding="utf-8",
    )

    evidence_inventory = (
        create_evidence_inventory(
            raw_inventory,
            scenario=scenario,
            session_id=session_id,
        )
    )

    write_csv(
        PRESERVATION_DIR
        / "evidence_inventory.csv",
        [
            "evidence_id",
            "relative_path",
            "category",
            "source",
            "evidence_role",
            "scenario",
            "collector_session_id",
            "size_bytes",
            "sha256",
            "status",
            "notes",
        ],
        evidence_inventory,
    )

    # -----------------------------------------------------
    # 3. Buat master dan verifikasi raw = master
    # -----------------------------------------------------

    ensure_empty_destination(
        MASTER_DIR,
        force=args.force,
    )

    shutil.copytree(
        RAW_DIR,
        MASTER_DIR / "raw",
        copy_function=shutil.copy2,
    )
    shutil.copytree(
        METADATA_DIR,
        MASTER_DIR / "metadata",
        copy_function=shutil.copy2,
    )

    master_inventory = build_inventory(
        MASTER_DIR
    )

    master_verification = compare_inventories(
        raw_inventory,
        master_inventory,
        source_label="RAW",
        destination_label="MASTER",
    )

    write_csv(
        PRESERVATION_DIR
        / "master_hash_verification.csv",
        [
            "relative_path",
            "source_label",
            "destination_label",
            "source_size_bytes",
            "destination_size_bytes",
            "source_sha256",
            "destination_sha256",
            "verification",
            "verified_at_utc",
            "note",
        ],
        master_verification,
    )

    master_failures = [
        row
        for row in master_verification
        if row["verification"] != "MATCH"
    ]

    if master_failures:
        print(
            "[FAILED] Verifikasi raw-master gagal."
        )
        return 1

    for path in list_files(MASTER_DIR):
        set_file_read_only(path)

    print("[OK] Master dibuat dan seluruh file MATCH.")

    # -----------------------------------------------------
    # 4. Buat working dan verifikasi master = working
    # -----------------------------------------------------

    ensure_empty_destination(
        WORKING_DIR,
        force=args.force,
    )

    copy_directory_contents(
        MASTER_DIR,
        WORKING_DIR,
    )

    for path in list_files(WORKING_DIR):
        clear_file_read_only(path)

    working_inventory = build_inventory(
        WORKING_DIR
    )

    working_verification = compare_inventories(
        master_inventory,
        working_inventory,
        source_label="MASTER",
        destination_label="INITIAL_WORKING",
    )

    write_csv(
        PRESERVATION_DIR
        / "working_hash_verification.csv",
        [
            "relative_path",
            "source_label",
            "destination_label",
            "source_size_bytes",
            "destination_size_bytes",
            "source_sha256",
            "destination_sha256",
            "verification",
            "verified_at_utc",
            "note",
        ],
        working_verification,
    )

    working_failures = [
        row
        for row in working_verification
        if row["verification"] != "MATCH"
    ]

    if working_failures:
        print(
            "[FAILED] Verifikasi master-working "
            "gagal."
        )
        return 1

    print("[OK] Working copy dibuat dan seluruh file MATCH.")

    # -----------------------------------------------------
    # 5. Capture metadata
    # -----------------------------------------------------

    capture_metadata = create_capture_metadata(
        scenario=scenario,
        capture_interface=(
            args.capture_interface
        ),
        capture_filter=args.capture_filter,
        capture_role=args.capture_role,
    )

    write_json(
        PRESERVATION_DIR
        / "capture_metadata.json",
        capture_metadata,
    )

    # -----------------------------------------------------
    # 6. Preservation notes
    # -----------------------------------------------------

    notes = [
        "PRESERVATION NOTES",
        "",
        f"created_at_utc={utc_now()}",
        f"operator={args.operator}",
        f"scenario={scenario}",
        f"experiment_id={experiment_id}",
        f"collector_session_id={session_id}",
        f"session_manifest={relative_path(CASE_ROOT, session_manifest_path)}",
        "",
        "Method:",
        "- Isi raw diverifikasi terhadap hash_manifest.csv dari collector.",
        "- Master dibuat dari raw dan diverifikasi menggunakan SHA-256.",
        "- Working copy dibuat dari master dan diverifikasi menggunakan SHA-256.",
        "- File master dibuat read-only sebagai kontrol tambahan.",
        "- Examination dan analysis hanya dilakukan pada working copy.",
        "",
        "Known conditions and limitations:",
    ]

    automated_notes = detect_time_sync_notes()

    if (
        session_manifest.get(
            "pcap_reference"
        )
        in (None, "", "null")
        and capture_metadata["capture_files"]
    ):
        automated_notes.append(
            "session_manifest.json memiliki "
            "pcap_reference=null/kosong walaupun "
            "file PCAP ditemukan di raw."
        )

    if not automated_notes and not args.note:
        notes.append(
            "- Tidak ada catatan otomatis tambahan."
        )
    else:
        for note in [
            *automated_notes,
            *args.note,
        ]:
            notes.append(f"- {note}")

    notes.extend([
        "",
        "Interpretation rule:",
        "- SHA-256 membuktikan file tidak berubah sejak hashing; hash tidak membuktikan nilai proses benar secara operasional.",
        "- Raw dan master tidak boleh diedit, dinormalisasi, atau diperbaiki.",
        "- Hasil parsing, filtering, correlation, dan perhitungan harus disimpan di analysis.",
    ])

    (
        PRESERVATION_DIR
        / "preservation_notes.txt"
    ).write_text(
        "\n".join(notes) + "\n",
        encoding="utf-8",
    )

    # -----------------------------------------------------
    # 7. Chain of custody awal
    # -----------------------------------------------------

    custody_rows = [
        {
            "custody_id": "COC-001",
            "timestamp_utc": utc_now(),
            "person": args.operator,
            "action": "SOURCE_VERIFIED",
            "source_location": (
                f"{RAW_DIR}; {METADATA_DIR}"
            ),
            "destination_location": "",
            "reason": (
                "Verifikasi raw terhadap collector "
                "hash manifest."
            ),
            "verification_reference": (
                "source_hash_verification.csv"
            ),
            "status": "COMPLETED",
            "notes": "",
        },
        {
            "custody_id": "COC-002",
            "timestamp_utc": utc_now(),
            "person": args.operator,
            "action": "MASTER_COPY_CREATED",
            "source_location": (
                f"{RAW_DIR}; {METADATA_DIR}"
            ),
            "destination_location": str(MASTER_DIR),
            "reason": (
                "Membuat evidence acuan untuk "
                "preservation."
            ),
            "verification_reference": (
                "master_hash_verification.csv"
            ),
            "status": "COMPLETED",
            "notes": (
                "Master dibuat read-only setelah "
                "verifikasi berhasil."
            ),
        },
        {
            "custody_id": "COC-003",
            "timestamp_utc": utc_now(),
            "person": args.operator,
            "action": "WORKING_COPY_CREATED",
            "source_location": str(MASTER_DIR),
            "destination_location": str(WORKING_DIR),
            "reason": (
                "Membuat salinan untuk examination "
                "dan analysis."
            ),
            "verification_reference": (
                "working_hash_verification.csv"
            ),
            "status": "COMPLETED",
            "notes": "",
        },
    ]

    write_csv(
        PRESERVATION_DIR
        / "chain_of_custody.csv",
        [
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
        ],
        custody_rows,
    )

    # -----------------------------------------------------
    # 8. Preservation run metadata
    # -----------------------------------------------------

    write_json(
        PRESERVATION_DIR
        / "preservation_run.json",
        {
            "created_at_utc": utc_now(),
            "script": str(SCRIPT_PATH),
            "python_version": sys.version,
            "operator": args.operator,
            "case_root": str(CASE_ROOT),
            "scenario": scenario,
            "experiment_id": experiment_id,
            "collector_session_id": session_id,
            "raw_file_count": len(raw_inventory),
            "master_file_count": len(
                master_inventory
            ),
            "working_file_count": len(
                working_inventory
            ),
            "source_verification": "MATCH",
            "master_verification": "MATCH",
            "working_verification": "MATCH",
            "master_read_only": True,
            "analysis_directory": str(
                ANALYSIS_DIR
            ),
        },
    )

    print("=" * 72)
    print("[SUCCESS] Preservation selesai.")
    print(f"Master       : {MASTER_DIR}")
    print(f"Working      : {WORKING_DIR}")
    print(f"Records      : {PRESERVATION_DIR}")
    print(f"Analysis     : {ANALYSIS_DIR}")
    print("=" * 72)
    print(
        "Lanjutkan Examination hanya dari "
        "folder working/."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())