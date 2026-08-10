PEMILAHAN SCRIPT SIMULASI DFIR
==============================

Paket ini berisi script yang paling kuat terkonfirmasi dipakai pada sesi simulasi final
tanggal 28 Juli 2026. File pengolahan evidence (preservation, examination, analysis,
reporting) sengaja tidak disertakan sesuai permintaan.

1) COLLECTION
-------------
- collection/collector_updated.py
  TERKONFIRMASI dipakai untuk BASELINE, P1, P2, dan P3.
  Bukti: session_manifest.json keempat sesi menunjuk langsung ke
  C:\Users\user\Documents\PrivateProject\DFIR\collector_updated.py
  dengan SHA-256:
  c1aedcf0b1587202e0a69d0144da35a831f13be80d3dc72b99cd48ef7d114be7
  Hash file dalam project identik.

- collection/phase_control.py
  SANGAT KUAT/OPERASIONAL dipakai untuk PRE_ATTACK, ATTACK, RECOVERY,
  POST_RECOVERY melalui experiment_phase.json. experiment_event_log.csv
  pada P1/P2/P3 membaca phase dari file tersebut.

- collection/experiment_phase.json
  Bukan script, tetapi file kontrol fase yang dibaca collector.

2) PERLAKUAN 1 — FDI
---------------------
- perlakuan_1_FDI/attack_fdi.py
  TERKONFIRMASI dari karakteristik trafik:
  attacker 192.168.21.210 -> OpenPLC 192.168.21.209
  FC06 / HR1024, 75 write request selama ~29.82 detik, interval ~0.4 detik.
  Penting: evidence PCAP final menunjukkan VALUE AKTUAL = 100, bukan 1000.
  Jadi script kemungkinan dijalankan dengan override kira-kira:
      --ip 192.168.21.209 --value 100 --duration 30 --interval 0.4
  Script melakukan read-back setelah write; pola Transaction ID pada PCAP juga
  konsisten dengan write+readback berulang.

3) PERLAKUAN 2 — FLOOD
-----------------------
- perlakuan_2_FLOOD/flod.py
  TERKONFIRMASI kuat dari signature:
  FC06 / HR1024 = 1212, transaction_id = 0, satu koneksi utama, pengiriman
  tanpa jeda. PCAP mencatat 28.607 attacker write request dalam ~0.43 detik.
  Ini cocok langsung dengan implementasi flod.py.
  Catatan: script ini TIDAK secara eksplisit membuat TCP RST. PCAP memang
  memiliki RST pada flow attacker, tetapi RST tersebut tidak cukup untuk
  menyatakan ada pemanggilan script khusus RST.

4) PERLAKUAN 3 — REPLAY + FLOOD
--------------------------------
- perlakuan_3_REPLAY_FLOOD/attack3.py
  TERKONFIRMASI sangat kuat dari payload dan durasi:
  FC16 write HR1024-HR1030 dengan snapshot:
      [79, 2250, 14500, 1, 125, 1, 1]
  PCAP mencatat 17.640 attacker request selama ~45.12 detik.
  Ini sangat sesuai dengan attack3.py:
      Replay 15 detik @ 1 s
      + Flood 30 detik @ 0.001 s
  Nilai replay ODO = 79 dan source_sequence lama = 125.
  attack_phase3.py BUKAN script final P3 karena menggunakan konsep FDI nilai
  1000 dan FC06, sedangkan evidence final P3 berisi replay FC16 nilai 79.

SCRIPT ROOT YANG TIDAK DIPILIH
------------------------------
- collector.py
  Versi lama; manifest final secara eksplisit menunjuk collector_updated.py.
- attack_phase3.py
  Tidak cocok dengan evidence P3 final (FDI 1000/FC06 vs replay 79/FC16).
- perlakuan2.py
  Controlled FC03 read-only; tidak cocok dengan P2 final FC06=1212.
- modbus_availability_load_test.py
  File log yang ditemukan bertanggal sekitar 17:03, sedangkan sesi P2 final
  berlangsung sekitar 11:51-11:52; merupakan test terpisah.
- scapy_modbus_crash.py
  Menggunakan malformed FC16 + spoofed SYN/RST; signature utama ini tidak
  cocok dengan P2 final yang didominasi FC06 HR1024=1212.
- analysis/analyze_testbed.py
  Tidak disertakan karena termasuk pengolahan evidence.

CATATAN KONSISTENSI DATA
------------------------
P1 memiliki ketidakkonsistenan metadata:
- experiment_event_log.csv mencatat note "Unauthorized FC06 HR1024=1000"
- tetapi PCAP dan openplc_evidence.csv menunjukkan nilai aktual 100.
Untuk dokumentasi simulasi final, evidence aktual lebih kuat daripada note fase,
sehingga nilai P1 sebaiknya dicatat sebagai 100 untuk sesi 28 Juli 2026 ini.

Folder ini adalah hasil pemilahan; seluruh source script disalin tanpa modifikasi.
