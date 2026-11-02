import serial
import requests
import re

SERIAL_PORT = 'COM3'  # Aapka COM Port
BAUD_RATE = 115200
FLASK_URL = "http://127.0.0.1:5000/api/wireless-attack"

try:
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
    print(f"[*] Connected to ESP8266 Deauther on {SERIAL_PORT}")

    while True:
        line = ser.readline().decode('utf-8', errors='ignore').strip()
        if line:
            print(f"[ESP Log]: {line}")

            # Jab bhi Packet summary line aaye
            if "Pkt/s" in line or "Deauth" in line or "Beacon" in line or "Probe" in line:
                
                # Packet counts extract karna
                deauth_match = re.search(r'Deauths:\s*(\d+)', line)
                beacon_match = re.search(r'Beacons:\s*(\d+)', line)
                probe_match = re.search(r'Probes:\s*(\d+)', line)

                deauth_cnt = int(deauth_match.group(1)) if deauth_match else 0
                beacon_cnt = int(beacon_match.group(1)) if beacon_match else 0
                probe_cnt = int(probe_match.group(1)) if probe_match else 0

                # 1. Check Deauth Attack
                if deauth_cnt > 0:
                    payload = {
                        "attack_type": "Deauth Attack",
                        "source_mac": "AA:BB:CC:11:22:33",
                        "target_mac": "FF:FF:FF:FF:FF:FF",
                        "channel": 6,
                        "packet_count": deauth_cnt,
                        "severity": "CRITICAL" if deauth_cnt > 50 else "HIGH",
                        "threat_score": 90,
                        "status": "ACTIVE",
                        "evidence": line
                    }
                    requests.post(FLASK_URL, json=payload)
                    print(f"  [-> Deauth Attack Alert Sent! Count: {deauth_cnt}]")

                # 2. Check Beacon Spam / Flood Attack
                if beacon_cnt > 0:
                    payload = {
                        "attack_type": "Beacon Flood Attack",
                        "source_mac": "DE:AD:BE:EF:00:11",
                        "target_mac": "BROADCAST",
                        "channel": 6,
                        "packet_count": beacon_cnt,
                        "severity": "MEDIUM",
                        "threat_score": 65,
                        "status": "ACTIVE",
                        "evidence": line
                    }
                    requests.post(FLASK_URL, json=payload)
                    print(f"  [-> Beacon Flood Alert Sent! Count: {beacon_cnt}]")

                # 3. Check Probe Spam / Sniffing
                if probe_cnt > 0:
                    payload = {
                        "attack_type": "Probe Request Burst",
                        "source_mac": "12:34:56:78:9A:BC",
                        "target_mac": "BROADCAST",
                        "channel": 6,
                        "packet_count": probe_cnt,
                        "severity": "LOW",
                        "threat_score": 40,
                        "status": "ACTIVE",
                        "evidence": line
                    }
                    requests.post(FLASK_URL, json=payload)
                    print(f"  [-> Probe Request Alert Sent! Count: {probe_cnt}]")

except Exception as e:
    print(f"[!] Serial Error: {e}")