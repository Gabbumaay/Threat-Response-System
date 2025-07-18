import sqlite3
from datetime import datetime
import csv
import os
from scapy.all import ARP, sniff
from threading import Thread

DB_PATH = "logs.db"
arp_cache = {}

# Initialize the database if not present
def initialize_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timeStamp TEXT,
        src_ip TEXT,
        src_mac TEXT,
        threat_type TEXT,
        description TEXT
    )
    """)
    conn.commit()
    conn.close()

# Function to insert a threat log
def log_threat(ip, mac, threat_type, description):
    timeStamp = datetime.now().isoformat()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO threat_logs (timeStamp, src_ip, src_mac, threat_type, description)
    VALUES (?, ?, ?, ?, ?)
    """, (timeStamp, ip, mac, threat_type, description))
    conn.commit()
    conn.close()
    print(f"\n✅ [LOGGED] {threat_type} from {ip} ({mac}) at {timeStamp}")

# Passive ARP sniffing for ARP spoofing
def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        print(f"[DEBUG] ARP reply: {ip} is at {mac}")

        if ip not in arp_cache:
            arp_cache[ip] = mac
        elif arp_cache[ip] != mac:
            description = f"⚠️ Detected ARP spoofing! {ip} was at {arp_cache[ip]}, now claims to be at {mac}"
            log_threat(ip, mac, "ARP Spoofing", description)
            # Update cache so we don't flood logs
            arp_cache[ip] = mac


# Background ARP monitor
def start_sniffer():
    print("\n🕵️ ARP Sniffer started. Listening for spoofing attempts...")
    sniff(filter="arp", store=0, prn=detect_arp_spoof)

# View logs
def view_logs():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    print("\n📋 Threat Logs:")
    print("=" * 60)
    for row in rows:
        print(f"[{row[0]}] {row[4]} from {row[2]} ({row[3]}) at {row[1]}")
        print(f"    └─ {row[5]}")
    print("=" * 60)

# Export logs to CSV
def export_to_csv(filename="threat_logs_export.csv"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_logs")
    rows = cursor.fetchall()
    conn.close()
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Timestamp", "Source IP", "Source MAC", "Threat Type", "Description"])
        writer.writerows(rows)
    print(f"\n✅ Logs exported to {filename}")

# Menu interface
def menu():
    while True:
        print("\n Threat Monitor Menu:")
        print("1. Add new threat log")
        print("2. View logs")
        print("3. Export logs to CSV")
        print("4. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            ip = input("Enter IP address: ").strip()
            mac = input("Enter MAC address: ").strip()
            threat_type = input("Enter Threat Type: ").strip()
            description = input("Enter Description: ").strip()
            log_threat(ip, mac, threat_type, description)
        elif choice == "2":
            view_logs()
        elif choice == "3":
            export_to_csv()
        elif choice == "4":
            print("🚪 Exiting... Stay secure!")
            break
        else:
            print(" Invalid option. Please choose 1-4.")

# Entry point
if __name__ == "__main__":
    initialize_db()
    Thread(target=start_sniffer, daemon=True).start()
    menu()

