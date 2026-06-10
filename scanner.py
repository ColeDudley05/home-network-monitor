
import nmap
import psycopg2

DB_NAME = "security_monitor"
DB_USER = "secmon"
DB_PASS = "Hockeypro52372!"
DB_HOST = "localhost"

scanner = nmap.PortScanner()

print("Scanning Network...")
scanner.scan("10.0.0.0/24", arguments="-sn")

conn = psycopg2.connect(
	dbname=DB_NAME,
	user=DB_USER,
	password=DB_PASS,
	host=DB_HOST,
)

cur = conn.cursor()

for host in scanner.all_hosts():
	hostname = scanner[host].hostname() or "Unknown"
	mac = scanner[host].get("addresses", {}).get("mac","Unknown")

	vendor_data = scanner[host].get("vendor", {})
	vendor = list(vendor_data.values())[0] if vendor_data else "Unknown"

	cur.execute("""
		Insert INTO devices (ip, hostname, mac, vendor)
		VALUES (%s, %s, %s, %s)
		ON CONFLICT (ip)
		DO UPDATE SET
			hostname = EXCLUDED.hostname,
			mac = EXCLUDED.mac,
			vendor = EXCLUDED.vendor,
			last_seen = CURRENT_TIMESTAMP;
		""", (host, hostname, mac, vendor))

	print(f"Saved: {host} {hostname}")

conn.commit()
cur.close()
conn.close()

print("Scan complete")
