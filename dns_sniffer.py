from scapy.sendrecv import sniff
from scapy.layers.inet import IP
from scapy.layers.dns import DNS, DNSQR
from firebase_admin import credentials, initialize_app, db
import datetime

# Initialize Firebase Admin SDK
cred = credentials.Certificate('goldenshield-01-firebase-adminsdk-fbsvc-cc0ff4e580.json')
initialize_app(cred, {
    'databaseURL': "https://goldenshield-01-default-rtdb.asia-southeast1.firebasedatabase.app"
})


def process_packet(packet):
    if packet.haslayer(DNSQR):  # DNS Query Record
        domain = packet[DNSQR].qname.decode('utf-8')
        ip = packet[IP].src

        # Lookup user from Firebase
        users_ref = db.reference('users')
        users_data = users_ref.get()

        full_name = 'Unknown'
        if users_data:
            for user_id, user in users_data.items():
                if user.get('ip_address') == ip:
                    full_name = user.get('full_name', 'Unknown')
                    break

        log_ref = db.reference('website_logs')
        log_ref.push({
            'user': full_name,
            'ip': ip,
            'domain': domain,
            'timestamp': datetime.datetime.now().isoformat(),
            'action': 'Visited',
            'status': 'Allowed'
        })


print("Starting DNS Sniffer... (Run as root/admin!)")
sniff(filter='udp port 53', prn=process_packet, store=0)
