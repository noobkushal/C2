import time
import sys
from src.ingestion.realworld_sniffer import realworld_sniffer_engine, list_active_interfaces
from src.services.auth_service import authenticate_user
from src.services.admin_permission_service import grant_admin_permission

print("Testing physical NIC live packet sniffer...")
ifaces = list_active_interfaces()
print(f"Detected physical network interfaces: {ifaces[:5]}... (total {len(ifaces)})")

admin_user = authenticate_user("admin", "Admin@123")
if not admin_user:
    print("Authentication failed.")
    sys.exit(1)

grant_admin_permission(admin_user=admin_user["username"])
print("Admin consent granted for testing.")

def on_packet(evt):
    print(f"  [LIVE PACKET CAPTURED] {evt.timestamp} | {evt.source_ip}:{getattr(evt, 'source_port', '')} -> {evt.destination_ip}:{getattr(evt, 'destination_port', '')} ({evt.protocol})")

realworld_sniffer_engine.callback_fn = on_packet

selected_iface = ifaces[0] if ifaces else None
print(f"Starting sniffer on interface: {selected_iface}...")
realworld_sniffer_engine.start_sniffing(interface=selected_iface, user_obj=admin_user)

time.sleep(5)

realworld_sniffer_engine.stop_sniffing()
print(f"Total live packets captured in 5 seconds: {realworld_sniffer_engine.packets_captured_count}")
