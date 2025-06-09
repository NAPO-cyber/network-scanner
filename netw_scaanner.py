import socket
from tkinter import *
from tkinter import messagebox, filedialog, ttk
import threading
from scapy.all import ARP, Ether, srp
from getmac import get_mac_address
from mac_vendor_lookup import MacLookup

# Initialize MAC vendor lookup
mac_lookup = MacLookup()
mac_lookup.update_vendors()

# Scan network
def scan_network(ip_range):
    live_hosts = []
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=0)[0]
    for sent, received in result:
        try:
            vendor = mac_lookup.lookup(received.hwsrc)
        except:
            vendor = "Unknown"
        live_hosts.append({'ip': received.psrc, 'mac': received.hwsrc, 'vendor': vendor})
    return live_hosts

# Scan ports
def scan_ports(ip, ports=[21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]):
    open_ports = []
    services = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                try:
                    sock.send(b"Hello\r\n")
                    banner = sock.recv(1024).decode().strip()
                    services[port] = banner if banner else "Unknown Service"
                except:
                    services[port] = "Unknown Service"
            sock.close()
        except:
            continue
    return open_ports, services

# Vulnerability checker
def check_vulnerabilities(ports):
    vulns = {
        21: "FTP - Unencrypted login",
        23: "Telnet - Unencrypted and outdated",
        80: "HTTP - Use HTTPS instead",
        139: "NetBIOS - Can be vulnerable",
        445: "SMB - Target for ransomware"
    }
    return [vulns[p] for p in ports if p in vulns]

# Start scan
def start_scan():
    ip_range = ip_range_entry.get()
    if not ip_range:
        messagebox.showerror("Error", "Please enter IP Range.")
        return

    result_text.delete(1.0, END)
    status_label.config(text="Scanning... Please wait.")
    scan_button.config(state=DISABLED)

    def scan():
        devices = scan_network(ip_range)
        summary = {'total': len(devices), 'vulnerable': 0, 'total_ports': 0}

        for device in devices:
            ip = device['ip']
            mac = device['mac']
            vendor = device['vendor']
            result_text.insert(END, f"\n📡 Device Found:\nIP: {ip}\nMAC: {mac} ({vendor})\n")

            open_ports, services = scan_ports(ip)
            summary['total_ports'] += len(open_ports)
            result_text.insert(END, f"Open Ports: {open_ports}\n")

            for port, banner in services.items():
                result_text.insert(END, f" ↪ Port {port}: {banner}\n")

            vulns = check_vulnerabilities(open_ports)
            if vulns:
                summary['vulnerable'] += 1
                result_text.insert(END, f"⚠️ Vulnerabilities:\n")
                for v in vulns:
                    result_text.insert(END, f" - {v}\n")
            else:
                result_text.insert(END, f"No common vulnerabilities detected.\n")

        result_text.insert(END, f"\n✅ Scan Completed.\n")
        result_text.insert(END, f"\n📊 Summary:\n - Devices Found: {summary['total']}\n - Vulnerable Devices: {summary['vulnerable']}\n - Total Open Ports: {summary['total_ports']}\n")
        status_label.config(text="Scan Complete.")
        scan_button.config(state=NORMAL)

    threading.Thread(target=scan).start()

# Save scan results
def save_results():
    text = result_text.get(1.0, END)
    if not text.strip():
        messagebox.showwarning("Warning", "No scan results to save.")
        return
    file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file:
        with open(file, "w") as f:
            f.write(text)
        messagebox.showinfo("Saved", f"Results saved to {file}")

# Clear results
def clear_results():
    result_text.delete(1.0, END)
    status_label.config(text="")

# GUI setup
app = Tk()
app.title("🛡️ Advanced Python Network Scanner")
app.geometry("850x700")
app.config(bg="#f0f2f5")
app.resizable(False, False)

title = Label(app, text="Advanced Network Scanner", font=("Segoe UI", 18, "bold"), bg="#f0f2f5", fg="#333")
title.pack(pady=10)

frame = Frame(app, bg="#f0f2f5")
frame.pack(pady=10)

Label(frame, text="IP Range (e.g. 192.168.1.1/24):", font=("Segoe UI", 11), bg="#f0f2f5").grid(row=0, column=0, padx=5, pady=5)

ip_range_entry = Entry(frame, width=35, font=("Segoe UI", 11))
ip_range_entry.grid(row=0, column=1, padx=5, pady=5)

scan_button = Button(frame, text="Start Scan", command=start_scan, bg="#4CAF50", fg="white", font=("Segoe UI", 10), width=12)
scan_button.grid(row=0, column=2, padx=5)

save_button = Button(frame, text="Save Results", command=save_results, bg="#2196F3", fg="white", font=("Segoe UI", 10), width=12)
save_button.grid(row=0, column=3, padx=5)

clear_button = Button(frame, text="Clear Results", command=clear_results, bg="#f44336", fg="white", font=("Segoe UI", 10), width=12)
clear_button.grid(row=0, column=4, padx=5)

# Scrollable results box
text_frame = Frame(app)
text_frame.pack(pady=10)

scrollbar = Scrollbar(text_frame)
scrollbar.pack(side=RIGHT, fill=Y)

result_text = Text(text_frame, wrap=WORD, yscrollcommand=scrollbar.set, font=("Consolas", 10), width=100, height=30)
result_text.pack()
scrollbar.config(command=result_text.yview)

status_label = Label(app, text="", font=("Segoe UI", 10), bg="#f0f2f5", fg="gray")
status_label.pack(pady=5)

app.mainloop()
