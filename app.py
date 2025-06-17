from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

# Tüm port açıklamaları — örnekle + otomatik doldurma
PORT_EXPLANATIONS = {
    "20": "FTP data portu.",
    "21": "FTP kontrol portu.",
    "22": "SSH - Güvenli uzak bağlantı.",
    "23": "Telnet - Eski uzak bağlantı protokolü.",
    "25": "SMTP - E-posta gönderim protokolü.",
    "53": "DNS - Alan adı çözümlemesi.",
    "67": "DHCP sunucu portu.",
    "68": "DHCP istemci portu.",
    "69": "TFTP - Basit dosya aktarım protokolü.",
    "80": "HTTP - Web servisi.",
    "110": "POP3 - E-posta alma protokolü.",
    "123": "NTP - Zaman senkronizasyonu.",
    "135": "MS RPC - Microsoft RPC servisi.",
    "137": "NetBIOS Name Service.",
    "138": "NetBIOS Datagram Service.",
    "139": "NetBIOS Session Service.",
    "143": "IMAP - E-posta alma protokolü.",
    "161": "SNMP - Ağ yönetimi protokolü.",
    "179": "BGP - Yönlendirme protokolü.",
    "389": "LDAP - Dizin hizmeti.",
    "443": "HTTPS - Güvenli web servisi.",
    "445": "SMB - Dosya paylaşımı protokolü.",
    "465": "SMTPS - Güvenli SMTP.",
    "500": "IKE - VPN tünel açma protokolü.",
    "514": "Syslog.",
    "520": "RIP - Routing Information Protocol.",
    "587": "SMTP Submission.",
    "631": "IPP - Yazıcı protokolü.",
    "636": "LDAPS - Güvenli LDAP.",
    "873": "rsync - Dosya senkronizasyonu.",
    "902": "VMware sunucu servisi.",
    "993": "IMAPS - Güvenli IMAP.",
    "995": "POP3S - Güvenli POP3.",
    "1025": "MS RPC Dinamik port.",
    "1080": "SOCKS proxy.",
    "1433": "Microsoft SQL Server.",
    "1521": "Oracle veritabanı.",
    "1723": "PPTP VPN.",
    "2049": "NFS - Ağ dosya sistemi.",
    "3306": "MySQL veritabanı.",
    "3389": "RDP - Uzak masaüstü.",
    "5432": "PostgreSQL veritabanı.",
    "5900": "VNC - Uzak masaüstü görüntüsü.",
    "6000": "X11 - Grafik arayüz servisi.",
    "8080": "HTTP alternatif port.",
    "8443": "HTTPS alternatif port.",
    "8888": "Jupyter Notebook, web paneli."
}

for i in range(1, 10001):
    key = str(i)
    if key not in PORT_EXPLANATIONS:
        PORT_EXPLANATIONS[key] = "Port açıklaması bulunamadı."

def find_active_ips(subnet):
    result = subprocess.run(["nmap", "-sn", "-T4", subnet], stdout=subprocess.PIPE, text=True)
    lines = result.stdout.splitlines()
    active_ips = []
    current_ip = None
    for line in lines:
        if line.startswith("Nmap scan report for"):
            ip_raw = line.split()[-1]
            current_ip = ip_raw.strip("()")
        elif "Host is up" in line and current_ip:
            active_ips.append(current_ip)
            current_ip = None
    return active_ips

def scan_ip(ip, options):
    ip = ip.strip("() \n")
    cmd = ["nmap", "-sV", "-O", "-p-", "-T4"]
    if options.get("scripts"):
        for s in options["scripts"]:
            cmd.extend(["--script", s])
    if options.get("pingless"):
        cmd.append("-Pn")
    if options.get("no_dns"):
        cmd.append("-n")
    if options.get("traceroute"):
        cmd.append("--traceroute")
    cmd.append(ip)
    result = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
    return result.stdout

def whois_lookup(ip):
    ip = ip.strip("() \n")
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("172.31."):
        return "Bu bir private IP adresidir, WHOIS sonucu yoktur."
    result = subprocess.run(["whois", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout

def parse_scan_info(report):
    os_guess = "Bilinmiyor"
    device_type = "Bilinmiyor"
    open_ports = []
    traceroute = ""
    scripts_output = {}

    lines = report.splitlines()
    in_traceroute = False
    in_script = False
    current_script = ""
    script_content = ""

    for line in lines:
        line = line.strip()
        if line.startswith("OS details:"):
            os_guess = line.replace("OS details:", "").strip()
        elif line.startswith("Running (JUST GUESSING):"):
            os_guess = line.replace("Running (JUST GUESSING):", "").strip()
        elif line.startswith("Running:") and os_guess == "Bilinmiyor":
            os_guess = line.replace("Running:", "").strip()
        elif "Service Info:" in line and os_guess == "Bilinmiyor":
            parts = line.split("OS:")
            if len(parts) > 1:
                os_guess = parts[1].split(";")[0].strip()

        if line.startswith("Device type:"):
            device_type = line.replace("Device type:", "").strip()

        if "/tcp" in line and "open" in line:
            port = line.split("/")[0].strip()
            description = PORT_EXPLANATIONS.get(port, "Port açıklaması yok.")
            open_ports.append({"port": port, "description": description})

        if line.startswith("TRACEROUTE"):
            in_traceroute = True
            traceroute += line + "\n"
        elif in_traceroute:
            if line == "" or line.startswith("Nmap done:"):
                in_traceroute = False
            else:
                traceroute += line + "\n"

        if line.startswith("|"):
            if not in_script:
                in_script = True
                current_script = "Script Çıktısı"
                script_content = ""
            script_content += line + "\n"
        elif in_script:
            if not line.startswith("|"):
                if current_script not in scripts_output:
                    scripts_output[current_script] = ""
                scripts_output[current_script] += script_content
                in_script = False
                current_script = ""
                script_content = ""
        if line.startswith("|_"):
            if not in_script:
                in_script = True
                current_script = "Script Çıktısı"
                script_content = ""
            script_content += line + "\n"

    return os_guess, device_type, open_ports, traceroute.strip(), scripts_output

@app.route("/subnet_scan", methods=["POST"])
def subnet_scan():
    try:
        data = request.json
        subnet = data.get("subnet")
        if not subnet:
            return jsonify({"error": "Subnet belirtilmedi"}), 400
        ips = find_active_ips(subnet)
        return jsonify({"active_ips": ips})
    except Exception as e:
        return jsonify({"error": f"Subnet tarama hatası: {str(e)}"}), 500

@app.route("/ip_scan", methods=["POST"])
def ip_scan():
    try:
        data = request.json
        ip = data.get("ip")
        options = data.get("options", {})
        if not ip:
            return jsonify({"error": "IP belirtilmedi"}), 400
        report = scan_ip(ip, options)
        os_guess, device_type, open_ports, traceroute, scripts_output = parse_scan_info(report)
        whois_info = whois_lookup(ip)
        return jsonify({
            "ip": ip,
            "os_guess": os_guess,
            "device_type": device_type,
            "open_ports": open_ports,
            "whois": whois_info,
            "traceroute": traceroute,
            "scripts_output": scripts_output,
            "raw_report": report
        })
    except Exception as e:
        return jsonify({"error": f"IP tarama hatası: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
