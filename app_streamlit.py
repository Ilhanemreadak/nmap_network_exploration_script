import streamlit as st
import requests

API_URL = "http://localhost:5000"

st.set_page_config(page_title="Nmap Arayüzü", layout="wide")
st.title("Nmap Tabanlı Ağ Tarayıcı")

subnet = st.text_input("Subnet yada ip adresi giriniz (ör. 192.168.1.0/24 veya 8.8.8.8):", "192.168.1.0/24")

if st.button("Subnet Taraması Başlat"):
    res = requests.post(f"{API_URL}/subnet_scan", json={"subnet": subnet})
    data = res.json()
    st.session_state["active_ips"] = data.get("active_ips", [])

if "active_ips" in st.session_state:
    selected_ip = st.selectbox("IP Seçiniz:", st.session_state["active_ips"])
    scripts = st.multiselect("NSE Script Seç", ["vulners", "ftp-anon", "http-enum"])
    os_detect = st.checkbox("OS Tespiti")
    pingless = st.checkbox("Ping Atma (-Pn)")
    no_dns = st.checkbox("DNS Çözümleme Yapma (-n)")
    traceroute = st.checkbox("Traceroute Yap (--traceroute)")

    if st.button("Seçilen IP'yi Tara"):
        payload = {
            "ip": selected_ip,
            "options": {
                "scripts": scripts,
                "os_detect": os_detect,
                "pingless": pingless,
                "no_dns": no_dns,
                "traceroute": traceroute
            }
        }
        res = requests.post(f"{API_URL}/ip_scan", json=payload)
        data = res.json()

        st.subheader("Genel Bilgi")
        st.write("IP:", data["ip"])
        st.write("OS Tahmini:", data["os_guess"])
        st.write("Cihaz Tipi:", data["device_type"])

        st.subheader("Açık Portlar")
        for p in data["open_ports"]:
            st.write(f"{p['port']} - {p['description']}")

        st.subheader("WHOIS Bilgisi")
        st.code(data["whois"])

        if traceroute and data["traceroute"]:
            st.subheader("Traceroute")
            st.code(data["traceroute"])

        if data["scripts_output"]:
            st.subheader("Script Çıktıları")
            for script, content in data["scripts_output"].items():
                st.markdown(f"**{script}**")
                st.code(content)
