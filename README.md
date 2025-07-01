# Nmap Network Exploration Toolkit

A lightweight Flask‑based REST API and optional Streamlit dashboard that wrap the power of **Nmap** and **WHOIS** to provide script‑friendly, human‑readable network reconnaissance.

> **Why?**  Nmap’s console output is perfect for experts, but it is painful to parse and share.  Turning it into a JSON‑speaking micro‑service (plus a web UI) means you can drop the data straight into dashboards, SIEMs, or other automations.

---

## Features

| Capability            | Details |
|-----------------------|---------|
| **Subnet discovery**  | `POST /subnet_scan` pings every address in a CIDR block and returns live hosts. |
| **Deep host scan**    | `POST /ip_scan` runs `nmap -sV -O -p- -T4`, enriches each open port with plain‑language descriptions, performs WHOIS, and returns JSON. |
| **Traceroute support**| Optional `--traceroute` flag shows network path. |
| **Scriptable output** | Pure JSON results—ideal for pipelines and integrations. |
| **Zero‑install UI**   | `streamlit run app_streamlit.py` starts a dashboard for point‑and‑click scans. |
| **Extensible KB**     | 10 000+ TCP ports mapped to descriptions; override via `PORT_EXPLANATIONS` in `app.py`. |

---

## Architecture

```text
┌────────────┐     HTTP JSON      ┌────────────────┐
│  Frontend  │  ◄──────────────► │  Flask API     │
│ (Streamlit)│                   │  (app.py)      │
└────────────┘                    │                │
        ▲                         │  Nmap CLI      │
        │                         │  WHOIS CLI     │
        └────────── results ─────►│  Parser / Enr. │
                                  └────────────────┘
```

---

## Quick‑start

### 1. Prerequisites

| Software | Tested version | Debian/Ubuntu install |
|----------|----------------|-----------------------|
| Python   | 3.9 – 3.12     | `sudo apt install python3 python3-venv` |
| Nmap     | 7.94+          | `sudo apt install nmap` |
| WHOIS    | 5.5+           | `sudo apt install whois` |

### 2. Clone & set up a virtual env

```bash
git clone https://github.com/Ilhanemreadak/nmap_network_exploration_script.git
cd nmap_network_exploration_script
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # create the file if missing (see below)
```

If `requirements.txt` does not exist, create it with:

```text
Flask>=3.0
requests>=2.32
streamlit>=1.35
```

### 3. Run the backend

```bash
python app.py          # http://0.0.0.0:5000
```

### 4. (Optional) Launch the dashboard

```bash
streamlit run app_streamlit.py
```

Set a custom API URL for the dashboard:

```bash
export API_URL="http://api.example.com:5000"
```

---

## API Reference

### `POST /subnet_scan`

```jsonc
{
  "subnet": "192.168.1.0/24"
}
```

| Field | Type   | Required | Description               |
|-------|--------|----------|---------------------------|
| subnet| string | ✔        | CIDR notation or IP range |

**Response**

```jsonc
{
  "active_ips": ["192.168.1.15", "192.168.1.42"]
}
```

---

### `POST /ip_scan`

```jsonc
{
  "ip": "192.168.1.42",
  "options": {
    "scripts": ["vulners", "http-enum"],
    "pingless": true,
    "no_dns": true,
    "traceroute": false
  }
}
```

| Option      | Effect                 |
|-------------|------------------------|
| `scripts[]` | NSE scripts to run     |
| `pingless`  | Adds `-Pn`             |
| `no_dns`    | Adds `-n`              |
| `traceroute`| Adds `--traceroute`    |

**Response (truncated)**

```jsonc
{
  "ip": "192.168.1.42",
  "os_guess": "Linux 5.X",
  "device_type": "general purpose",
  "open_ports": [
    { "port": "22", "description": "SSH – Secure shell." },
    { "port": "80", "description": "HTTP – Web service." }
  ],
  "whois": "…",
  "traceroute": "",
  "scripts_output": { "vulners": "…" },
  "raw_report": "Starting Nmap 7.94 …"
}
```

---

## Deployment Notes

* **Root privileges** may be required for full port scans.  On Linux you can grant capabilities to Nmap instead of running as root:

  ```bash
  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
  ```

* Expose the API only on trusted networks or behind authentication—port scanning can be intrusive.

---

## Roadmap / TODO

- [ ] IPv6 support
- [ ] Dockerfile & CI workflow
- [ ] Unit tests with `pytest`
- [ ] Persist scan history to SQLite/PostgreSQL
- [ ] CSV/HTML export

---

## Contributing

1. Fork → Branch → PR.
2. Follow **PEP 8**; run `ruff`/`flake8` before pushing.
3. Explain **what** and **why** in the PR description.

---

## License

This project is distributed under the **MIT License**.  See [`LICENSE`](LICENSE).

---

## Acknowledgements

* [Nmap](https://nmap.org/) – the de‑facto standard network scanner.
* Inspired by countless one‑off scripts on the Nmap mailing list—now wrapped in a clean API.
