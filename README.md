<p align="center">
<img src="https://www.rbcafe.com/wp-content/uploads/host3r_python_script.png" alt="HOST3R" width="420">
</p>

<h1 align="center">HOST3R</h1>

<p align="center">
Subdomain enumeration — hosts file generator
</p>

<p align="center">
<a href="https://www.rbcafe.com/software/host3r/">rbcafe.com</a> · Python 3 · GNU GPL
</p>

---

## What it does

HOST3R enumerates subdomains of a target domain by querying multiple public sources simultaneously, then formats the results as `/etc/hosts` entries ready to paste or save.

**Sources queried in parallel :**
Google · Yahoo · Bing · Baidu · Ask · Netcraft · DNSdumpster · VirusTotal · ThreatCrowd · crt.sh (CT logs) · PassiveDNS

**Output :**
```
127.0.0.1  mail.example.com
127.0.0.1  dev.example.com
127.0.0.1  api.example.com

::1  mail.example.com   # with -6
```

---

## Install

```bash
git clone https://github.com/Rbcafe/HOST3R
cd HOST3R
pip install -r install/requirements.txt
chmod +x app.sh
```

**Requires Python 3.9+**

---

## Usage

```bash
./app.sh -d <domain> [options]
```

| Flag | Long | Description |
|------|------|-------------|
| `-d` | `--domain`    | Target domain (required) |
| `-o` | `--output`    | Save results to file |
| `-v` | `--verbose`   | Show each subdomain as found |
| `-e` | `--exception` | Print engine errors |
| `-6` | `--ipv6`      | Also output `::1` entries |
| `-h` | `--help`      | Show help |

### Examples

```bash
# Basic enumeration
./app.sh -d example.com

# Verbose + export
./app.sh -d example.com -v -o /tmp/example.hosts

# Full — verbose, exceptions, IPv4 + IPv6, export
./app.sh -d example.com -v -e -6 -o /tmp/example.hosts
```

**Paste results directly into `/etc/hosts` to block all subdomains at the system level.**

---

## Project structure

```
HOST3R/
├── app.sh              — entry point
├── app/
│   └── host3r.py       — engine
├── tests/              — pytest suite (151 tests)
├── install/
│   ├── requirements.txt
│   └── requirements.lock
└── documentations/
    └── LICENSE
```

---

## License

GNU GPL — see [documentations/LICENSE](documentations/LICENSE)
