# 👻 Ghost-Dir

<div align="center">

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗      ██████╗ ██╗██████╗          ║
║  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝      ██╔══██╗██║██╔══██╗         ║
║  ██║  ███╗███████║██║   ██║███████╗   ██║   █████╗██║  ██║██║██████╔╝         ║
║  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ╚════╝██║  ██║██║██╔══██╗         ║
║  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║         ██████╔╝██║██║  ██║         ║
║   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝         ╚═════╝ ╚═╝╚═╝  ╚═╝         ║
║                                                                               ║
║                    Web Directory & File Fuzzer Tool                           ║
║                              by egnake                                        ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

**Fast, powerful, and flexible web directory fuzzing tool**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-red.svg)](https://github.com/egnake/ghost-dir)
[![Author](https://img.shields.io/badge/Author-egnake-purple.svg)](https://github.com/egnake)

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Examples](#-examples) • [License](#-license)

</div>

---

## 🚀 Features

### Core Features
- 🔥 **Multi-threading** - Blazing fast with 50+ concurrent threads
- 📁 **Extension Fuzzing** - Automatically append extensions (.php, .html, .bak, etc.)
- 🔍 **Recursive Scanning** - Automatically scan discovered directories
- 🎯 **Status Code Filtering** - Filter by HTTP status codes
- 📊 **Response Size Filtering** - Filter by response content length

### Advanced Features
- 🌐 **Proxy Support** - Burp Suite, OWASP ZAP integration
- 🔐 **Authentication** - Basic/Digest auth support
- 🍪 **Cookie Support** - Session cookies for authenticated scanning
- 🎭 **Random User-Agent** - Evade detection with rotating User-Agents
- ⏱️ **Rate Limiting** - Delay between requests to avoid blocking

### Output Options
- 📝 **Multiple Formats** - TXT, JSON, CSV output
- 🎨 **Rich CLI** - Beautiful colorized terminal output
- 📈 **Statistics** - Detailed scan statistics and summary

---

## 📦 Installation

### Requirements
- Python 3.8+
- pip

### Quick Install

```bash
# Clone the repository
git clone https://github.com/egnake/ghost-dir.git
cd ghost-dir

# Install dependencies
pip install -r requirements.txt
```

### Dependencies
```
requests>=2.28.0
rich>=13.0.0
colorama>=0.4.6
urllib3>=2.0.0
```

---

## 🎯 Usage

### Basic Usage

```bash
# Simple scan
python ghost_dir.py -u https://target.com -w wordlists/common.txt

# Scan with extensions
python ghost_dir.py -u https://target.com -w wordlists/common.txt -x php,html,txt,bak

# Fast scan with 50 threads
python ghost_dir.py -u https://target.com -w wordlists/common.txt -t 50
```

### Advanced Usage

```bash
# Recursive scanning (depth: 3)
python ghost_dir.py -u https://target.com -w wordlists/common.txt -r --recursive-depth 3

# Through proxy (Burp Suite)
python ghost_dir.py -u https://target.com -w wordlists/common.txt --proxy http://127.0.0.1:8080

# JSON output
python ghost_dir.py -u https://target.com -w wordlists/common.txt -o results.json --format json

# With cookies
python ghost_dir.py -u https://target.com -w wordlists/common.txt --cookies "session=abc123; token=xyz"

# With basic auth
python ghost_dir.py -u https://target.com -w wordlists/common.txt --auth admin:password

# Filter by response size
python ghost_dir.py -u https://target.com -w wordlists/common.txt --min-length 100 --exclude-length 1234

# Skip SSL verification
python ghost_dir.py -u https://target.com -w wordlists/common.txt -k
```

### Custom Headers

```bash
# Single header
python ghost_dir.py -u https://target.com -w wordlists/common.txt -H "Authorization: Bearer token123"

# Multiple headers
python ghost_dir.py -u https://target.com -w wordlists/common.txt -H "X-Api-Key: key" -H "X-Custom: value"
```

---

## 📖 Parameters

### Target Options
| Parameter | Description |
|-----------|-------------|
| `-u, --url` | Target URL (required) |
| `-w, --wordlist` | Wordlist file path (required) |

### Scan Options
| Parameter | Default | Description |
|-----------|---------|-------------|
| `-t, --threads` | 10 | Number of concurrent threads |
| `-x, --extensions` | - | File extensions to append |
| `-s, --status-codes` | 200,201,... | Status codes to show |
| `-e, --exclude-codes` | - | Status codes to exclude |
| `--timeout` | 10 | Request timeout (seconds) |
| `--delay` | 0 | Delay between requests |
| `-r, --recursive` | False | Enable recursive scanning |
| `--recursive-depth` | 2 | Maximum recursion depth |

### Filtering Options
| Parameter | Description |
|-----------|-------------|
| `--min-length` | Minimum response length |
| `--max-length` | Maximum response length |
| `--exclude-length` | Exclude specific lengths |
| `--match-string` | Match string in response |
| `--exclude-string` | Exclude if string found |

### HTTP Options
| Parameter | Description |
|-----------|-------------|
| `--proxy` | Proxy URL |
| `--cookies` | Cookie string |
| `-H, --header` | Custom header (repeatable) |
| `-A, --user-agent` | Custom User-Agent |
| `--random-agent` | Use random User-Agent |
| `-L, --follow-redirects` | Follow HTTP redirects |
| `-k, --insecure` | Skip SSL verification |
| `--auth` | Basic auth (user:pass) |

### Output Options
| Parameter | Default | Description |
|-----------|---------|-------------|
| `-o, --output` | - | Output file path |
| `--format` | txt | Output format (txt/json/csv) |
| `-q, --quiet` | False | Quiet mode |
| `--no-color` | False | Disable colored output |

---

## 📂 Included Wordlists

| File | Description | Entries |
|------|-------------|---------|
| `wordlists/common.txt` | Common directories and files | 150+ |
| `wordlists/backup.txt` | Backup file patterns | 100+ |
| `wordlists/admin.txt` | Admin panel paths | 130+ |

### Recommended External Wordlists

- [SecLists](https://github.com/danielmiessler/SecLists) - Ultimate collection
- [dirbuster-lists](https://github.com/daviddias/node-dirbuster/tree/master/lists)
- [fuzzdb](https://github.com/fuzzdb-project/fuzzdb)

---

## 🎨 Example Output

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗      ██████╗ ██╗██████╗          ║
║  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝      ██╔══██╗██║██╔══██╗         ║
║  ██║  ███╗███████║██║   ██║███████╗   ██║   █████╗██║  ██║██║██████╔╝         ║
║                         Author: egnake | v1.0.0                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

[*] Target URL     : https://target.com
[*] Wordlist       : wordlists/common.txt
[*] Threads        : 50
[*] Extensions     : php, html, txt

[+] Target accessible: https://target.com (Status: 200)
[*] Wordlist loaded: 150 words
[*] Starting scan...

/admin (Status: 301 | Size: 162 | Time: 0.12s) -> https://target.com/admin/
/backup (Status: 403 | Size: 280 | Time: 0.08s)
/config.php (Status: 200 | Size: 0 | Time: 0.15s)
/login (Status: 200 | Size: 4521 | Time: 0.10s)

═══════════════════════════════════════════════════════════════════════════════
                           SCAN SUMMARY
═══════════════════════════════════════════════════════════════════════════════
[*] Total Requests   : 450
[*] Found            : 4
[*] Errors           : 2
[*] Elapsed Time     : 3.45 seconds
[*] Requests/Second  : 130.43
═══════════════════════════════════════════════════════════════════════════════
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **legal and ethical use only**:

- ✅ Security testing on your own systems
- ✅ Authorized penetration testing
- ✅ Bug bounty programs with permission
- ❌ Unauthorized access to systems

**The user is solely responsible for any misuse of this tool.**

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 👤 Author

**egnake**

- GitHub: [@egnake](https://github.com/egnake)

---

## ⭐ Support

If you find this tool useful, please consider giving it a star on GitHub!

---

<div align="center">
  <b>Made with by egnake</b>
  <br><br>
  <a href="https://github.com/egnake/ghost-dir">
    <img src="https://img.shields.io/github/stars/egnake/ghost-dir?style=social" alt="GitHub Stars">
  </a>
</div>
