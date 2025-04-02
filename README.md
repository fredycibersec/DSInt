# DSInt - Domain & Subdomain Intelligence Tool

<div align="center">
  
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
[![GitHub issues](https://img.shields.io/github/issues/fredycibersec/DSInt.svg)](https://github.com/fredycibersec/DSInt/issues)
[![GitHub stars](https://img.shields.io/github/stars/fredycibersec/DSInt.svg)](https://github.com/fredycibersec/DSInt/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/fredycibersec/DSInt.svg)](https://github.com/fredycibersec/DSInt/network)

</div>

<p align="center">
  <img src="https://github.com/fredycibersec/DSInt/blob/main/DSInt_Tool_logo.png" alt="DSInt Logo" width="150"/>
</p>

## 🌐 Overview

DSInt is a comprehensive reconnaissance tool for domain intelligence gathering and subdomain enumeration. It combines the power of multiple tools (Amass, Subfinder, DNSenum, Sublist3r, and MassDNS) to discover and validate subdomains, map IP addresses, and provide detailed reports.

This tool is designed to help security professionals, bug bounty hunters, and penetration testers streamline their reconnaissance process with a unified command-line interface for various subdomain discovery techniques.
## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
  - [Prerequisites](#prerequisites)
  - [Setup](#setup)
- [Usage](#-usage)
  - [Basic Usage](#basic-usage)
  - [Advanced Options](#advanced-options)
- [Output Files](#-output-files)
- [Screenshots](#-screenshots)
- [License](#-license)
- [Contributing](#-contributing)
- [Acknowledgements](#-acknowledgements)
- [Disclaimer](#-disclaimer)

## ✨ Features

- **Multiple Discovery Methods**: Combines results from Amass, Subfinder, DNSenum, and Sublist3r
- **MassDNS Integration**: Validates subdomains through DNS resolution
- **Dictionary-based Discovery**: Includes bruteforce subdomain discovery with custom wordlists
- **IP Mapping**: Maps discovered subdomains to their IP addresses
- **Recursive Enumeration**: Option to recursively enumerate discovered subdomains
- **Structured Output**: Generates organized, readable reports
- **Rich Visualizations**: Beautiful terminal output with progress indicators
- **Flexible Verbosity**: Control the amount of output detail
- **Email Security Analysis**: Checks for SPF, DKIM, and DMARC records to evaluate email spoofing protection


## 🔧 Installation

### Prerequisites

- Python 3.6 or higher
- The following tools installed and in your PATH:
  - [Amass](https://github.com/OWASP/Amass) - Install using instructions from their GitHub repository
  - [Subfinder](https://github.com/projectdiscovery/subfinder) - Install using instructions from their GitHub repository
  - [DNSenum](https://github.com/fwaeytens/dnsenum) - Available in Kali Linux or install manually
  - [Sublist3r](https://github.com/aboul3la/Sublist3r) - `pip install git+https://github.com/aboul3la/Sublist3r.git`
  - [MassDNS](https://github.com/blechschmidt/massdns) - Clone and compile from source

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/fredycibersec/DSInt.git
   cd DSInt
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Verify installation:
   ```bash
   python domain_recon.py --version
   ```

The `requirements.txt` file includes:
- rich==13.4.2 - For beautiful terminal output
- requests==2.31.0 - For HTTP requests
- dnspython==2.3.0 - For DNS operations


## 🚀 Usage

### Basic Usage

```bash
python domain_recon.py example.com
```

This will:
1. Run all configured subdomain discovery tools
2. Validate discovered subdomains with MassDNS
3. Map IP addresses to discovered subdomains
4. Generate reports in the `results/example.com_TIMESTAMP/` directory

### Advanced Options

```bash
# Run with increased verbosity
python3 domain_recon.py example.com -v

# Run with minimal output
python3 domain_recon.py example.com -q

# Specify IP address mode (for IP reconnaissance)
python3 domain_recon.py 192.168.1.1 --ip

# Enable recursive enumeration (enumerate discovered subdomains)
python3 domain_recon.py example.com --recursive

# Skip MassDNS verification stage
python3 domain_recon.py example.com --no-massdns

# Use custom output directory
python3 domain_recon.py example.com --output-dir custom_folder

# Use custom wordlist for dictionary-based discovery
python3 domain_recon.py example.com --wordlist path/to/wordlist.txt

# Skip dictionary-based subdomain discovery
python3 domain_recon.py example.com --skip-wordlist

# Run only specific tools
python3 domain_recon.py example.com --tools amass,subfinder

# Check email security records (SPF, DKIM, DMARC)
python3 domain_recon.py example.com --check-email-security

# Export results to specific formats
python3 domain_recon.py example.com --export json,csv
```


## 📁 Output Files

Results are saved in the `results/[domain]_[timestamp]/` directory:

| File | Description |
|------|-------------|
| `[domain]_subdomains.txt` | Complete list of all discovered subdomains |
| `[domain]_results.json` | Detailed JSON results including tool-specific findings and email security analysis (when enabled) |
| `[domain]_summary.txt` | Human-readable summary of findings including email security analysis (when enabled) |
| `[domain]_ip_mapping.json` | JSON mapping of IPs to associated domains |
| `[domain]_ip_mapping.txt` | Human-readable IP to domain mapping |

Sample output:
```
results/example.com_20230621_120145/
├── example.com_subdomains.txt
├── example.com_results.json
├── example.com_summary.txt
├── example.com_ip_mapping.json
└── example.com_ip_mapping.txt
```

## 📸 Screenshots

<p align="center">
  <img src="https://github.com/fredycibersec/DSInt/blob/main/DSint_1.png" alt="DSInt Terminal Output"/>
  <img src="https://github.com/fredycibersec/DSInt/blob/main/DSint_2.png" alt="DSInt Terminal Output"/>
  <br>
  <em>DSInt in action showing subdomain discovery process</em>
</p>


## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Here's how you can contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure to update tests as appropriate and follow the code style guidelines.

## 🙏 Acknowledgements

- The developers of Amass, Subfinder, DNSenum, Sublist3r, and MassDNS
- The Rich library for beautiful terminal output
- All open-source contributors who make tools like this possible

## ⚠️ Disclaimer

This tool is provided for educational and legal security assessment purposes only. Always obtain proper authorization before conducting security testing against any domain or system.

**Misuse of this tool can lead to legal consequences. The authors and contributors are not responsible for any misuse or damage caused by this program.**

## 🔗 Related Projects

- [Amass](https://github.com/OWASP/Amass) - In-depth Attack Surface Mapping and Asset Discovery
- [Subfinder](https://github.com/projectdiscovery/subfinder) - A subdomain discovery tool
- [MassDNS](https://github.com/blechschmidt/massdns) - A high-performance DNS stub resolver

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/fredycibersec">SaruMan</a>
</p>

