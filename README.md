# XSSDynaGen 🪄

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![GitHub Issues](https://img.shields.io/github/issues/Cybersecurity-Ethical-Hacker/xssdynagen.svg)](https://github.com/Cybersecurity-Ethical-Hacker/xssdynagen/issues)
[![GitHub Stars](https://img.shields.io/github/stars/Cybersecurity-Ethical-Hacker/xssdynagen.svg)](https://github.com/Cybersecurity-Ethical-Hacker/xssdynagen/stargazers)
[![Contributions Welcome](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)](CONTRIBUTING.md)

🪄 XSSDynaGen is a tool designed to analyze URLs with parameters, identify the characters allowed by the server, and generate advanced XSS payloads based on the analysis results. It utilizes fast and modern technologies like AsyncIO and aiohttp for high-speed scanning and payload generation.

## 📸 Screenshot:
![xssdynagen](https://github.com/user-attachments/assets/a53b5788-10cf-40c1-a34b-0a85e21112c3)

## 🌟 Features

- **⚡ Asynchronous Processing**: **AsyncIO** and **aiohttp** for high-performance concurrent scanning.
- **🔍 Parameter Character Analysis**: Tests allowed and blocked characters for each parameter.
- **💣 Dynamic Payload Generation**: Produces tailored XSS payloads based on server allowed characters.
- **🗂️ Customizable Character Sets**: Load and define your own custom character groups for tailored payload generation.
- **🛡️ Advanced Evasion**: Generates payloads with techniques like null bytes, Unicode encoding, and obfuscation.
- **📦 Batch Processing**: Efficient handling of large URL lists with configurable batch sizes and connection limits.
- **📝 Organized Output**: Saves generated payloads to structured files for easy use.
- **⚙️ Customizable**: Adjustable timeout, concurrency, and output settings.
- **🔄 Auto-Updater**: Check for and apply the latest updates seamlessly via Git integration.

## 📥 Kali Linux Installation - (Recommended)

**Clone the repository:**

   ```bash
   git clone https://github.com/Cybersecurity-Ethical-Hacker/xssdynagen.git
   cd xssdynagen
   ```

**Kali Linux already includes the following dependencies by default. However, if needed, you can install the required dependencies manually using pipx (Kali 2024.4+):**

   ```bash
   pipx install aiohttp 
   pipx install colorama
   pipx install tqdm
   pipx install "uvloop>=0.17.0"
   ```

**If you're using an older Kali Linux version or a different Linux distribution ensure that you have Python 3.8+ installed. Then install the required dependencies using pip:**

   ```bash
   pip install -r requirements.txt
   ```

## 📥 Install using Virtual Environment:

**Create and activate a virtual environment (optional but recommended):**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

**Upgrade pip (Optional but Recommended):**

   ```bash
   pip install --upgrade pip
   ```

**Clone the repository:**

   ```bash
   git clone https://github.com/Cybersecurity-Ethical-Hacker/xssdynagen.git
   cd xssdynagen
   ```

**Ensure you have Python 3.8+ installed. Install the required dependencies using pip:**

   ```bash
   pip install -r requirements.txt
   ```


❗ Important: Always Activate The Virtual Environment Before Use
Whenever you:

- Open a New Terminal Window
- Restart Your Computer
  
You must activate the virtual environment before running XSSDynagen to ensure that all dependencies are correctly loaded.


## 🧩 **URLs with Parameters - Kali Linux**

The tool requires URLs with parameters (e.g., `?id=1` or `?search=example&page=2`) to work effectively.

If you don't have a URL with parameters or a list of such URLs, you can generate one using the following method (replace the `domain.com`). Processing may take significant time.:

```bash
paramspider -d domain.com -s 2>&1 | grep -Ei "https?://" | sort -u | httpx-toolkit -silent -mc 200 | awk '{print $1}' > live_urls.txt
```

Alternatively, you can use tools like `waybackurls`, `urlfinder`, `katana`, and others to collect URLs efficiently.

Then just load the list using `-l urls.txt`.

## 🚀 Usage
XSSDynaGen can be used to scan a single domain or a list of URLs.

📍 Command-Line Options:
```
Usage: oredirectme.py [options]

options:
  -h, --help         Show this help message and exit
  -d, --domain       Specify the domain with parameter(s) to scan (required unless -l is used)
  -l, --url-list     Provide a file containing a list of URLs with parameters to scan
  -o, --output       Specify the output file name
  -c, --connections  Set the maximum number of concurrent connections
  -b, --batch-size   Define the number of requests per batch
  -H, --header       Custom headers can be specified multiple times. Format: "Header: Value"
  -f, --char-file    Specify a file containing character groups to test
  -u, --update       Check for updates and automatically install the latest version
```

## 💡 Examples
💻 Analyze a single domain with parameter(s) using default settings:
```bash
python xssdynagen.py -d "https://domain.com/file.php?parameter=1234"
```
💻 Analyze multiple URLs with parameter(s) from a file:
```bash
python xssdynagen.py -l urls.txt 
```
💻 Analyze multiple URLs with parameter(s) from a file with specific concurrency:
```bash
python xssdynagen.py -l urls.txt -c 100
```
💻 Include custom headers in the requests:
```bash
python xssdynagen.py -l urls.txt -H "Authorization: Bearer <token>" -H "X-Forwarded-For: 127.0.0.1"
```
💻 Update XSSDynaGen to the latest version:
```bash
python xssdynagen.py --update
```

> [!CAUTION]
> XSSDynagen analyzes parameters that have already been confirmed for value reflection !
> If you provide parameters that do not reflect their values back in the response, the tool will not be able to analyze character allowances and may behave unexpectedly.
> Always verify parameter reflection before running the tool.

## 📊 Output
- Results are saved in the `payloads` directory.
- The output file name includes a timestamp for easy reference.

## 🐛 Error Handling
- Graceful Exception Handling: The tool gracefully handles exceptions.
- Informative Messages: Provides clear messages.
- Interruption Support: Supports interruption via Ctrl+C, safely stopping the scan and providing a summary.

## 🛠️ Troubleshooting

**Common Issues and Solutions**

If you encounter problems while using **XSSDynaGen**, consider the following common causes and their respective solutions:

1. **Excessive Concurrency**
   - **Issue:** Setting the `Max Connections` value too high can lead to excessive resource consumption, causing the tool to crash or perform inefficiently.
   - **Solution:** Reduce the `Max Connections` value to a more manageable number (e.g., 50 or 80) to balance performance and resource usage.
  
## 📂 Directory Structure
- `xssdynagen.py`: Main executable script.
- `requirements.txt`: Contains a list of dependencies required to run the script.
- `payloads/`: Directory containing generated payload files.
- `characters.txt`: Contains extra character groups to test.

## 🤝 Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements, bug fixes, or new features.

## 🛡️ Ethical Usage Guidelines
I am committed to promoting ethical practices in cybersecurity. Please ensure that you use this tool responsibly and in accordance with the following guidelines:

1. Educational Purposes Only
This tool is intended to be used for educational purposes, helping individuals learn about penetration testing techniques and cybersecurity best practices.

2. Authorized Testing
Always obtain explicit permission from the system owner before conducting any penetration tests. Unauthorized testing is illegal and unethical.

3. Responsible Vulnerability Reporting
If you discover any vulnerabilities using this tool, report them responsibly to the respective organizations or maintainers. Do not exploit or disclose vulnerabilities publicly without proper authorization.

4. Compliance with Laws and Regulations
Ensure that your use of this tool complies with all applicable local, national, and international laws and regulations.

## 📚 Learn and Grow
Whether you're a budding penetration tester aiming to enhance your skills or a seasoned professional seeking to uncover and mitigate security issues, LFier is here to support your journey in building a safer digital landscape.

> [!NOTE]
> Let’s build a safer web together! 🌐🔐

