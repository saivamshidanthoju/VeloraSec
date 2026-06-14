# VeloraSec - Malware Detection and Threat Intelligence System

VeloraSec is an open-source Command Line Interface (CLI) cybersecurity tool developed in Python for detecting and analyzing malicious files using multi-source threat intelligence platforms. The system performs SHA256 hash-based malware analysis by integrating MalwareBazaar and VirusTotal APIs to identify potentially harmful files quickly and efficiently.

VeloraSec provides detailed threat intelligence information including malware signatures, vendor verdicts, YARA rule matches, file metadata, and VirusTotal detection statistics. The tool is designed for cybersecurity students, SOC analysts, malware researchers, and threat intelligence workflows.

---

# Features

* Generate SHA256 hashes from local files
* Analyze files using MalwareBazaar threat intelligence
* Integrate VirusTotal multi-engine malware scanning
* Display malware signatures and file metadata
* Show YARA rule matches for malware classification
* Display vendor verdicts and threat intelligence results
* Support direct SHA256 hash analysis
* Export analysis results to text files
* CLI-based lightweight malware analysis workflow
* Supports multiple file formats:

  * `.exe`
  * `.pdf`
  * `.txt`
  * `.js`
  * `.png`
  * `.zip`
  * `.docx`
  * and more

---

# Technologies Used

* Python
* MalwareBazaar API
* VirusTotal API
* SHA256 Hashing
* Requests Library
* Rich CLI UI
* Pyfiglet

---

# Installation

Before installing VeloraSec, ensure Python 3 and pip are installed.

## Clone Repository

```bash
git clone https://github.com/saivamshidanthoju/VeloraSec.git
cd VeloraSec
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Environment Variables

Create a `.env` file inside the project folder.

```env
MALWAREBAZAAR_AUTH_KEY=your_malwarebazaar_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

Without these API keys, malware intelligence scanning will not work.

---

# Usage

Run the tool using Python:

```bash
python velorasec.py [OPTIONS]
```

---

<img width="2048" height="6012" alt="OutputVeloraSec" src="https://github.com/user-attachments/assets/a872d476-5655-41c1-a3d5-cd5ed4501a4b" />


# Command Line Options

| Option                   | Description               |
| ------------------------ | ------------------------- |
| `-h`, `--help`           | Display help message      |
| `-f`, `--file`, `--path` | Scan local file           |
| `-s`, `--signature`      | Scan SHA256 hash directly |
| `-o`, `--output`         | Save output to text file  |

---

# Examples

## Analyze Local File

```bash
python velorasec.py -f sample.exe
```

## Analyze SHA256 Hash

```bash
python velorasec.py -s 87a54f9ce22e98c0cb1972b0991367cd1152148d7fc0106dd9c62fa7094ce5b0
```

## Save Report

```bash
python velorasec.py -f malware.exe -o report
```

---

# Example Output

VeloraSec provides:

* SHA256 hash
* Malware family
* File metadata
* Vendor verdicts
* YARA rule matches
* VirusTotal malicious detection counts
* Threat intelligence summary

Example:

```text
MALWARE DETECTED

Signature: Mirai
File Type: ELF
VirusTotal: 32 malicious detections
YARA Matches: Mirai Botnet Malware
```

---

# Limitations

While VeloraSec provides efficient malware analysis capabilities, there are some limitations:

* **Hash-Based Detection:** Detection depends on known malware hashes already indexed in threat intelligence databases.
* **Database Dependency:** Results rely on MalwareBazaar and VirusTotal intelligence availability.
* **Potential False Positives/Negatives:** Malware detection systems may occasionally produce inaccurate results.
* **Static Analysis:** VeloraSec focuses on static threat intelligence and does not perform dynamic behavioral analysis.
* **API Rate Limits:** Free API plans may have request limitations.

---

# Future Scope

VeloraSec can be expanded into a larger cybersecurity platform with features such as:

* Web dashboard integration
* Real-time file monitoring
* PDF report generation
* URL/IP/domain reputation analysis
* Docker container support
* Threat scoring system
* Cloud deployment
* SIEM integration
* Machine learning-based malware classification
* Sandbox behavior analysis

---

# Applications

* SOC Analyst workflows
* Malware analysis labs
* Threat intelligence enrichment
* Incident response
* Security research
* Cybersecurity education
* IOC investigation

---

# Acknowledgments

VeloraSec was inspired by open-source cybersecurity intelligence tools and enhanced with additional threat intelligence integrations and advanced malware analysis capabilities.

Developed by:

**Danthoju Sai Vamshi [ V ]**

GitHub:
https://github.com/saivamshidanthoju

---

# Disclaimer

VeloraSec is developed strictly for educational and research purposes only. Users are responsible for complying with all applicable cybersecurity laws and regulations. The developer is not responsible for misuse of this software.

Always handle suspicious or malicious files in isolated and secure environments.

---

# License

This project is released under the MIT License.
