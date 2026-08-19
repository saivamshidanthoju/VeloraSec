# VeloraSec - Malware Detection & Threat Intelligence System

VeloraSec is an open-source Python CLI tool for malware detection and threat intelligence. It analyzes files using *SHA256 hashing, **MalwareBazaar, and **VirusTotal* APIs to identify known malicious files and display detailed threat intelligence.

## Features

- SHA256 file hashing
- MalwareBazaar integration
- VirusTotal integration
- YARA rule matching
- Vendor verdicts
- File metadata analysis
- SHA256 hash lookup
- Export results to a text file

## Technologies

- Python
- MalwareBazaar API
- VirusTotal API
- SHA256
- Rich
- Requests
- python-dotenv

## Installation

bash
git clone https://github.com/saivamshidanthoju/VeloraSec.git
cd VeloraSec
pip install -r requirements.txt


## Environment Variables

Create a .env file in the project root:

env
MALWAREBAZAAR_AUTH_KEY=your_api_key
VIRUSTOTAL_API_KEY=your_api_key


## Usage

### Analyze a local file

bash
python velorasec.py -f sample.exe


### Analyze a SHA256 hash

bash
python velorasec.py -s <SHA256_HASH>


### Save the output to a report

bash
python velorasec.py -f sample.exe -o report.txt


## Command Line Options

| Option | Description |
|--------|-------------|
| -h | Show help |
| -f | Scan a local file |
| -s | Scan a SHA256 hash |
| -o | Save results to a file |

## Screenshot

> *Add your terminal output screenshot here.*

## Future Improvements

- Web dashboard
- PDF report generation
- Threat scoring system
- Docker support
- URL/IP reputation analysis
- Sandbox integration
- Multi-engine malware scanning
- Scheduled automated scans

## Disclaimer

VeloraSec is intended for *educational and research purposes only*. Always analyze suspicious files in a secure and isolated environment. The developers are not responsible for any misuse of this tool.

## Authors

*VeloraSec* was developed by:

- *D. Sai Vamshi*
- *Sharath Kumar Reddy*

We built *VeloraSec* as an open-source cybersecurity project to help security enthusiasts, students, and researchers perform malware detection and threat intelligence using Python, MalwareBazaar, VirusTotal, and YARA.

Documentation and setup instructions improved for easier project usage

## License

This project is licensed under the *MIT License*.
