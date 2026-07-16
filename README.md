# VeloraSec - Malware Detection & Threat Intelligence System

VeloraSec is an open-source Python CLI tool for malware detection and threat intelligence. It analyzes files using **SHA256 hashing**, **MalwareBazaar**, and **VirusTotal** APIs to identify known malicious files and display detailed threat intelligence.

## Features

* SHA256 file hashing
* MalwareBazaar integration
* VirusTotal integration
* YARA rule matching
* Vendor verdicts
* File metadata analysis
* SHA256 hash lookup
* Export results to a text file

## Technologies

* Python
* MalwareBazaar API
* VirusTotal API
* SHA256
* Rich
* Requests
* python-dotenv

## Installation

```bash
git clone https://github.com/saivamshidanthoju/VeloraSec.git
cd VeloraSec
pip install -r requirements.txt
```

## Environment Variables

Create a `.env` file:

```env
MALWAREBAZAAR_AUTH_KEY=your_api_key
VIRUSTOTAL_API_KEY=your_api_key
```

## Usage

Analyze a file:

```bash
python velorasec.py -f sample.exe
```

Analyze a SHA256 hash:

```bash
python velorasec.py -s <SHA256_HASH>
```

Save the output:

```bash
python velorasec.py -f sample.exe -o report.txt
```

## Command Line Options

| Option | Description            |
| ------ | ---------------------- |
| `-h`   | Show help              |
| `-f`   | Scan a local file      |
| `-s`   | Scan a SHA256 hash     |
| `-o`   | Save results to a file |

## Screenshot

*(Add your terminal output screenshot here.)*

## Future Improvements

* Web dashboard
* PDF reports
* Threat scoring
* Docker support
* URL/IP reputation analysis
* Sandbox integration

## Disclaimer

VeloraSec is intended for educational and research purposes only. Always analyze suspicious files in a secure and isolated environment.

## License

MIT License
