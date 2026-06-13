import argparse
import hashlib
import requests
import pyfiglet
import os
from datetime import datetime

from dotenv import load_dotenv

from rich.console import Console
from rich.table import Table
from rich.text import Text

load_dotenv()

console = Console()

APP_NAME = "VeloraSec"
APP_TAGLINE = "Enterprise Threat Intelligence Console"
APP_DESCRIPTION = "Malware Detection and Threat Analysis System"
AUTHOR = "Danthoju Sai Vamshi [ V ]"
GITHUB_URL = "https://github.com/saivamshidanthoju"
SOURCE_NAME = "MalwareBazaar"

INFO_STYLE = "bold cyan"
SUCCESS_STYLE = "bold green"
WARNING_STYLE = "bold yellow"
ERROR_STYLE = "bold red"
MUTED_STYLE = "dim white"


def current_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def section(title):
    console.print()
    console.print(f"[{INFO_STYLE}]:: {title}[/{INFO_STYLE}]")


def status_line(label, value, style="white"):
    value = str(value)

    if len(value) > 56:
        console.print(f"[{MUTED_STYLE}]{label}[/{MUTED_STYLE}]")
        console.print(f"  [{style}]{value}[/{style}]")
        return

    console.print(f"[{MUTED_STYLE}]{label:<16}[/{MUTED_STYLE}] [{style}]{value}[/{style}]")


def info(message):
    console.print(f"[{INFO_STYLE}]INFO[/{INFO_STYLE}] {message}")


def success(message):
    console.print(f"[{SUCCESS_STYLE}]OK[/{SUCCESS_STYLE}] {message}")


def warning(message):
    console.print(f"[{WARNING_STYLE}]NOTICE[/{WARNING_STYLE}] {message}")


def error(message="Something went wrong."):
    console.print(f"[{ERROR_STYLE}]ERROR[/{ERROR_STYLE}] {message}")


def clean_table(title=None):
    if title:
        console.print(Text(title, style="yellow"))

    return Table(
        show_header=False,
        box=None,
        show_edge=False,
        show_lines=False,
        pad_edge=False,
    )


def normalize_file_path(file_path):
    cleaned_path = str(file_path).strip()

    while (
        len(cleaned_path) >= 2
        and cleaned_path[0] == cleaned_path[-1]
        and cleaned_path[0] in ("'", '"')
    ):
        cleaned_path = cleaned_path[1:-1].strip()

    return os.path.abspath(os.path.expanduser(cleaned_path))


# ==========================================
# Banner / Branding
# ==========================================

def banner():

    banner_text = pyfiglet.figlet_format("Ve l o ra  Sec")

    console.print(
        banner_text,
        style="bold white"
    )

    console.print(
        "Malware Detection and Threat Analysis System.",
        style="bold"
    )

    print("\n")
    console.print("#> by Danthoju Sai Vamshi [ V ]", style="bold bright_white")
    console.print(
    "#> GitHub: https://github.com/saivamshidanthoju",
    style="bold bright_white"
)
    print("-" * 40)
    print("\n")



# ==========================================
# Generate SHA256 Hash
# ==========================================
def calculate_sha256(file_path):

    sha256 = hashlib.sha256()

    try:

        # Clean path
        clean_path = os.path.abspath(
            os.path.expanduser(
                str(file_path).strip().replace('"', '')
            )
        )

        print("DEBUG:", repr(clean_path))

        if not os.path.exists(clean_path):

            error("File does not exist.")

            return None

        with open(clean_path, "rb") as file:

            while chunk := file.read(4096):

                sha256.update(chunk)

        return sha256.hexdigest()

    except Exception as e:

        error(f"Unable to read file: {e}")

        return None

# ==========================================
# MalwareBazaar API Request
# ==========================================
def check_malwarebazaar(file_hash):

    url = url = "https://mb-api.abuse.ch/api/v1/"

    payload = {
        "query": "get_info",
        "hash": file_hash
    }

    headers = {
    "Auth-Key": API_KEY,
    "User-Agent": "VeloraSec",
    "Accept": "application/json"
}
    try:

        response = requests.post(
            url,
            data=payload,
            headers=headers,
            timeout=20
        )

        status_line("HTTP Status", response.status_code, "bright_white")

        if response.status_code != 200:

            return {
                "error": f"API request failed with status code {response.status_code}",
                "response": response.text
            }

        try:

            return response.json()

        except:

            return {
                "error": "API did not return valid JSON.",
                "response": response.text
            }

    except requests.exceptions.RequestException as e:

        return {
            "error": str(e)
        }


def output(f_name, data):
    file_name = f"{f_name}.txt"

    try:
        with open(file_name, "w", encoding="utf-8") as file:
            file.write(data)

        success(f"Report saved to {file_name}")

    except Exception as e:
        error(f"Unable to save report: {e}")


def file_info(json_data, file_hash):
    js = json_data
    output_str = ""
    table = clean_table("Info:")
    table.add_column(style="bold cyan")
    table.add_column(style="bright_white")

    for item in js["data"]:
        info_fields = {
            "File Name": item.get("file_name", "N/A"),
            "File Type": item.get("file_type", "N/A"),
            "File Size": item.get("file_size", "N/A"),
            "Signature": item.get("signature", "N/A"),
            "Reporter": item.get("reporter", "N/A"),
            "First Seen": item.get("first_seen", "N/A"),
            "SHA256": file_hash,
        }

        for key, value in info_fields.items():
            output_str += f"{key}: {value}\n"
            table.add_row(key, str(value))

        break

    console.print(table)
    return output_str


def get_verdicts(json_data):
    js = json_data
    verdicts = dict()
    output_str = ""
    table = clean_table("Verdicts (Vendor, Verdict):")
    table.add_column(style="bold cyan")
    table.add_column(style="bright_red")

    for item in js["data"]:
        for vendor in item.get("vendor_intel", {}):
            details = item.get("vendor_intel", {})[vendor]

            if isinstance(details, dict) and "verdict" in details:
                verdicts[vendor] = details["verdict"]

            if isinstance(details, dict) and "detection" in details:
                verdicts[vendor] = details["detection"]

            if isinstance(details, list):
                for entry in details:
                    if "verdict" in entry:
                        verdicts[vendor] = entry["verdict"]
                    elif "detection" in entry:
                        verdicts[vendor] = entry["detection"]

    for vendor in verdicts:
        output_str += f"{vendor.capitalize()}: {str(verdicts[vendor]).capitalize()}\n"
        table.add_row(vendor.capitalize(), str(verdicts[vendor]).capitalize())

    output_str += "\n"
    console.print(table)
    return output_str


def get_yara(json_data):
    js = json_data
    yara = list()
    output_str = ""
    table = clean_table("Yara Rules:")
    table.add_column(style="bold cyan")
    table.add_column(style="bright_white")

    for item in js["data"]:
        for rule in item.get("yara_rules", []):
            yara.append(rule)

    for rule in yara:
        for key in rule:
            output_str += f"{key.capitalize()}: {rule[key]}\n"
            table.add_row(key.capitalize(), str(rule[key]))

        table.add_row("", "")
        output_str += "\n"

    console.print(table)
    return output_str


def handle_response(response, o, file_hash):
    js = response

    section("Scan Target")
    status_line("SHA256", file_hash, "yellow")

    if js is None:
        error("No response from API.")
        return

    if "error" in js:
        error(js["error"])

        if js.get("response"):
            status_line("API Response", js["response"], "red")

        if o:
            output(o, f"Error: {js['error']}\nResponse: {js.get('response', '')}\n")

        return

    if js["query_status"] == "ok":
        console.print(Text("Malware Detected!", style="bold red"))
        print("\n")

        output_str = ""
        output_str += "Malware detected!\n"
        output_str += f"{file_info(js, file_hash)}\n"
        output_str += f"{get_verdicts(js)}\n"
        output_str += f"{get_yara(js)}\n"

        section("Final Verdict")
        status_line("Verdict", "MALICIOUS", "bold red")
        status_line("Source", SOURCE_NAME, "bright_cyan")

        if o:
            output(o, output_str)

    else:
        heading = Text("No malware detected. This file is likely safe.\n", style="bold green")
        console.print(heading)
        status_line("Query Status", js.get("query_status"), "yellow")

        if o:
            output(o, f"No malware detected.\nQuery Status: {js.get('query_status')}\nHash: {file_hash}\n")


def make_post_request(file_hash, o):
    response = check_malwarebazaar(file_hash)
    handle_response(response, o, file_hash)


def parse():
    parser = argparse.ArgumentParser(
        description="VeloraSec - Malware Detection and Threat Analysis System"
    )

    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Enter file path to scan"
    )

    parser.add_argument(
        "-s",
        "--signature",
        help="Enter SHA256 hash directly"
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output to a file"
    )

    args = parser.parse_args()
    f = args.file if args.file else False
    o = args.output if args.output else False
    s = args.signature if args.signature else False
    return f, o, s


def render_scan_context(source_type, source_value, file_hash):
    section("Scan Context")
    status_line("Input Type", source_type, "bright_white")
    status_line("Input Value", source_value, "bright_white")
    status_line("Source", SOURCE_NAME, "bright_cyan")
    status_line("Timestamp", current_timestamp(), "bright_white")
    status_line("SHA256", file_hash, "yellow")


def main():
    banner()

    f, o, s = parse()

    if f != False or s != False:
        if f:
            section("File Hashing")
            info("Generating SHA256 fingerprint from local file.")

            file_path = normalize_file_path(f)
            hash_value = calculate_sha256(file_path)

            if hash_value is None:
                return

            success("SHA256 fingerprint generated.")
            render_scan_context("File", file_path, hash_value)

        elif s:
            hash_value = s
            section("Signature Input")

            table = clean_table()
            table.add_column(style="bold cyan")
            table.add_column(style="bright_white")
            table.add_row("Hash Entered", hash_value)
            console.print(table)

            render_scan_context("Signature", s, hash_value)

        section("Threat Intelligence Lookup")

        with console.status(
            "[bold cyan]Querying MalwareBazaar threat intelligence...[/bold cyan]",
            spinner="line",
        ):
            make_post_request(hash_value, o)

    else:
        error("Please provide a file path or SHA256 hash.")

        section("Examples")

        console.print(
            "python velorasec.py -f test.txt",
            style="bright_white"
        )

        console.print(
            "python velorasec.py -s 44d88612fea8a8f36de82e1278abb02f176e6cbba3fe4",
            style="bright_white"
        )

        console.print(
            "python velorasec.py -f test.txt -o report",
            style="bright_white"
        )


load_dotenv()

API_KEY = os.getenv("MALWAREBAZAAR_AUTH_KEY")

# ==========================================
# Program Start
# ==========================================
if __name__ == "__main__":

    main()