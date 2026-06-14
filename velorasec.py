#!/usr/bin/env python3

import pyfiglet
import requests
import hashlib
import argparse
import os

from dotenv import load_dotenv

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box
from rich.panel import Panel

load_dotenv()

console = Console()
API_KEY = os.getenv("MALWAREBAZAAR_AUTH_KEY", "").strip()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY","").strip()


def banner():

    console.print(pyfiglet.figlet_format("Velora   Sec"), style="bold white")

    print("Fast Intelligent Cyber Analysis & Security System.")

    print("\n")

    console.print("#> by Danthoju Sai Vamshi [ V ]", style="bold white")

    console.print("#> https://github.com/saivamshidanthoju", style="bold white")

    print("-" * 40)

    print("\n")


def error():

    err_text = Text(
        "An error has occurred. Please refer to the help below:",
        style="bold red"
    )

    console.print(err_text)

    print("\n")

    help()


def help():

    console.print("[bold yellow]Usage:[/bold yellow]")

    console.print("  velorasec.py [-h] [-f PATH] [-s SIGNATURE] [-o OUTPUT]\n")

    console.print("[bold yellow]Options:[/bold yellow]")

    table = Table(
        show_header=True,
        box=box.SIMPLE
    )

    table.add_column("Option", style="bold cyan")

    table.add_column("Description", style="white")

    table.add_row(
        "-h, --help",
        "Show this help message and exit"
    )

    table.add_row(
        "-f PATH, --file PATH, --path PATH",
        "Enter the file path"
    )

    table.add_row(
        "-s SIGNATURE, --signature SIGNATURE",
        "Enter the file signature"
    )

    table.add_row(
        "-o OUTPUT, --output OUTPUT",
        "Output to a file"
    )

    console.print(table)


def normalize_file_path(file_path):

    cleaned_path = str(file_path).strip()

    while (
        len(cleaned_path) >= 2
        and cleaned_path[0] == cleaned_path[-1]
        and cleaned_path[0] in ("'", '"')
    ):

        cleaned_path = cleaned_path[1:-1].strip()

    return os.path.abspath(os.path.expanduser(cleaned_path))


try:

    def output(f_name, data):

        file_name = f"{f_name}.txt"

        try:

            with open(file_name, "w", encoding="utf-8") as f:

                f.write(data)

        except:

            error()

    def get_verdicts(json_data):

        js = json_data

        verdicts = dict()

        output_str = ""

        header = Text(
            "Verdicts (Vendor, Verdict): ",
            style="yellow"
        )

        console.print(header)

        table = Table(
            show_header=False,
            box=box.SIMPLE
        )

        table.add_column(style="bold cyan")

        table.add_column(style="bright_red")

        for i in js["data"]:

            vendor_intel = i.get("vendor_intel") or {}

            for j in vendor_intel:

                k = vendor_intel[j]

                if type(k) == dict and "verdict" in k:

                    verdicts[j] = k["verdict"]

                if type(k) == dict and "detection" in k:

                    verdicts[j] = k["detection"]

                if type(k) == list:

                    for l in k:

                        if "verdict" in l:

                            verdicts[j] = l["verdict"]

                        elif "detection" in l:

                            verdicts[j] = l["detection"]

        for i in verdicts:

            output_str += (
                f"{i.capitalize()}: "
                f"{str(verdicts[i]).capitalize()}\n"
            )

            table.add_row(
                i.capitalize(),
                str(verdicts[i]).capitalize()
            )

        output_str += "\n"

        console.print(table)

        return output_str

    def get_yara(json_data):

        js = json_data

        output_str = ""

        data = js["data"][0] if js.get("data") else {}

        # ==========================================
        # YARA Rules
        # ==========================================
        yara_rules = data.get("yara_rules") or []

        if yara_rules:

            yara_table = Table(title="YARA Rule Matches")

            yara_table.add_column(
                "Rule Name",
                style="cyan"
            )

            yara_table.add_column(
                "Description",
                style="white"
            )

            for rule in yara_rules:

                rule_name = str(rule.get("rule_name", "N/A"))

                description = str(rule.get("description", "N/A"))

                yara_table.add_row(
                    rule_name,
                    description
                )

                output_str += (
                    f"Rule Name: {rule_name}\n"
                    f"Description: {description}\n\n"
                )

            console.print(yara_table)

        else:

            console.print("YARA Rules: None\n")

            output_str = "YARA Rules: None\n"

        return output_str

    def file_info(json_data):

        js = json_data

        info = list()

        output_str = ""

        header = Text(
            "Info: ",
            style="yellow"
        )

        console.print(header)

        table = Table(
            show_header=False,
            box=box.SIMPLE
        )

        table.add_column(style="bold cyan")

        table.add_column(style="bright_white")

        for i in js["data"]:

            info.append(i)

            break

        for i in info:

            for s in i:

                if s != "file_information":

                    output_str += (
                        f"{s.capitalize()}: "
                        f"{i[s]}\n"
                    )

                    table.add_row(
                        s.capitalize(),
                        str(i[s])
                    )

                else:

                    break

            break

        console.print(table)

        return output_str

    def handle_response(response, o):

        js = response

        if js["query_status"] == "ok":

            heading = Panel(
                "[bold red]!!! MALWARE DETECTED !!![/bold red]",
                border_style="red",
                expand=False
            )

            console.print(heading)

            print("\n")

            output_str = ""

            output_str += "Malware detected!\n"

            output_str += f"{file_info(js)}\n"

            output_str += f"{get_verdicts(js)}\n"

            output_str += f"{get_yara(js)}\n"

            if o:

                output(o, output_str)

        else:

            heading = Text(
                "No malware detected. "
                "This file is likely safe.\n",
                style="bold green"
            )

            console.print(heading)

    def make_post_request(url, data, o):

        if not API_KEY:

            print("Missing MALWAREBAZAAR_AUTH_KEY in .env file.")

            return

        headers = {

            "Auth-Key": API_KEY,

            "User-Agent": "VeloraSec",

            "Accept": "application/json"
        }

        try:

            response = requests.post(
                url,
                data=data,
                headers=headers,
                timeout=20
            )

        except requests.exceptions.RequestException as e:

            print(f"POST request failed: {e}")

            return

        if response.status_code == 200:

            response = response.json()

            handle_response(response, o)

        else:

            print(
                f"POST request failed "
                f"with status code: "
                f"{response.status_code}"
            )

            print("Response:")

            print(response.text)

    def check_virustotal(file_hash):

        if not VT_API_KEY:

            console.print(
                "VirusTotal API Key is missing. "
                "Please set the VIRUSTOTAL_API_KEY in your .env file to enable VirusTotal scanning.",
                style="bold yellow"
            )

            return

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

        headers = {
            "x-apikey": VT_API_KEY
        }

        try:

            response = requests.get(
                url,
                headers=headers,
                timeout=20
            )

            if response.status_code == 404:

                console.print(
                    "VirusTotal: Hash not found.",
                    style="bold yellow"
                )

                return

            if response.status_code != 200:

                console.print(
                    f"VirusTotal API Error: {response.status_code}",
                    style="bold red"
                )

                return

            vt_data = response.json()

            stats = vt_data["data"]["attributes"]["last_analysis_stats"]

            harmless = stats.get("harmless", 0)
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)

            table = Table(
                title="VirusTotal Analysis",
                box=box.SIMPLE
            )

            table.add_column("Category", style="bold cyan")
            table.add_column("Count", style="bright_white")

            table.add_row("Harmless", str(harmless))
            table.add_row("Malicious", str(malicious))
            table.add_row("Suspicious", str(suspicious))
            table.add_row("Undetected", str(undetected))

            console.print(table)

            if malicious > 0:

                console.print(
                    "VirusTotal Verdict: MALICIOUS",
                    style="bold red"
                )

            elif suspicious > 0:

                console.print(
                    "VirusTotal Verdict: SUSPICIOUS",
                    style="bold yellow"
                )

            else:

                console.print(
                    "VirusTotal Verdict: SAFE / UNKNOWN",
                    style="bold green"
                )

        except Exception as e:

            console.print(
                f"VirusTotal Error: {e}",
                style="bold red"
            )

    def calculate_file_hash(
        file_path,
        hash_algorithm='sha256',
        chunk_size=8192
    ):

        hash_obj = hashlib.new(hash_algorithm)

        file_path = normalize_file_path(file_path)

        try:

            with open(file_path, 'rb') as f:

                while True:

                    data = f.read(chunk_size)

                    if not data:

                        break

                    hash_obj.update(data)

        except OSError as e:

            print(f"Unable to read file: {e}")

            return None

        return hash_obj.hexdigest()

    def parse():

        parser = argparse.ArgumentParser(
            description=(
                "Velora Sec - "
                "Fast Intelligent Cyber Analysis & Security System"
            )
        )

        parser.add_argument(
            "-f",
            "--file",
            "--path",
            nargs=1,
            dest="path",
            help="Enter the file path."
        )

        parser.add_argument(
            "-s",
            "--signature",
            nargs=1,
            help="Enter the file signature."
        )

        parser.add_argument(
            "-o",
            "--output",
            nargs=1,
            help="Output to a file."
        )

        args = parser.parse_args()

        f = args.path[0] if args.path else False

        o = args.output[0] if args.output else False

        s = args.signature[0] if args.signature else False

        return f, o, s

    def main():

        banner()

        f, o, s = parse()

        if f != False or s != False:

            if f:

                hash_value = calculate_file_hash(f)
                print("Generated Hash:", hash_value)

                if hash_value is None:

                    return

            elif s:

                hash_value = s

                table = Table(
                    show_header=False,
                    box=box.SIMPLE
                )

                table.add_column(style="bold cyan")

                table.add_column(style="bright_white")

                table.add_row(
                    "Hash Entered",
                    hash_value
                )

                console.print(table)

            url = "https://mb-api.abuse.ch/api/v1/"

            data = {
                "query": "get_info",
                "hash": ""
            }

            data["hash"] = hash_value

            make_post_request(url, data, o)

            print("\nChecking VirusTotal...\n")

            check_virustotal(hash_value)

        else:

            error()

except Exception as e:

    error()

main()
