import argparse
from datetime import datetime
import json
import logging
import platform
from pathlib import Path
import re
import socket
import subprocess
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

NETWORK = ""
OUTPUT_FILE = Path("inventory.json")
LOG_FILE = Path("inventory.log")
CONFIG_FILE = Path("config.json")
SECTION = "windows"

verbose = False

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

def load_config(input_file: Path) -> dict:
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
        if verbose:
            print(f"Loaded {len(data)} records from {CONFIG_FILE}.")
        logging.info(f"Loaded {len(data)} records from {CONFIG_FILE}.")
        return data
    except FileNotFoundError:
        if verbose:
            print(f"Input file {CONFIG_FILE} not found.")
        logging.error(f"Input file {CONFIG_FILE} not found.")
        return []
    except json.JSONDecodeError as e:
        if verbose:
            print(f"Error decoding JSON from {CONFIG_FILE}: {e}")
        logging.error(f"Error decoding JSON from {CONFIG_FILE}: {e}")
        return []

def load_existing_inventory(input_file: Path) -> dict:
    if not input_file.exists():
        if verbose:
            print(f"No existing inventory file found at {input_file}. Starting fresh.")
        logging.info(f"No existing inventory file found at {input_file}. Starting fresh.")
        return {}

    try:
        with input_file.open("r", encoding="utf-8") as arquivo:
            return json.load(arquivo)
    except Exception as e:
        if verbose:
            print(f"Failed to read existing inventory from {input_file}: {e}")
        logging.warning(f"Failed to read existing inventory from {input_file}: {e}")
        return {}

def save_results_to_json(data: dict, output_file: Path) -> None:
    with output_file.open("w", encoding="utf-8") as arquivo:
        json.dump(data, arquivo, indent=2, ensure_ascii=False)

def run_command(command: List[str], timeout=30) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired as e:
        logging.warning(f"Command timed out after {timeout}s: {command}")
        return ""
    except subprocess.CalledProcessError as e:
        logging.error(f"Error occurred while running command: {command}")
        raise

def scan_arp_scan(network: str) -> List[dict]:
    logging.info(f"Scanning network {network} using arp-scan...")
    result = run_command(["arp-scan", "-t", network])
    registros = {}
    pattern = r"Reply that ([0-9A-F:]+) is ([0-9.]+) in ([0-9.]+)"

    for mac, ip, time in re.findall(pattern, result):
        registros[mac] = {
             "ip": ip, 
             "latency": float(time), 
             "vendor": "Missing"
        }

    if verbose:
        print(f"Found {len(registros)} entries using arp-scan.")
    logging.info(f"Found {len(registros)} entries using arp-scan.")

    return registros

def scan_nmap(network: str) -> List[dict]:
    if verbose:
        print(f"Scanning network {network} using nmap scan...")
    logging.info(f"Scanning network {network} using nmap scan...")
    try:
        result = run_command(["nmap", "-sn", network], timeout=120)
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"nmap scan timedout for network {network}.")
        logging.warning(f"nmap scan timedout for network {network}.")
        return {}
    except Exception as e:
        if verbose:
            print(f"Error occurred while scanning network {network} with nmap: {e}")
        logging.error(f"Error occurred while scanning network {network} with nmap: {e}")
        return {}

    registros = {}

    regex = re.compile(
        r'Nmap scan report for (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'
        r'Host is up(?:\s+\((?P<latencia>[\d.]+s)\s+latency\))?\.\s*'
        r'(?:MAC Address:\s+(?P<mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})'
        r'(?:\s+\((?P<fabricante>[^)]+)\))?)?',
        re.MULTILINE
        )

    for match in regex.finditer(result):
        mac = match.group("mac")

        key = mac if mac else get_mac(match.group("ip"))

        registros[key] = {
            "ip": match.group("ip"),
            "latency": match.group("latencia"),
            "vendor": match.group("fabricante")
        }

    if verbose:
        print(f"Found {len(registros)} entries using nmap.")
    logging.info(f"Found {len(registros)} entries using nmap.")
    return registros

def get_mac(ip: str) -> str:
    result = run_command(["arp-scan", "-t", ip])
    pattern = r"Reply that ([0-9A-F:]+) is ([0-9.]+) in ([0-9.]+)"

    for mac, new_ip, time in re.findall(pattern, result):
        logging.info("Found mac %s to ip %s", mac, ip)
        return mac

def latency_to_float(value):
    if value is None:
        return float("inf")

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, str):
        return float(value.rstrip("s"))

    return float("inf")


def merge_devices(arpscan_results, nmap_results):
    merged = {}

    all_macs = set(arpscan_results) | set(nmap_results)

    for mac in all_macs:
        arp = arpscan_results.get(mac, {})
        nmap = nmap_results.get(mac, {})

        vendor_arp = arp.get("vendor")
        vendor_nmap = nmap.get("vendor")

        # prefere fabricante conhecido
        vendor = vendor_arp
        if vendor in (None, "", "Missing", "Unknown"):
            vendor = vendor_nmap

        # pega menor latência
        lat_arp = arp.get("latency")
        lat_nmap = nmap.get("latency")

        latency = min(
            latency_to_float(lat_arp),
            latency_to_float(lat_nmap)
        )

        if latency == float("inf"):
            latency = None

        merged[mac] = {
            "mac": mac,
            "ip": nmap.get("ip") or arp.get("ip"),
            "latency": latency,
            "vendor": vendor
        }

    if verbose:
        print(f"merge_devices = {len(merged)} after merge.")
    logging.info(f"merge_devices = {len(merged)} after merge.")
    return merged

def update_inventory(inventory, merged):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for mac, data in merged.items():

        if mac not in inventory:
            # novo dispositivo
            inventory[mac] = {
                "first_seen": now,
                "last_seen": now,
                **data
            }
            continue

        current = inventory[mac]

        # atualiza última vez visto
        current["last_seen"] = now

        # IP
        if data.get("ip"):
            old_ip = current.get("ip")

            if isinstance(old_ip, list):
                if data["ip"] not in old_ip:
                    old_ip.append(data["ip"])
            elif old_ip and old_ip != data["ip"]:
                current["ip"] = [old_ip, data["ip"]]
            else:
                current["ip"] = data["ip"]

        # Vendor: substitui Missing/Unknown
        vendor = data.get("vendor")
        if vendor and vendor not in ("Missing", "Unknown"):
            current["vendor"] = vendor

        # Menor latência
        latency = data.get("latency")

        if latency is not None:
            old_latency = current.get("latency")

            if old_latency is None or latency < old_latency:
                current["latency"] = latency

    return inventory

def get_info(ip: str) -> Dict[str, str]:

    result = run_command([
        "nmap",
        "-O",
        "--osscan-guess",
        "--host-timeout",
        "30s",
        ip
    ])

    device_type = "Unknown"
    os_name = "Unknown"

    m = re.search(r"Device type:\s*(.+)", result)
    if m:
        device_type = m.group(1).strip()

    m = re.search(r"Running:\s*(.+)", result)
    if m:
        os_name = m.group(1).strip()
    else:
        m = re.search(r"(?<=Aggressive OS guesses:\s)([^,]+)", result)
        if m:
            os_name = m.group(1).strip()

    logging.info(
        "IP=%s Device=%s OS=%s",
        ip,
        device_type,
        os_name
    )

    return {
        "device_type": device_type,
        "os": os_name,
    }

def process_device(mac, dados):
    ip = dados.get("ip")

    if isinstance(ip, list):
        ip = ip[-1]

    logging.info("Processing device: %s", ip)

    if ip and dados.get("device_type", "Unknown") == "Unknown":
        try:
            return mac, {**get_info(ip), "hostname": get_dns(ip)}
        except Exception as e:
            if verbose:
                print("Error to get information from %s: %s", ip, e)
            logging.error("Error to get information from %s: %s", ip, e)

    return mac, {"hostname": get_dns(ip)}

def get_dns(ip):

    try:
        hostname = socket.gethostbyaddr(ip)[0]
        logging.info("IP=%s hostname=%s", ip, hostname)
        return hostname
    except:
        return None

def process_network():
    if verbose:
        print(f"Starting network discovery on {NETWORK}...")
    logging.info(f"Starting network discovery on {NETWORK}...")
    arpscan_results = scan_arp_scan(NETWORK)
    nmap_results = scan_nmap(NETWORK)
    merged = merge_devices(arpscan_results, nmap_results)
    inventory = load_existing_inventory(OUTPUT_FILE)
    if verbose:
        print(f"Inventory loaded {len(inventory)} registers.")
    logging.info(f"Inventory loaded {len(inventory)} registers.")
    inventory = update_inventory(inventory, merged)

    print("Start getting device type...")
    logging.info("Start getting device type...")
    logging.info("Inventory has %d items to process.", len(inventory))
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(process_device, mac, dados)
            for mac, dados in inventory.items()
            if dados.get("ip")
            and (
                dados.get("device_type") in (None, "", "Unknown")
                or dados.get("os") in (None, "", "Unknown")
            )
        ]
        for future in as_completed(futures):
            try:
                mac, info = future.result()

                if info:
                    for key, value in info.items():

                        current = inventory[mac].get(key, "Unknown")

                        if current in (None, "", "Unknown") and value not in (None, "", "Unknown"):
                            inventory[mac][key] = value

            except Exception as e:
                logging.error("Erro em thread: %s", e)

    save_results_to_json(inventory,OUTPUT_FILE)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Discovering windows networl")
    p.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable verbose logging")
    args = p.parse_args()

    verbose = args.verbose

    print(f"Starting network discovery on {platform.system()} platform.")
    logging.info(f"Starting network discovery on {platform.system()} platform.")

    config = load_config(CONFIG_FILE)
    if not config:
        print("Error reading configuration file (%s).", CONFIG_FILE)
        logging.error("Error reading configuration file (%s).", CONFIG_FILE)
    else:
        config_info = config[SECTION]
        NETWORK = config_info["network"]
        process_network()

    print("Finish network discovery.")
    logging.info("Finish network discovery.")

