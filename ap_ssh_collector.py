#!/usr/bin/env python3
"""
AP SSH Command Collector + CSCwf25731 Analyzer
===============================================
Reads AP names/IPs from Excel (.xlsx) or text file (.txt),
connects via SSH, runs diagnostic commands, and analyzes
results for Cisco bug CSCwf25731 / CSCwf37271.

Usage:
  python ap_ssh_collector.py ap_list.xlsx
  python ap_ssh_collector.py ap_ips.txt

TXT format: one IP address per line (lines starting with # are ignored)
"""

import sys
import os
import re
import time
import getpass
import datetime
import argparse

# ============================================================
# AUTO-INSTALL DEPENDENCIES
# ============================================================

def pip_install(package):
    """Install a Python package if missing."""
    print(f"[!] Installing {package}...")
    os.system(f"{sys.executable} -m pip install {package} --quiet")

try:
    import openpyxl
except ImportError:
    pip_install("openpyxl")
    import openpyxl

try:
    import paramiko
except ImportError:
    pip_install("paramiko")
    import paramiko

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    pip_install("colorama")
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)


# ============================================================
# CONFIGURATION
# ============================================================

# Excel: Sheet name (None = first sheet)
SHEET_NAME = None

# Excel: Columns (1-indexed): A=1, B=2, C=3, D=4
AP_NAME_COL = 1   # column A - AP Name
IP_ADDR_COL = 4   # column D - IP Address
AP_MODEL_COL = 2  # column B - AP Model

# Excel: Data starts at row 2 (row 1 = header)
DATA_START_ROW = 2

# Commands to run on each AP
COMMANDS = [
    "show clock",
    "show version",
    "show flash",
    "show flash | i cnssdaemon.log",
    "show boot",
    "show filesystems",
    "show image integrity",
]

# SSH settings
SSH_PORT = 22
SSH_TIMEOUT = 15
CMD_TIMEOUT = 15
CMD_TIMEOUT_LONG = 60
BUFFER_SIZE = 65535

# Commands that need longer timeout
SLOW_COMMANDS = ["show image integrity"]

# Output file (None = auto-generated with timestamp)
OUTPUT_FILE = None

# ============================================================
# CSCwf25731 - AFFECTED VERSIONS & MODELS
# ============================================================

AFFECTED_MODELS = [
    "C9124", "C9130", "C9136",
    "C9162", "C9163", "C9164", "C9166",
    "IW9167",
]

# Affected version ranges (prefix, min_sub, max_sub)
AFFECTED_VERSIONS = [
    ("17.12.4", 0, 212),
    ("17.12.5", 0, 208),
    ("17.12.6", 0, 200),
]

LOW_MEMORY_THRESHOLD_MB = 20


# ============================================================
# COLOR OUTPUT (colorama + Windows compatibility)
# ============================================================

def c_ok(text):
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}"

def c_warn(text):
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"

def c_err(text):
    return f"{Fore.RED}{text}{Style.RESET_ALL}"

def c_crit(text):
    return f"{Fore.RED}{Style.BRIGHT}{text}{Style.RESET_ALL}"

def c_info(text):
    return f"{Fore.CYAN}{text}{Style.RESET_ALL}"

def c_dim(text):
    return f"{Style.DIM}{text}{Style.RESET_ALL}"

def c_bold(text):
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"

RISK_COLORS = {
    "CRITICAL": c_crit,
    "WARNING":  c_warn,
    "LOW":      c_warn,
    "SAFE":     c_ok,
    "UNKNOWN":  c_dim,
}

RISK_ICONS = {
    "CRITICAL": "[!!!]",
    "WARNING":  "[ ! ]",
    "LOW":      "[ ~ ]",
    "SAFE":     "[ OK]",
    "UNKNOWN":  "[ ? ]",
}

# Column widths for aligned table output
COL_NAME    = 26
COL_IP      = 17
COL_MODEL   = 14
COL_RUNNING = 14
COL_BOOT    = 6
COL_APART   = 20
COL_IPART   = 20
COL_CNSSD   = 6
COL_RISK    = 10


def cpad(text, width, color_fn=None):
    """Pad text to width FIRST, then apply color. This keeps columns aligned
    because padding is done on plain text before invisible ANSI codes are added."""
    padded = f"{text:<{width}}"
    if color_fn:
        return color_fn(padded)
    return padded


# ============================================================
# SSH FUNCTIONS
# ============================================================

def strip_ansi(text):
    """Remove ANSI escape sequences from text."""
    return re.sub(r'\x1b\[[0-9;]*m|\[\d+;\d+m|\[m', '', text)


def read_until_prompt(shell, prompts=("#", ">"), timeout=30):
    """Read shell output until a prompt is detected or timeout expires."""
    output = ""
    start = time.time()
    while time.time() - start < timeout:
        if shell.recv_ready():
            chunk = shell.recv(BUFFER_SIZE).decode("utf-8", errors="replace")
            output += chunk
            lines = output.rstrip().split("\n")
            last_line = lines[-1].strip() if lines else ""
            if any(last_line.endswith(p) for p in prompts):
                break
        else:
            time.sleep(0.3)
    return output


def ssh_run_commands(ip, username, password, enable_password, commands):
    """Connect to AP via SSH, enter enable mode, run commands."""
    results = {}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=ip,
            port=SSH_PORT,
            username=username,
            password=password,
            timeout=SSH_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )

        shell = client.invoke_shell(width=200, height=1000)

        # Wait for initial prompt (>)
        read_until_prompt(shell, prompts=(">",), timeout=10)

        # Enter enable mode
        shell.send("en\n")
        read_until_prompt(shell, prompts=("Password:", "assword:"), timeout=10)

        shell.send(enable_password + "\n")
        en_result = read_until_prompt(shell, prompts=("#",), timeout=10)

        if "%" in en_result or "denied" in en_result.lower() or "fail" in en_result.lower():
            results["__ERROR__"] = "Enable authentication failed"
            client.close()
            return results

        # Disable paging
        shell.send("terminal length 0\n")
        read_until_prompt(shell, prompts=("#",), timeout=5)

        # Execute commands
        for cmd in commands:
            shell.send(cmd + "\n")
            timeout = CMD_TIMEOUT_LONG if cmd in SLOW_COMMANDS else CMD_TIMEOUT
            output = read_until_prompt(shell, prompts=("#",), timeout=timeout)

            # Trim echoed command and prompt
            lines = output.strip().split("\n")
            if len(lines) >= 2:
                cleaned = "\n".join(lines[1:-1])
            else:
                cleaned = output.strip()
            results[cmd] = strip_ansi(cleaned)

        shell.close()

    except Exception as e:
        results["__ERROR__"] = str(e)

    finally:
        client.close()

    return results


# ============================================================
# INPUT FILE READING
# ============================================================

def read_ap_list_xlsx(excel_path, sheet_name=None):
    """Read AP list from Excel file. Returns [(name, ip, model), ...]"""
    wb = openpyxl.load_workbook(excel_path, read_only=False)
    ws = wb[sheet_name] if sheet_name else wb.active

    ap_list = []
    for row in ws.iter_rows(min_row=DATA_START_ROW, values_only=False):
        ap_name = row[AP_NAME_COL - 1].value
        ip_addr = row[IP_ADDR_COL - 1].value
        ap_model = row[AP_MODEL_COL - 1].value if len(row) >= AP_MODEL_COL else ""
        if ap_name and ip_addr:
            ap_list.append((
                str(ap_name).strip(),
                str(ip_addr).strip(),
                str(ap_model).strip() if ap_model else "",
            ))

    wb.close()
    return ap_list


def read_ap_list_txt(txt_path):
    """Read AP list from TXT file (one IP per line).
    Returns [(name, ip, model), ...] where name=IP (resolved later from show version)."""
    ap_list = []
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    with open(txt_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ip_pattern.match(line):
                ap_list.append((line, line, ""))
            else:
                print(c_warn(f"  [!] Line {line_num}: '{line}' is not a valid IP, skipping"))
    return ap_list


def read_ap_list(file_path, sheet_name=None):
    """Auto-detect file format and read AP list."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".xlsx", ".xls"):
        return read_ap_list_xlsx(file_path, sheet_name)
    elif ext == ".txt":
        return read_ap_list_txt(file_path)
    else:
        print(c_err(f"[ERROR] Unsupported file format '{ext}'. Use .xlsx or .txt"))
        sys.exit(1)


# ============================================================
# CSCwf25731 ANALYSIS
# ============================================================

def is_affected_model(model_str):
    """Check if the AP model is affected by the bug."""
    model_upper = model_str.upper()
    return any(m in model_upper for m in AFFECTED_MODELS)


def is_affected_version(version_str):
    """Check if the version is in the affected range."""
    if not version_str:
        return False
    parts = version_str.strip().split(".")
    if len(parts) < 4:
        return False
    try:
        prefix = ".".join(parts[:3])
        sub = int(parts[3])
        for (affected_prefix, min_sub, max_sub) in AFFECTED_VERSIONS:
            if prefix == affected_prefix and min_sub <= sub <= max_sub:
                return True
    except (ValueError, IndexError):
        pass
    return False


def parse_version_info(show_version_output):
    """Parse show version output."""
    info = {
        "running_image": "",
        "primary_image": "",
        "backup_image": "",
        "model": "",
        "uptime": "",
        "serial": "",
        "hostname": "",
    }
    for line in show_version_output.split("\n"):
        line = line.strip()
        if "AP Running Image" in line:
            info["running_image"] = line.split(":")[-1].strip()
        elif "Primary Boot Image" in line and "Hash" not in line:
            info["primary_image"] = line.split(":")[-1].strip()
        elif "Backup Boot Image" in line and "Hash" not in line:
            info["backup_image"] = line.split(":")[-1].strip()
        elif "Product/Model Number" in line:
            info["model"] = line.split(":")[-1].strip()
        elif "uptime is" in line:
            info["uptime"] = line.strip()
            parts = line.split(" uptime is")
            if parts:
                info["hostname"] = parts[0].strip()
        elif "Processor board ID" in line:
            info["serial"] = line.split()[-1].strip()
    return info


def parse_boot_partition(show_boot_output):
    """Parse show boot. Returns 'part1', 'part2', or 'unknown'."""
    for line in show_boot_output.split("\n"):
        if "BOOT path-list" in line:
            if "part1" in line:
                return "part1"
            elif "part2" in line:
                return "part2"
    return "unknown"


def get_inactive_partition(boot_partition):
    """Return the inactive (non-boot) partition name."""
    if boot_partition == "part1":
        return "part2"
    elif boot_partition == "part2":
        return "part1"
    return "unknown"


def parse_filesystems(show_filesystems_output):
    """Parse show filesystems. Returns dict {mount: {size_mb, used_mb, avail_mb, use_pct}}."""
    partitions = {}
    for line in show_filesystems_output.split("\n"):
        line = line.strip()
        match = re.match(
            r'(\S+)\s+([\d.]+)([MG])\s+([\d.]+)([MG])\s+([\d.]+)([MG])\s+(\d+)%\s+(\S+)',
            line
        )
        if match:
            mount = match.group(9)
            if "/part" in mount:
                def to_mb(val, unit):
                    v = float(val)
                    return v * 1024 if unit == "G" else v

                partitions[mount] = {
                    "size_mb": to_mb(match.group(2), match.group(3)),
                    "used_mb": to_mb(match.group(4), match.group(5)),
                    "avail_mb": to_mb(match.group(6), match.group(7)),
                    "use_pct": int(match.group(8)),
                }
    return partitions


def parse_cnssdaemon(show_flash_cnssdaemon_output):
    """Check for presence and size of cnssdaemon.log."""
    for line in show_flash_cnssdaemon_output.split("\n"):
        if "cnssdaemon.log" in line:
            size_match = re.search(r'\s(\d+)\s+\w{3}\s+\d+\s+[\d:]+\s+.*cnssdaemon', line)
            if size_match:
                return {"found": True, "size_bytes": int(size_match.group(1))}
            return {"found": True, "size_bytes": -1}
    return {"found": False, "size_bytes": 0}


def parse_image_integrity(show_integrity_output):
    """Parse show image integrity."""
    result = {"supported": True, "partitions": {}}

    if "Invalid input" in show_integrity_output:
        result["supported"] = False
        return result

    current_part = None
    for line in show_integrity_output.split("\n"):
        line = line.strip()
        part_match = re.match(r'/(part\d+)', line)
        if part_match:
            current_part = part_match.group(1)
            result["partitions"][current_part] = {"files": {}, "all_good": True}
        elif current_part and ":" in line:
            fname, _, status = line.partition(":")
            status = status.strip()
            result["partitions"][current_part]["files"][fname.strip()] = status
            if status.lower() != "good":
                result["partitions"][current_part]["all_good"] = False

    return result


def analyze_ap(ap_name, ap_ip, ap_model_from_excel, cmd_results):
    """Full analysis of one AP for CSCwf25731."""
    analysis = {
        "ap_name": ap_name,
        "ap_ip": ap_ip,
        "model": ap_model_from_excel,
        "running_image": "",
        "primary_image": "",
        "backup_image": "",
        "serial": "",
        "boot_partition": "unknown",
        "inactive_partition": "unknown",
        "cnssdaemon_found": False,
        "cnssdaemon_size": 0,
        "cnssdaemon_raw": "",
        "partitions": {},
        "integrity": {},
        "integrity_supported": True,
        "affected_model": False,
        "running_affected": False,
        "primary_affected": False,
        "backup_affected": False,
        "status": "OK",
        "risk_level": "SAFE",
        "recommendation": "",
        "error": None,
    }

    if "__ERROR__" in cmd_results:
        analysis["error"] = cmd_results["__ERROR__"]
        analysis["status"] = "CONNECTION ERROR"
        analysis["risk_level"] = "UNKNOWN"
        analysis["recommendation"] = "Cannot connect - verify manually"
        return analysis

    # Parse show version
    ver_info = parse_version_info(cmd_results.get("show version", ""))
    analysis["running_image"] = ver_info["running_image"]
    analysis["primary_image"] = ver_info["primary_image"]
    analysis["backup_image"] = ver_info["backup_image"]
    analysis["serial"] = ver_info["serial"]
    if ver_info["model"]:
        analysis["model"] = ver_info["model"]

    # If loaded from TXT (name=IP), use hostname from show version
    if analysis["ap_name"] == analysis["ap_ip"] and ver_info["hostname"]:
        analysis["ap_name"] = ver_info["hostname"]

    # Model check
    analysis["affected_model"] = is_affected_model(analysis["model"])

    # Version checks
    analysis["running_affected"] = is_affected_version(analysis["running_image"])
    analysis["primary_affected"] = is_affected_version(analysis["primary_image"])
    analysis["backup_affected"] = is_affected_version(analysis["backup_image"])

    # Boot partition
    analysis["boot_partition"] = parse_boot_partition(cmd_results.get("show boot", ""))
    analysis["inactive_partition"] = get_inactive_partition(analysis["boot_partition"])

    # Filesystems
    analysis["partitions"] = parse_filesystems(cmd_results.get("show filesystems", ""))

    # cnssdaemon.log
    cnssd_raw = cmd_results.get("show flash | i cnssdaemon.log", "")
    cnssd = parse_cnssdaemon(cnssd_raw)
    analysis["cnssdaemon_found"] = cnssd["found"]
    analysis["cnssdaemon_size"] = cnssd["size_bytes"]
    analysis["cnssdaemon_raw"] = cnssd_raw.strip()

    # Image integrity
    integrity = parse_image_integrity(cmd_results.get("show image integrity", ""))
    analysis["integrity_supported"] = integrity["supported"]
    analysis["integrity"] = integrity.get("partitions", {})

    # ============================================================
    # RISK ASSESSMENT (per Cisco documentation)
    # ============================================================

    if not analysis["affected_model"]:
        analysis["status"] = "Model not affected by bug"
        analysis["risk_level"] = "SAFE"
        analysis["recommendation"] = "No action needed"
        return analysis

    any_version_affected = (
        analysis["running_affected"]
        or analysis["primary_affected"]
        or analysis["backup_affected"]
    )

    integrity_failed = False
    if analysis["integrity_supported"]:
        for part_name, part_data in analysis["integrity"].items():
            if not part_data.get("all_good", True):
                integrity_failed = True

    part2_info = analysis["partitions"].get("/part2", {})
    part2_avail = part2_info.get("avail_mb", 999)
    part2_pct = part2_info.get("use_pct", 0)

    part1_info = analysis["partitions"].get("/part1", {})
    part1_avail = part1_info.get("avail_mb", 999)

    if integrity_failed:
        analysis["status"] = "IMAGE INTEGRITY FAILED"
        analysis["risk_level"] = "CRITICAL"
        analysis["recommendation"] = "Option 4: Open TAC case - image integrity check failed"

    elif any_version_affected and analysis["boot_partition"] == "part1" and part2_pct >= 90:
        analysis["status"] = f"AFFECTED - part2 full ({part2_pct}%)"
        analysis["risk_level"] = "CRITICAL"
        analysis["recommendation"] = "Option 1: Partition swap (config boot path 2 + reset) or Option 2: TAC case"

    elif any_version_affected and analysis["cnssdaemon_found"]:
        if analysis["boot_partition"] == "part1":
            analysis["status"] = "AFFECTED - cnssdaemon.log found, boot from part1"
            analysis["risk_level"] = "WARNING"
            analysis["recommendation"] = "Option 1: Partition swap recommended before upgrade"
        else:
            analysis["status"] = "cnssdaemon.log found, boot from part2"
            analysis["risk_level"] = "LOW"
            analysis["recommendation"] = "AP boots from part2 - upgrade should succeed, cleanup APSP recommended"

    elif analysis["backup_affected"] and not analysis["running_affected"]:
        analysis["status"] = "Backup image has affected version"
        analysis["risk_level"] = "LOW"
        analysis["recommendation"] = "Option 3: AP runs fixed version, backup has bug - cleanup APSP recommended"

    elif any_version_affected and (part2_avail < LOW_MEMORY_THRESHOLD_MB or part1_avail < LOW_MEMORY_THRESHOLD_MB):
        analysis["status"] = "Low memory on partition"
        analysis["risk_level"] = "WARNING"
        analysis["recommendation"] = "Option 5: Partition OK but low space (<20MB) - TAC case for cleanup"

    elif any_version_affected:
        analysis["status"] = "Affected version but enough space for now"
        analysis["risk_level"] = "WARNING"
        analysis["recommendation"] = "Run precheck before upgrade, APSP fix recommended"

    else:
        analysis["status"] = "Not affected"
        analysis["risk_level"] = "SAFE"
        analysis["recommendation"] = "No action needed"

    return analysis


# ============================================================
# FORMATTING HELPERS
# ============================================================

SEPARATOR = "=" * 72
CMD_SEP = "-" * 52


def fmt_size(size_bytes):
    """Format size in human-readable format."""
    if size_bytes < 0:
        return "unknown size"
    elif size_bytes >= 1048576:
        return f"{size_bytes / 1048576:.1f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes} B"


def get_partition_summary(analysis, partition_name):
    """Get formatted partition info string for table/details."""
    mount = f"/{partition_name}"
    p = analysis["partitions"].get(mount, {})
    if p:
        return f"{p['use_pct']}% ({p['avail_mb']:.0f}MB free)"
    return "N/A"


# ============================================================
# PLAIN TEXT OUTPUT (for log file)
# ============================================================

def format_analysis_plain(all_analyses):
    """Format CSCwf25731 analysis summary - plain text for log file."""
    lines = []
    lines.append("")
    lines.append(SEPARATOR)
    lines.append("  CSCwf25731 / CSCwf37271 - ACCESS POINT ANALYSIS")
    lines.append(SEPARATOR)
    lines.append("")
    lines.append("  Bug: File /storage/cnssdaemon.log grows up to 5MB/day")
    lines.append("       and can prevent AP upgrade (boot loop during upgrade).")
    lines.append("  Affected versions: 17.12.4.0-212, 17.12.5.0-208, 17.12.6.0-200")
    lines.append("  Affected models:   C9124, C9130, C9136, C9162, C9163, C9164, C9166, IW9167")
    lines.append("  Ref: https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/225443")
    lines.append("")
    lines.append(SEPARATOR)

    total = len(all_analyses)
    critical = sum(1 for a in all_analyses if a["risk_level"] == "CRITICAL")
    warning = sum(1 for a in all_analyses if a["risk_level"] == "WARNING")
    low = sum(1 for a in all_analyses if a["risk_level"] == "LOW")
    safe = sum(1 for a in all_analyses if a["risk_level"] == "SAFE")
    unknown = sum(1 for a in all_analyses if a["risk_level"] == "UNKNOWN")

    lines.append("")
    lines.append(f"  OVERALL SUMMARY:  {total} APs")
    lines.append(f"  [!!!] CRITICAL:   {critical}")
    lines.append(f"  [ ! ] WARNING:    {warning}")
    lines.append(f"  [ ~ ] LOW:        {low}")
    lines.append(f"  [ OK] SAFE:       {safe}")
    if unknown:
        lines.append(f"  [ ? ] UNKNOWN:    {unknown}")
    lines.append("")
    lines.append(SEPARATOR)

    # Table header
    lines.append("")
    hdr = (f"  {'AP Name':<{COL_NAME}} {'IP':<{COL_IP}} {'Model':<{COL_MODEL}} "
           f"{'Running':<{COL_RUNNING}} {'Boot':<{COL_BOOT}} "
           f"{'Active Part':<{COL_APART}} {'Inactive Part':<{COL_IPART}} "
           f"{'cnssd':<{COL_CNSSD}} {'Risk':<{COL_RISK}} Status")
    lines.append(hdr)
    total_width = COL_NAME + COL_IP + COL_MODEL + COL_RUNNING + COL_BOOT + COL_APART + COL_IPART + COL_CNSSD + COL_RISK + 30
    lines.append(f"  {'-' * total_width}")

    for a in all_analyses:
        boot_str = a["boot_partition"].replace("part", "p") if a["boot_partition"] != "unknown" else "?"
        cnssd_str = "YES" if a["cnssdaemon_found"] else "no"

        active_str = get_partition_summary(a, a["boot_partition"])
        inactive_str = get_partition_summary(a, a["inactive_partition"])

        lines.append(
            f"  {a['ap_name']:<{COL_NAME}} {a['ap_ip']:<{COL_IP}} {a['model']:<{COL_MODEL}} "
            f"{a['running_image']:<{COL_RUNNING}} {boot_str:<{COL_BOOT}} "
            f"{active_str:<{COL_APART}} {inactive_str:<{COL_IPART}} "
            f"{cnssd_str:<{COL_CNSSD}} {a['risk_level']:<{COL_RISK}} {a['status']}"
        )

    lines.append("")
    lines.append(SEPARATOR)

    # Details for problem APs
    problem_aps = [a for a in all_analyses if a["risk_level"] not in ("SAFE",)]
    if problem_aps:
        lines.append("")
        lines.append("  PROBLEM AP DETAILS:")
        lines.append(SEPARATOR)

        for a in problem_aps:
            icon = RISK_ICONS.get(a["risk_level"], "")
            lines.append("")
            lines.append(f"  {icon} {a['ap_name']} ({a['ap_ip']})")
            lines.append(f"      Model:              {a['model']}")
            lines.append(f"      Serial:             {a['serial']}")
            lines.append(f"      Running Image:      {a['running_image']}")
            lines.append(f"      Primary Image:      {a['primary_image']}")
            lines.append(f"      Backup Image:       {a['backup_image']}")
            lines.append(f"      Boot Partition:     {a['boot_partition']} (active)")
            lines.append(f"      Inactive Partition: {a['inactive_partition']}")

            # Partition details
            for pname in sorted(a["partitions"]):
                p = a["partitions"][pname]
                label = "(active)" if pname == f"/{a['boot_partition']}" else "(inactive)"
                lines.append(
                    f"      {pname} {label}: {p['used_mb']:.1f}MB / {p['size_mb']:.1f}MB "
                    f"({p['use_pct']}%) - {p['avail_mb']:.1f}MB free"
                )

            # cnssdaemon.log
            if a["cnssdaemon_found"]:
                sz = a["cnssdaemon_size"]
                size_str = f" ({fmt_size(sz)})" if sz != 0 else ""
                lines.append(f"      cnssdaemon.log:     FOUND{size_str}")
                if a["cnssdaemon_raw"]:
                    lines.append(f"      show flash output:  {a['cnssdaemon_raw']}")
            else:
                lines.append(f"      cnssdaemon.log:     not found")

            # Image integrity
            if a["integrity_supported"]:
                for pname in sorted(a["integrity"]):
                    pd = a["integrity"][pname]
                    status = "OK" if pd["all_good"] else "!!! FAILED !!!"
                    lines.append(f"      Image integrity {pname}: {status}")
                    if not pd["all_good"]:
                        for fname, fstatus in pd["files"].items():
                            if fstatus.lower() != "good":
                                lines.append(f"        - {fname}: {fstatus}")
            else:
                lines.append(f"      Image integrity:    not supported on this version")

            if a["error"]:
                lines.append(f"      Error: {a['error']}")

            lines.append(f"      ---> Status:         {a['status']}")
            lines.append(f"      ---> Recommendation: {a['recommendation']}")

        lines.append("")
        lines.append(SEPARATOR)
    else:
        lines.append("")
        lines.append("  No problem APs detected.")
        lines.append(SEPARATOR)

    lines.append("")
    return "\n".join(lines)


# ============================================================
# COLOR CLI OUTPUT
# ============================================================

def print_color_summary(all_analyses):
    """Display colorized analysis summary in CLI."""
    print()
    print(c_bold(SEPARATOR))
    print(c_bold("  CSCwf25731 / CSCwf37271 - ACCESS POINT ANALYSIS"))
    print(c_bold(SEPARATOR))

    total = len(all_analyses)
    critical = sum(1 for a in all_analyses if a["risk_level"] == "CRITICAL")
    warning = sum(1 for a in all_analyses if a["risk_level"] == "WARNING")
    low = sum(1 for a in all_analyses if a["risk_level"] == "LOW")
    safe = sum(1 for a in all_analyses if a["risk_level"] == "SAFE")
    unknown = sum(1 for a in all_analyses if a["risk_level"] == "UNKNOWN")

    print()
    print(f"  OVERALL SUMMARY:  {c_bold(str(total))} APs")
    print(f"  {c_crit('[!!!] CRITICAL:')}   {c_crit(str(critical))}")
    print(f"  {c_warn('[ ! ] WARNING:')}    {c_warn(str(warning))}")
    print(f"  {c_warn('[ ~ ] LOW:')}        {c_warn(str(low))}")
    print(f"  {c_ok('[ OK] SAFE:')}       {c_ok(str(safe))}")
    if unknown:
        print(f"  {c_dim('[ ? ] UNKNOWN:')}    {c_dim(str(unknown))}")

    print()
    print(c_bold(SEPARATOR))
    print()

    # Table
    hdr = (f"  {'AP Name':<{COL_NAME}} {'IP':<{COL_IP}} {'Model':<{COL_MODEL}} "
           f"{'Running':<{COL_RUNNING}} {'Boot':<{COL_BOOT}} "
           f"{'Active Part':<{COL_APART}} {'Inactive Part':<{COL_IPART}} "
           f"{'cnssd':<{COL_CNSSD}} {'Risk':<{COL_RISK}} Status")
    print(c_bold(hdr))
    total_width = COL_NAME + COL_IP + COL_MODEL + COL_RUNNING + COL_BOOT + COL_APART + COL_IPART + COL_CNSSD + COL_RISK + 30
    print(f"  {'-' * total_width}")

    for a in all_analyses:
        boot_str = a["boot_partition"].replace("part", "p") if a["boot_partition"] != "unknown" else "?"
        cnssd_str = "YES" if a["cnssdaemon_found"] else "no"

        color_fn = RISK_COLORS.get(a["risk_level"], c_dim)

        # cnssdaemon coloring
        cnssd_color = c_crit if a["cnssdaemon_found"] else c_ok

        # Active partition
        active_text = get_partition_summary(a, a["boot_partition"])
        active_p = a["partitions"].get(f"/{a['boot_partition']}", {})
        active_pct = active_p.get("use_pct", 0) if active_p else 0
        active_color = c_crit if active_pct >= 90 else (c_warn if active_pct >= 70 else None)

        # Inactive partition
        inactive_text = get_partition_summary(a, a["inactive_partition"])
        inactive_p = a["partitions"].get(f"/{a['inactive_partition']}", {})
        inactive_pct = inactive_p.get("use_pct", 0) if inactive_p else 0
        inactive_color = c_crit if inactive_pct >= 90 else (c_warn if inactive_pct >= 70 else None)

        print(
            f"  {a['ap_name']:<{COL_NAME}} {a['ap_ip']:<{COL_IP}} {a['model']:<{COL_MODEL}} "
            f"{a['running_image']:<{COL_RUNNING}} {boot_str:<{COL_BOOT}} "
            f"{cpad(active_text, COL_APART, active_color)} "
            f"{cpad(inactive_text, COL_IPART, inactive_color)} "
            f"{cpad(cnssd_str, COL_CNSSD, cnssd_color)} "
            f"{cpad(a['risk_level'], COL_RISK, color_fn)} {color_fn(a['status'])}"
        )

    print()
    print(c_bold(SEPARATOR))

    # Problem AP details
    problem_aps = [a for a in all_analyses if a["risk_level"] not in ("SAFE",)]
    if problem_aps:
        print()
        print(c_bold("  PROBLEM AP DETAILS:"))
        print(c_bold(SEPARATOR))

        for a in problem_aps:
            color_fn = RISK_COLORS.get(a["risk_level"], c_dim)
            icon = RISK_ICONS.get(a["risk_level"], "")

            print()
            print(f"  {color_fn(icon)} {c_bold(a['ap_name'])} ({a['ap_ip']})")
            print(f"      Model:              {a['model']}")
            print(f"      Serial:             {a['serial']}")
            print(f"      Running Image:      {a['running_image']}")
            print(f"      Primary Image:      {a['primary_image']}")
            print(f"      Backup Image:       {a['backup_image']}")
            print(f"      Boot Partition:     {a['boot_partition']} (active)")
            print(f"      Inactive Partition: {a['inactive_partition']}")

            # Partition details with color
            for pname in sorted(a["partitions"]):
                p = a["partitions"][pname]
                pct = p["use_pct"]
                avail = p["avail_mb"]
                label = "(active)" if pname == f"/{a['boot_partition']}" else "(inactive)"

                if pct >= 90:
                    pct_c = c_crit(f"{pct}%")
                    avail_c = c_crit(f"{avail:.1f}MB free")
                elif pct >= 70:
                    pct_c = c_warn(f"{pct}%")
                    avail_c = c_warn(f"{avail:.1f}MB free")
                else:
                    pct_c = c_ok(f"{pct}%")
                    avail_c = c_ok(f"{avail:.1f}MB free")

                print(
                    f"      {pname} {label}: {p['used_mb']:.1f}MB / {p['size_mb']:.1f}MB "
                    f"({pct_c}) - {avail_c}"
                )

            # cnssdaemon.log
            if a["cnssdaemon_found"]:
                sz = a["cnssdaemon_size"]
                size_str = f" ({fmt_size(sz)})" if sz != 0 else ""
                print(f"      cnssdaemon.log:     {c_crit('FOUND' + size_str)}")
                if a["cnssdaemon_raw"]:
                    print(f"      show flash output:  {c_warn(a['cnssdaemon_raw'])}")
            else:
                print(f"      cnssdaemon.log:     {c_ok('not found')}")

            # Image integrity
            if a["integrity_supported"]:
                for pname in sorted(a["integrity"]):
                    pd = a["integrity"][pname]
                    if pd["all_good"]:
                        print(f"      Image integrity {pname}: {c_ok('OK')}")
                    else:
                        print(f"      Image integrity {pname}: {c_crit('!!! FAILED !!!')}")
                        for fname, fstatus in pd["files"].items():
                            if fstatus.lower() != "good":
                                print(f"        - {fname}: {c_crit(fstatus)}")
            else:
                print(f"      Image integrity:    {c_dim('not supported on this version')}")

            if a["error"]:
                print(f"      Error: {c_err(a['error'])}")

            print(f"      ---> Status:         {color_fn(a['status'])}")
            print(f"      ---> Recommendation: {c_info(a['recommendation'])}")

        print()
        print(c_bold(SEPARATOR))
    else:
        print()
        print(c_ok("  No problem APs detected."))
        print(c_bold(SEPARATOR))

    print()


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="AP SSH Command Collector + CSCwf25731 Analyzer",
        epilog="Supported formats: .xlsx (Excel with AP Name, IP, Model columns) and .txt (one IP per line)"
    )
    parser.add_argument("input_file", help="Path to .xlsx or .txt file with AP list")
    args = parser.parse_args()

    print(c_bold(SEPARATOR))
    print(c_bold("  AP SSH Command Collector + CSCwf25731 Analyzer"))
    print(c_bold(SEPARATOR))

    input_path = args.input_file
    if not os.path.isfile(input_path):
        print(c_err(f"\n[ERROR] File '{input_path}' not found!"))
        sys.exit(1)

    ext = os.path.splitext(input_path)[1].lower()
    print(f"\n  Input file: {c_info(os.path.basename(input_path))} ({ext})")

    ap_list = read_ap_list(input_path, SHEET_NAME)
    print(f"  {c_ok('Loaded')} {c_bold(str(len(ap_list)))} access points")

    if not ap_list:
        print(c_err("[ERROR] No APs found!"))
        sys.exit(1)

    # Credentials
    print()
    username = input("  SSH username: ").strip()
    password = getpass.getpass("  SSH password: ")
    enable_password = getpass.getpass("  Enable password: ")

    if not username or not password or not enable_password:
        print(c_err("[ERROR] Username, password and enable password are all required!"))
        sys.exit(1)

    # Output file
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = OUTPUT_FILE or f"ap_log_{timestamp}.txt"

    print(f"\n  Output:   {c_info(output_file)}")
    print(f"  Commands: {c_bold(str(len(COMMANDS)))}")
    print(f"\n  {c_bold('Starting scan of')} {c_bold(str(len(ap_list)))} APs...\n")

    success_count = 0
    fail_count = 0
    all_analyses = []

    with open(output_file, "w", encoding="utf-8") as f:
        # Log header
        f.write(SEPARATOR + "\n")
        f.write(f"  AP SSH Command Collector + CSCwf25731 Analyzer\n")
        f.write(f"  Date:   {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Source: {os.path.basename(input_path)}\n")
        f.write(f"  APs:    {len(ap_list)}\n")
        f.write(f"  User:   {username}\n")
        f.write(SEPARATOR + "\n\n")

        for idx, (ap_name, ip, model) in enumerate(ap_list, 1):
            progress = f"[{idx}/{len(ap_list)}]"
            print(f"  {c_dim(progress)} {c_bold(ap_name)} ({ip}) ... ", end="", flush=True)

            f.write(SEPARATOR + "\n")
            f.write(f"  AP:    {ap_name}\n")
            f.write(f"  IP:    {ip}\n")
            f.write(f"  Model: {model}\n")
            f.write(f"  Time:  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(SEPARATOR + "\n\n")

            results = ssh_run_commands(ip, username, password, enable_password, COMMANDS)

            if "__ERROR__" in results:
                error_msg = results["__ERROR__"]
                print(c_err(f"ERROR: {error_msg}"))
                f.write(f"  !!! CONNECTION ERROR: {error_msg}\n\n")
                fail_count += 1
            else:
                print(c_ok("OK"))
                success_count += 1
                for cmd in COMMANDS:
                    output = results.get(cmd, "(no output)")
                    f.write(f">>> {cmd}\n")
                    f.write(CMD_SEP + "\n")
                    f.write(output.strip() + "\n")
                    f.write(CMD_SEP + "\n\n")

            # Analyze AP
            analysis = analyze_ap(ap_name, ip, model, results)
            all_analyses.append(analysis)

            # Update AP name in log if resolved from show version (TXT input)
            if ap_name == ip and analysis["ap_name"] != ip:
                f.write(f"  [Resolved AP name: {analysis['ap_name']}]\n")

            # Quick status in CLI
            color_fn = RISK_COLORS.get(analysis["risk_level"], c_dim)
            icon = RISK_ICONS.get(analysis["risk_level"], "")
            if analysis["risk_level"] not in ("SAFE",):
                print(f"         {color_fn(icon + ' ' + analysis['status'])}")

            f.write("\n")

        # ============================================================
        # SUMMARY + ANALYSIS AT END OF LOG
        # ============================================================
        f.write(SEPARATOR + "\n")
        f.write(f"  CONNECTION SUMMARY\n")
        f.write(f"  Total APs: {len(ap_list)}\n")
        f.write(f"  Success:   {success_count}\n")
        f.write(f"  Failed:    {fail_count}\n")
        f.write(f"  Completed: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(SEPARATOR + "\n")

        # Plain text analysis to log
        plain_summary = format_analysis_plain(all_analyses)
        f.write(plain_summary)

    # Color analysis to CLI
    print_color_summary(all_analyses)

    print(f"  {c_bold('DONE!')} Success: {c_ok(str(success_count))} | Failed: {c_err(str(fail_count))}")
    print(f"  Log saved: {c_info(output_file)}\n")


if __name__ == "__main__":
    main()
