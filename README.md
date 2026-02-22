# AP SSH Collector + CSCwf25731 Analyzer

A Python tool that connects to Cisco Catalyst Access Points via SSH, collects diagnostic data, and automatically analyzes each AP for susceptibility to **Cisco bug [CSCwf25731](https://www.cisco.com/c/en/us/support/docs/wireless/catalyst-9800-series-wireless-controllers/225443-validate-and-recover-catalyst-aps-on-17-1.html)** / **CSCwf37271** — a known issue where the file `/storage/cnssdaemon.log` grows up to 5 MB/day, exhausts partition space, and causes APs to enter a boot loop during upgrade.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

## The Problem

Access Points running IOS-XE versions **17.12.4 through 17.12.6a** can accumulate a persistent log file (`cnssdaemon.log`) that fills the flash partition. When an upgrade is attempted, the AP fails to write the new image and enters a boot loop. The issue affects these AP models:

- Catalyst 9124 (I/D/E)
- Catalyst 9130 (I/E)
- Catalyst 9136I
- Catalyst 9162I
- Catalyst 9163E
- Catalyst 9164I
- Catalyst 9166 (I/D1)
- Catalyst IW9167 (I/E)

This tool automates the pre-check procedure recommended by Cisco, scanning all your APs in bulk and producing a clear risk assessment.

## Features

- **Bulk SSH collection** — connects to all APs from an Excel or text file, runs diagnostic commands, and saves full output
- **Automatic risk analysis** — classifies each AP as `SAFE`, `LOW`, `WARNING`, or `CRITICAL` based on Cisco's recovery documentation
- **Colored CLI output** — instant visual overview with color-coded risk levels, partition usage, and `cnssdaemon.log` detection (Windows 10+ compatible via colorama)
- **Detailed log file** — complete command output from every AP plus a summary analysis table at the end
- **Dual input format** — supports `.xlsx` exports from Cisco WLC and simple `.txt` files with one IP per line
- **AP hostname auto-detection** — when using a TXT input file, AP names are automatically resolved from `show version` output

## Installation

```bash
pip install openpyxl paramiko colorama
```

> The script will auto-install missing dependencies on first run.

## Usage

### From Excel (WLC export)

Export your AP list from the Cisco 9800 WLC (Monitor > Access Points) and run:

```bash
python ap_ssh_collector_CSCwf25731.py ap_statistics.xlsx
```

The script reads columns: **A** (AP Name), **B** (AP Model), **D** (IP Address). Column mapping can be changed in the configuration section.

### From text file

Create a text file with one AP IP address per line:

```text
# Site A - Building 1
10.10.1.101
10.10.1.102
10.10.1.103

# Site A - Building 2
10.10.2.101
```

Lines starting with `#` are treated as comments. Then run:

```bash
python ap_ssh_collector_CSCwf25731.py ap_ips.txt
```

### Authentication

The script prompts for three credentials:

```
SSH username: admin
SSH password: ****
Enable password: ****
```

The SSH session flow matches standard Cisco AP access: login → `en` → enable password → privileged EXEC mode.

## Commands Executed

The following commands are run on each AP:

| Command | Purpose |
|---|---|
| `show clock` | Verify AP time |
| `show version` | Running/primary/backup image versions, model, serial |
| `show flash` | Flash storage contents |
| `show flash \| i cnssdaemon.log` | Check for the problematic log file |
| `show boot` | Active boot partition (part1/part2) |
| `show filesystems` | Partition usage and free space |
| `show image integrity` | Image integrity check for both partitions |

## Output

### CLI (colored)

```
  AP Name                    IP                Model          Running        Boot   Active Part          Inactive Part        cnssd  Risk       Status
  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  SITE-B1-FL1-AP01           10.10.1.101       C9120AXI-E     17.3.4.40      p2     12% (456MB free)     17% (310MB free)     no     SAFE       Model not affected by bug
  SITE-B1-FL2-AP03           10.10.1.102       C9130AXI-E     17.12.5.41     p1     21% (294MB free)     98% (10MB free)      YES    CRITICAL   AFFECTED - part2 full (98%)
```

Problem APs get detailed breakdowns with partition info, `cnssdaemon.log` size, image integrity status, and a specific recovery recommendation.

### Log file

A timestamped log file `ap_log_YYYYMMDD_HHMMSS.txt` is generated with:

1. **Full command output** from every AP (for reference and TAC cases)
2. **Summary table** with all APs and their risk levels
3. **Detailed analysis** of problem APs with recovery recommendations

## Risk Levels

| Level | Meaning | Action |
|---|---|---|
| `SAFE` | AP model not affected, or no affected version detected | No action needed |
| `LOW` | Backup image has bug but AP runs from safe partition, or `cnssdaemon.log` present but boots from part2 | Cleanup APSP recommended |
| `WARNING` | Affected version detected, `cnssdaemon.log` found with boot from part1, or low free space | Partition swap or APSP fix before upgrade |
| `CRITICAL` | Inactive partition full (≥90%), or image integrity check failed | Immediate action required — partition swap, TAC case, or recovery |

## Recovery Options

The tool maps each problem AP to the appropriate Cisco recovery option:

| Option | Condition | Recovery |
|---|---|---|
| **Option 1** | Boot from part1, part2 full | Partition swap: `config boot path 2` → `reset` |
| **Option 2** | Cannot perform Option 1 | Open TAC case for root shell cleanup |
| **Option 3** | Running fixed version, backup has bug | Install cleanup APSP |
| **Option 4** | Image integrity check failed | Open TAC case |
| **Option 5** | Partition OK but free space < 20 MB | Open TAC case to remove `cnssdaemon.log` via devshell |

## Configuration

All settings are in the `CONFIGURATION` section at the top of the script:

```python
# Excel column mapping (1-indexed)
AP_NAME_COL = 1    # column A
IP_ADDR_COL = 4    # column D
AP_MODEL_COL = 2   # column B

# SSH settings
SSH_PORT = 22
SSH_TIMEOUT = 15       # connection timeout (seconds)
CMD_TIMEOUT = 15       # per-command timeout (seconds)
CMD_TIMEOUT_LONG = 60  # timeout for slow commands

# Customizable command list
COMMANDS = [
    "show clock",
    "show version",
    ...
]
```

## Requirements

- Python 3.8+
- Network access to AP management IPs (SSH port 22)
- AP SSH credentials + enable password
- Tested on Windows 10/11 and Linux

## References

- [Cisco: Validate and Recover Catalyst APs on 17.12 Impacted by Upgrade Failure](https://www.cisco.com/c/en/us/support/docs/wireless/wireless-lan-controller-software/225443-validate-and-recover-catalyst-aps-on.html)
- Cisco Bug IDs: [CSCwf25731](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf25731), [CSCwf37271](https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf37271)

## License

MIT
