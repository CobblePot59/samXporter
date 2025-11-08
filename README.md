# samXporter

samXporter is a Python script that automates the extraction of Windows registry security hives (SAM, SYSTEM, and SECURITY) required for offline credential recovery. It handles the necessary privilege elevation and Windows API calls to backup them.

## Requirements

- Windows operating system
- Python 3.6+
- Administrator privileges (required for hive extraction)

## Installation

1. Clone or download the script:
```bash
git clone <repository>
cd samXporter
```

2. No additional dependencies required (uses only Python standard library)

## Usage

Run the script with administrator privileges:

```bash
python samXporter.py
```

### Output

```
Registry_Backup/
├── SAM
├── SYSTEM
└── SECURITY
```

## Extracting Credentials

Once you have the backed-up hives, use `impacket-secretsdump` to extract credentials:

```bash
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

## Logging

The script uses Python's logging module with the following levels:

- **DEBUG** - Detailed operational information, errors, and API calls
- **INFO** - Successfully saved registry hives with file paths and sizes

Example output:
```
DEBUG: Registry Hives Backup Script started
DEBUG: Admin privileges detected
DEBUG: SeBackupPrivilege enabled successfully
INFO: Saved HKLM\SAM to C:\path\Registry_Backup\SAM (123456 bytes)
INFO: Saved HKLM\SYSTEM to C:\path\Registry_Backup\SYSTEM (654321 bytes)
INFO: Saved HKLM\SECURITY to C:\path\Registry_Backup\SECURITY (98765 bytes)
DEBUG: Backup completed successfully
```

## Disclaimer

This script interacts with sensitive system files. Use responsibly and only in environments where you have authorization. Unauthorized access to computer systems may be illegal.