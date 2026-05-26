# phpMyAdmin Finder

Fast concurrent scanner to find exposed phpMyAdmin and Adminer panels.

## Features

- `main.py` — Lightweight finder with compiled regex and rich output
- `main-v2.py` — Extended login scanner with verbose rich logging
- `ThreadPoolExecutor` for concurrent I/O-bound scanning
- Pre-compiled regex markers for fast body matching
- Session reuse for connection pooling

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Finder (main.py)

```bash
python main.py -u https://example.com
python main.py -f targets.txt -t 50 -o found.txt
```

### Login Scanner (main-v2.py)

```bash
python main-v2.py -u https://example.com -d
python main-v2.py -f targets.txt -t 50 -o found.txt
```

## Options

| Flag | Description |
|------|-------------|
| `-u, --url` | Single URL to scan |
| `-f, --file` | File containing target URLs |
| `-t, --threads` | Concurrent threads (default: 20) |
| `--timeout` | Request timeout in seconds (default: 10) |
| `-o, --output` | Output file for results |
| `-d, --debug` | Enable debug logging (v2 only) |

## Disclaimer

This tool is intended for authorized security testing only.
