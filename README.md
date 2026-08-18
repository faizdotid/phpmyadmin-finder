# phpMyAdmin Finder

Fast concurrent scanner to find exposed phpMyAdmin and Adminer panels. Written in Go (standard library only).

## Features

- Single binary — default = finder mode, `-d` = verbose/debug logging
- Goroutine worker pool for fast I/O-bound scanning
- Pre-compiled regex markers, response body capped at 1 MiB
- Preserves input scheme (http/https), blocks cross-host redirects
- Deduplicates input URLs (normalizes scheme and default port)

## Build

```bash
go build -o phpmyadmin-finder .
```

## Usage

```bash
go run . -u https://example.com
go run . -u https://example.com -d
go run . -f targets.txt -t 50 -o found.txt
```

`-u` is repeatable; `-f` loads one URL per line (blank lines and `#` comments are skipped).

## Options

| Flag | Description |
|------|-------------|
| `-u, --url` | Single URL to scan (repeatable) |
| `-f, --file` | File containing target URLs |
| `-t, --threads` | Concurrent workers (default: 20) |
| `--timeout` | Request timeout in seconds (default: 10) |
| `-o, --output` | Output file for results |
| `-d, --debug` | Enable debug logging |

## Disclaimer

This tool is intended for authorized security testing only.
