#!/usr/bin/env python3
"""
phpMyAdmin Login Scanner
=========================
Extended scanner with verbose logging for phpMyAdmin login pages.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.logging import RichHandler

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# Extended markers for login forms
_LOGIN_MARKERS_RE = re.compile(
    r"pma_username|pma_password|auth\[username]|auth\[password]|server_select|"
    r"phpMyAdmin|PMA_token|pma_servername|input_username|input_password|"
    r"mysql-admin|adminer|MariaDB administration|type=\"password\"|"
    r"name=\"password\"|id=\"password\"|login_form|loginform|login-form|"
    r"<form|method=\"post\"",
    re.IGNORECASE,
)

_PATHS = [
    "adminer.{domain}",
    "pma.{domain}",
    "db.{domain}",
    "dbadmin.{domain}",
    "sql.{domain}",
    "mysql.{domain}",
    "mysqlmanager.{domain}",
    "mariadb.{domain}",
    "phpmyadmin.{domain}",
    "{domain}/admin/phpmyadmin/",
    "{domain}/phpmyadmin/",
    "{domain}/phpMyAdmin/",
    "{domain}/phpmyadmin/index.php",
    "{domain}/phpMyAdmin/index.php",
    "{domain}/adminer.php",
    "{domain}/adminer/",
    "{domain}/phpMyAdmin.php",
    "{domain}/phpmyadmin.php",
    "{domain}/pma.php",
    "{domain}/PMA/",
    "{domain}/pma/",
    "{domain}/myadmin/",
    "{domain}/database/",
    "{domain}/db/phpmyadmin/",
    "{domain}/sqlmanager/",
    "{domain}/mysqlmanager/",
    "{domain}/php-myadmin/",
    "{domain}/phpmy/",
    "{domain}/mysqladmin/",
    "{domain}/mysql-admin/",
    "{domain}/admin/mysql/",
    "{domain}/admin/mysql/index.php",
    "{domain}/admin/pma/",
    "{domain}/admin/db/",
    "{domain}/admin/adminer.php",
    "{domain}/mysql/db/",
    "{domain}/mysql/pma/",
    "{domain}/sql/myadmin/",
    "{domain}/sql/php-myadmin/",
    "{domain}/sql/phpMyAdmin/",
    "{domain}/sql/phpmyadmin/",
    "{domain}/db/myadmin/",
    "{domain}/db/phpMyAdmin/",
    "{domain}/db/phpmyadmin/",
]


def _setup_logging(debug: bool = False) -> logging.Logger:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )
    return logging.getLogger("pma_scanner")


class LoginScanner:
    def __init__(
        self,
        urls: list[str],
        threads: int = 20,
        timeout: int = 10,
        output: Path | None = None,
        debug: bool = False,
    ):
        self.urls = urls
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.logger = _setup_logging(debug)
        self._session = requests.Session()
        self._session.headers.update(
            {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        self._found: list[str] = []

    @staticmethod
    def _normalize(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url

    def _build_targets(self, url: str) -> list[str]:
        domain = urlparse(self._normalize(url)).netloc
        targets: list[str] = []
        for path in _PATHS:
            full = path.format(domain=domain)
            if not full.startswith(("http://", "https://")):
                full = "http://" + full
            targets.append(full)
        return targets

    def _check(self, target: str) -> str | None:
        try:
            resp = self._session.get(
                target, timeout=self.timeout, verify=False, allow_redirects=True
            )
            if resp.status_code == 200 and _LOGIN_MARKERS_RE.search(resp.text):
                return target
        except requests.RequestException as exc:
            self.logger.debug(f"Request failed: {target} — {exc}")
        return None

    def _scan_one(self, url: str) -> list[str]:
        self.logger.info(f"Scanning {url}")
        found: list[str] = []
        for target in self._build_targets(url):
            if result := self._check(target):
                self.logger.warning(f"Found: {result}")
                found.append(result)
                if self.output:
                    with self.output.open("a", encoding="utf-8") as fh:
                        fh.write(result + "\n")
        return found

    def run(self) -> list[str]:
        self.logger.info(
            f"Starting scan: {len(self.urls)} URL(s), {self.threads} threads"
        )
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_one, u): u for u in self.urls}
            for future in as_completed(futures):
                self._found.extend(future.result())
        self.logger.info(f"Complete. Found {len(self._found)} login page(s).")
        return self._found


def load_urls(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="phpMyAdmin Login Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -u https://example.com -v
  %(prog)s -f targets.txt -t 50 -o found.txt -d
        """,
    )
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-f", "--file", type=Path, help="File containing target URLs")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("-o", "--output", type=Path, help="Output file")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    urls: list[str] = []
    if args.url:
        urls = [args.url]
    elif args.file:
        urls = load_urls(args.file)
    else:
        parser.print_help()
        sys.exit(1)

    scanner = LoginScanner(
        urls=urls,
        threads=args.threads,
        timeout=args.timeout,
        output=args.output,
        debug=args.debug,
    )
    found = scanner.run()
    console.print(f"\n[green]Found {len(found)} login page(s)[/green]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        sys.exit(130)
