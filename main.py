import requests
import argparse
from typing import List
from urllib.parse import urlparse
import warnings
import socket
import concurrent.futures
import time
import sys

# Mematikan peringatan SSL
warnings.filterwarnings(
    "ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning
)


class PhpMyAdminFinder:
    php_my_admin_paths: List[str] = [
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
        # Additional common paths
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

    php_myadmin_marker: List[str] = [
        "pma_username",
        "pma_password",
        "auth[username]",
        "auth[password]",
        "server_select",
        "phpMyAdmin",
        "PMA_token",
        "pma_servername",
        "input_username",
        "input_password",
        "mysql-admin",
        "adminer",
        "MariaDB administration",
    ]

    def __init__(
        self, urls: List[str], threads: int, timeout: int = 10, output_file: str = None
    ):
        """
        Initialize the PhpMyAdminFinder instance.
        Args:
            urls (List[str]): List of URLs to scan for phpMyAdmin.
            threads (int): Number of processes for concurrent scanning.
            timeout (int): Timeout for HTTP requests.
            output_file (str): Output file to save results.
        """
        self.urls = urls
        self.threads = threads
        self.timeout = timeout
        self.output_file = output_file
        self.results = []  # Untuk menyimpan hasil
        self.found_count = 0

    def check_phpmyadmin(self, url: str):
        """
        Check if phpMyAdmin is accessible at the given URL.
        Args:
            url (str): The target URL to check.
        Returns:
            List[str]: The found phpMyAdmin URLs
        """
        found_urls = []

        # Validasi URL
        if not url:
            return found_urls

        # Pastikan URL memiliki skema
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        # Ekstrak domain
        try:
            domain = urlparse(url).netloc
        except Exception as e:
            print(f"Error parsing URL {url}: {e}")
            return found_urls

        for path in self.php_my_admin_paths:
            try:
                # Format path dengan domain
                full_url = path.format(domain=domain)

                # Pastikan URL memiliki skema jika diperlukan
                if not full_url.startswith(("http://", "https://")):
                    full_url = "http://" + full_url

                response = requests.get(
                    full_url,
                    timeout=self.timeout,
                    verify=False,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
                    },
                    allow_redirects=True,
                )

                if response.status_code == 200 and any(
                    marker in response.text for marker in self.php_myadmin_marker
                ):
                    print(f"[+] phpMyAdmin found at: {full_url}")
                    found_urls.append(full_url)

                    # Simpan hasil jika output_file ditentukan
                    if self.output_file:
                        with open(self.output_file, "a") as f:
                            f.write(full_url + "\n")

            except requests.RequestException:
                # Proses tetap berlanjut meskipun ada kesalahan
                continue
            except Exception as e:
                # Tangani kesalahan tak terduga
                print(f"Unexpected error checking {url}: {e}")
                continue

        return found_urls

    def start(self):
        """
        Start the phpMyAdmin finder with multiprocessing.
        """
        print(f"Starting scan with {self.threads} processes...")

        start_time = time.time()

        # Gunakan ProcessPoolExecutor untuk lebih baik menangani hasil
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=self.threads
        ) as executor:
            # Submit semua tugas dan dapatkan futures
            futures = {
                executor.submit(self.check_phpmyadmin, url): url for url in self.urls
            }

            # Proses hasil saat tersedia
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                try:
                    found_urls = future.result()
                    if found_urls:
                        self.results.extend(found_urls)
                        self.found_count += len(found_urls)
                except Exception as e:
                    print(f"Error processing {url}: {e}")

        end_time = time.time()
        elapsed_time = end_time - start_time

        print(f"Scan completed in {elapsed_time:.2f} seconds.")
        print(
            f"Found {self.found_count} phpMyAdmin installations across {len(self.urls)} target URLs."
        )

        return self.results

    @staticmethod
    def validate_url(url: str) -> str:
        """
        Validate and normalize a URL.
        Args:
            url (str): The URL to validate.
        Returns:
            str: Normalized URL or empty string if invalid.
        """
        if not url:
            return ""

        # Tambahkan skema jika tidak ada
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            result = urlparse(url)
            if not result.netloc:
                return ""
            return url
        except Exception:
            return ""

    @staticmethod
    def do_reverse_ip_lookup(url: str) -> List[str]:
        """
        Perform reverse IP lookup to find other websites on the same server.
        Args:
            url (str): The target URL to perform reverse IP lookup on.
        Returns:
            List[str]: A list of websites on the same server.
        """
        # Validasi URL
        url = PhpMyAdminFinder.validate_url(url)
        if not url:
            return []

        try:
            # Ekstrak domain
            domain = urlparse(url).netloc

            # Dapatkan alamat IP
            ip = socket.gethostbyname(domain)
            print(f"[*] IP address for {domain}: {ip}")

            # Di sini seharusnya ada kode untuk reverse IP lookup
            # Biasanya menggunakan API eksternal atau layanan DNS
            # Contoh placeholder:
            print(f"[*] Performing reverse IP lookup for {ip}...")

            # Return placeholder, ganti dengan implementasi sebenarnya
            return []
        except Exception as e:
            print(f"Error performing reverse IP lookup for {url}: {e}")
            return []


def read_urls_from_file(file_path: str) -> List[str]:
    """
    Read URLs from a file, one URL per line.
    Args:
        file_path (str): Path to the file containing URLs.
    Returns:
        List[str]: List of URLs.
    """
    urls = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
        return urls
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []


def main():
    # Banner
    print("""
    +---------------------------------------------------+
    |                 phpMyAdmin Finder                 |
    |                                                   |
    | Scan websites for phpMyAdmin installations        |
    +---------------------------------------------------+
    """)

    parser = argparse.ArgumentParser(
        description="phpMyAdmin Finder - Tool to scan websites for phpMyAdmin installations",
        prog="phpmyadmin_finder",
        epilog="Example: python phpmyadmin_finder.py -u https://example.com -r",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    # Create a group for required arguments
    required_group = parser.add_argument_group("required arguments (one of -u or -f)")
    group = required_group.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "-u",
        "--url",
        help="URL to scan for phpMyAdmin",
        metavar="URL",
        dest="target_url",
    )

    group.add_argument(
        "-f",
        "--file",
        help="File containing URLs to scan for phpMyAdmin (one URL per line)",
        metavar="FILE",
        type=str,
        dest="url_file",
    )

    parser.add_argument(
        "-r",
        "--reverse",
        help="Perform reverse IP lookup to find other websites on the same server",
        action="store_true",
        dest="reverse_ip",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        help="Request timeout in seconds",
        type=int,
        default=10,
        metavar="SECONDS",
        dest="timeout",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output file to save results",
        metavar="OUTPUT_FILE",
        dest="output_file",
    )

    parser.add_argument(
        "--threads",
        help="Number of processes for concurrent scanning",
        type=int,
        default=5,
        metavar="NUM",
        dest="threads",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        help="Enable verbose output",
        action="store_true",
        dest="verbose",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0",
    )

    args = parser.parse_args()

    # Initialize URLs list
    urls = []

    # Handle single URL input
    if args.target_url:
        target_url = PhpMyAdminFinder.validate_url(args.target_url)
        if not target_url:
            parser.error(f"Invalid URL: {args.target_url}")

        urls.append(target_url)

        # Handle reverse IP lookup if requested
        if args.reverse_ip:
            print("Performing reverse IP lookup...")
            related_urls = PhpMyAdminFinder.do_reverse_ip_lookup(target_url)
            if related_urls:
                urls.extend(related_urls)
                print(f"Found {len(related_urls)} related websites.")
            else:
                print("No additional websites found.")

    # Handle file input
    elif args.url_file:
        if args.reverse_ip:
            parser.error("You cannot use -f/--file with -r/--reverse at the same time")

        file_urls = read_urls_from_file(args.url_file)
        if not file_urls:
            parser.error(f"No valid URLs found in file: {args.url_file}")

        # Validate all URLs
        for url in file_urls:
            valid_url = PhpMyAdminFinder.validate_url(url)
            if valid_url:
                urls.append(valid_url)
            elif args.verbose:
                print(f"Skipping invalid URL: {url}")

    # Final check
    if not urls:
        parser.error("No valid URLs provided for scanning")

    # Remove duplicates
    urls = list(set(urls))
    print(f"Scanning {len(urls)} URLs for phpMyAdmin installations...")

    # Create and start the scanner
    finder = PhpMyAdminFinder(
        urls=urls,
        threads=args.threads,
        timeout=args.timeout,
        output_file=args.output_file,
    )

    results = finder.start()

    if results:
        print("\nFound phpMyAdmin installations:")
        for url in results:
            print(f"  - {url}")

        if args.output_file:
            print(f"\nResults saved to: {args.output_file}")
    else:
        print("\nNo phpMyAdmin installations found.")

    print("\nphpMyAdmin Finder - Scan completed.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
