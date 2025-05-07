import requests
import argparse
from typing import List
from urllib.parse import urlparse
import warnings
import socket
import concurrent.futures
import time
import sys
import logging

# Mematikan peringatan SSL
warnings.filterwarnings(
    "ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning
)


# Setup logging
logger = logging.getLogger("PhpMyAdminLoginScanner")

class LoggerSetup:
    @staticmethod
    def setup_logging(level=logging.INFO, debug=False):
        """
        Set up logging configuration.
        
        Args:
            level (int): Logging level, default is INFO
            debug (bool): Whether to enable debug mode
        """
        if debug:
            level = logging.DEBUG
        
        # Configure logger
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        date_format = '%Y-%m-%d %H:%M:%S'
        
        # Clear any existing handlers
        root = logging.getLogger()
        if root.handlers:
            for handler in root.handlers:
                root.removeHandler(handler)
                
        # Configure logging
        logging.basicConfig(
            level=level,
            format=log_format,
            datefmt=date_format,
        )
        
        # Create console handler
        console = logging.StreamHandler()
        console.setLevel(level)
        formatter = logging.Formatter(log_format)
        console.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(console)
        logger.setLevel(level)
        
        if debug:
            logger.debug("Debug logging enabled")


class PhpMyAdminLoginScanner:
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

    # Marker untuk halaman login
    login_markers: List[str] = [
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
        "type=\"password\"",
        "name=\"password\"",
        "id=\"password\"",
        "login_form",
        "loginform",
        "login-form",
        "<form",
        "method=\"post\"",
    ]

    def __init__(
        self, urls: List[str], threads: int, timeout: int = 10, output_file: str = None, verbose: bool = False, debug: bool = False
    ):
        """
        Initialize the PhpMyAdminLoginScanner instance.
        Args:
            urls (List[str]): List of URLs to scan for phpMyAdmin login pages.
            threads (int): Number of processes for concurrent scanning.
            timeout (int): Timeout for HTTP requests.
            output_file (str): Output file to save results.
            verbose (bool): Enable verbose output.
            debug (bool): Enable debug output (more detailed than verbose).
        """
        """
        Initialize the PhpMyAdminLoginScanner instance.
        Args:
            urls (List[str]): List of URLs to scan for phpMyAdmin login pages.
            threads (int): Number of processes for concurrent scanning.
            timeout (int): Timeout for HTTP requests.
            output_file (str): Output file to save results.
            verbose (bool): Enable verbose output.
        """
        self.urls = urls
        self.threads = threads
        self.timeout = timeout
        self.output_file = output_file
        self.verbose = verbose
        self.debug = debug
        self.results = []  # Untuk menyimpan hasil
        self.found_count = 0
        
        # Configure logging based on verbose and debug settings
        log_level = logging.WARNING
        if self.verbose:
            log_level = logging.INFO
        if self.debug:
            log_level = logging.DEBUG
            
        LoggerSetup.setup_logging(level=log_level, debug=self.debug)

    def check_login_page(self, url: str):
        """
        Check if phpMyAdmin login page is accessible at the given URL.
        Args:
            url (str): The target URL to check.
        Returns:
            List[str]: The found phpMyAdmin login page URLs
        """
        found_urls = []

        # Validasi URL
        if not url:
            logger.debug(f"Empty URL provided")
            return found_urls

        # Pastikan URL memiliki skema
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
            logger.debug(f"Added HTTP scheme to URL: {url}")

        # Ekstrak domain
        try:
            domain = urlparse(url).netloc
            logger.info(f"Extracting domain from {url}: {domain}")
            logger.debug(f"Full parsed URL: {urlparse(url)}")
        except Exception as e:
            logger.error(f"Error parsing URL {url}: {e}")
            return found_urls

        for path in self.php_my_admin_paths:
            try:
                # Format path dengan domain
                full_url = path.format(domain=domain)

                # Pastikan URL memiliki skema jika diperlukan
                if not full_url.startswith(("http://", "https://")):
                    full_url = "http://" + full_url
                    logger.debug(f"Added HTTP scheme to path: {full_url}")

                logger.info(f"Scanning: {full_url}")
                
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
                }
                logger.debug(f"Request headers: {headers}")
                
                logger.debug(f"Sending GET request to {full_url} with timeout={self.timeout}")
                response = requests.get(
                    full_url,
                    timeout=self.timeout,
                    verify=False,
                    headers=headers,
                    allow_redirects=True,
                )

                # Cek status code dan response
                logger.debug(f"Response status code: {response.status_code}")
                logger.debug(f"Response headers: {response.headers}")
                
                if response.status_code == 200:
                    logger.info(f"Got 200 response from {full_url}, checking content...")
                    
                    # Log a small sample of response text for debugging
                    if self.debug:
                        content_sample = response.text[:500] + ("..." if len(response.text) > 500 else "")
                        logger.debug(f"Response content sample: {content_sample}")
                    
                    markers_found = [marker for marker in self.login_markers if marker in response.text]
                    logger.debug(f"Markers found: {markers_found}")
                    
                    if markers_found:
                        logger.warning(f"phpMyAdmin login page found at: {full_url}")
                        logger.info(f"Login markers found: {', '.join(markers_found[:3])}{'...' if len(markers_found) > 3 else ''}")
                        
                        found_urls.append(full_url)

                        # Simpan hasil jika output_file ditentukan
                        if self.output_file:
                            logger.info(f"Saving result to {self.output_file}")
                            with open(self.output_file, "a") as f:
                                f.write(full_url + "\n")
                    else:
                        logger.info(f"No login markers found at {full_url}")
                else:
                    logger.info(f"Got status code {response.status_code} from {full_url}")

            except requests.RequestException as e:
                # Proses tetap berlanjut meskipun ada kesalahan
                logger.info(f"Request error for {full_url}: {e}")
                logger.debug(f"Request exception details: {type(e).__name__}: {str(e)}")
                continue
            except Exception as e:
                # Tangani kesalahan tak terduga
                logger.error(f"Unexpected error checking {full_url}: {e}")
                logger.debug(f"Exception traceback:", exc_info=True)
                continue

        return found_urls

    def start(self):
        """
        Start the phpMyAdmin login scanner with multiprocessing.
        """
        logger.warning(f"Starting login page scan with {self.threads} processes...")
        logger.debug(f"Scanner configuration: timeout={self.timeout}s, output_file={self.output_file}, urls_count={len(self.urls)}")

        start_time = time.time()

        # Gunakan ProcessPoolExecutor untuk lebih baik menangani hasil
        with concurrent.futures.ProcessPoolExecutor(
            max_workers=self.threads
        ) as executor:
            logger.debug(f"Created process pool with {self.threads} workers")
            
            # Submit semua tugas dan dapatkan futures
            futures = {
                executor.submit(self.check_login_page, url): url for url in self.urls
            }
            logger.debug(f"Submitted {len(futures)} tasks to process pool")

            # Proses hasil saat tersedia
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                completed += 1
                logger.debug(f"Processing result {completed}/{len(futures)} from {url}")
                
                try:
                    found_urls = future.result()
                    if found_urls:
                        self.results.extend(found_urls)
                        self.found_count += len(found_urls)
                        logger.info(f"Found {len(found_urls)} phpMyAdmin login pages at {url}")
                    else:
                        logger.debug(f"No phpMyAdmin login pages found at {url}")
                except Exception as e:
                    logger.error(f"Error processing {url}: {e}")
                    if self.debug:
                        logger.debug("Exception details:", exc_info=True)

        end_time = time.time()
        elapsed_time = end_time - start_time
        
        logger.debug(f"All tasks completed. Processing time: {elapsed_time:.2f} seconds")
        logger.warning(f"Scan completed in {elapsed_time:.2f} seconds.")
        logger.warning(
            f"Found {self.found_count} phpMyAdmin login pages across {len(self.urls)} target URLs."
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
            logger.debug("Empty URL provided to validate_url")
            return ""

        # Tambahkan skema jika tidak ada
        if not url.startswith(("http://", "https://")):
            original_url = url
            url = "http://" + url
            logger.debug(f"Added HTTP scheme to URL: {original_url} -> {url}")

        try:
            result = urlparse(url)
            logger.debug(f"Parsed URL components: {result}")
            
            if not result.netloc:
                logger.debug(f"Invalid URL (no netloc): {url}")
                return ""
                
            logger.debug(f"URL validated successfully: {url}")
            return url
        except Exception as e:
            logger.error(f"Exception while parsing URL {url}: {e}")
            return ""

    @staticmethod
    def do_reverse_ip_lookup(url: str, verbose: bool = False, debug: bool = False) -> List[str]:
        """
        Perform reverse IP lookup to find other websites on the same server.
        Args:
            url (str): The target URL to perform reverse IP lookup on.
            verbose (bool): Enable verbose output.
            debug (bool): Enable debug output.
        Returns:
            List[str]: A list of websites on the same server.
        """
        # Validasi URL
        url = PhpMyAdminLoginScanner.validate_url(url)
        if not url:
            logger.error("Invalid URL provided for reverse IP lookup")
            return []

        try:
            # Ekstrak domain
            domain = urlparse(url).netloc
            logger.debug(f"Extracted domain for reverse IP lookup: {domain}")

            # Dapatkan alamat IP
            logger.debug(f"Resolving IP address for domain: {domain}")
            ip = socket.gethostbyname(domain)
            logger.warning(f"IP address for {domain}: {ip}")
            
            # Log additional network information in debug mode
            if debug:
                try:
                    hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(domain)
                    logger.debug(f"Full hostname lookup: hostname={hostname}, aliases={aliaslist}, IPs={ipaddrlist}")
                except Exception as e:
                    logger.debug(f"Could not get extended host information: {e}")

            # Di sini seharusnya ada kode untuk reverse IP lookup
            # Biasanya menggunakan API eksternal atau layanan DNS
            logger.warning(f"Performing reverse IP lookup for {ip}...")
            if debug:
                logger.debug(f"Reverse IP lookup would normally use external API services")
                logger.debug(f"This is a placeholder for actual reverse IP lookup implementation")

            # Return placeholder, ganti dengan implementasi sebenarnya
            return []
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {url}: {e}")
            logger.debug(f"Socket error details: {type(e).__name__}: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Error performing reverse IP lookup for {url}: {e}")
            if debug:
                logger.debug("Exception details:", exc_info=True)
            return []


def read_urls_from_file(file_path: str, verbose: bool = False, debug: bool = False) -> List[str]:
    """
    Read URLs from a file, one URL per line.
    Args:
        file_path (str): Path to the file containing URLs.
        verbose (bool): Enable verbose output.
        debug (bool): Enable debug output.
    Returns:
        List[str]: List of URLs.
    """
    urls = []
    try:
        logger.info(f"Reading URLs from file: {file_path}")
        
        if debug:
            logger.debug(f"Opening file {file_path} in read mode")
            
        with open(file_path, "r") as f:
            line_num = 0
            for line in f:
                line_num += 1
                line = line.strip()
                if debug:
                    logger.debug(f"Line {line_num}: '{line}'")
                
                if line and not line.startswith("#"):
                    urls.append(line)
                    if debug:
                        logger.debug(f"Added URL: {line}")
                elif debug:
                    if not line:
                        logger.debug(f"Skipping empty line {line_num}")
                    elif line.startswith("#"):
                        logger.debug(f"Skipping comment line {line_num}: {line}")
        
        logger.info(f"Successfully read {len(urls)} URLs from file {file_path}")
        
        if debug and urls:
            logger.debug(f"First 5 URLs: {urls[:5]}")
            if len(urls) > 5:
                logger.debug(f"... and {len(urls) - 5} more")
        
        return urls
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return []
    except PermissionError:
        logger.error(f"Permission denied when accessing file: {file_path}")
        return []
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        if debug:
            logger.debug("Exception details:", exc_info=True)
        return []


def main():
    # Banner
    logger.warning("""
    +---------------------------------------------------+
    |             phpMyAdmin Login Scanner              |
    |                                                   |
    | Scan websites for phpMyAdmin login pages          |
    +---------------------------------------------------+
    """)

    parser = argparse.ArgumentParser(
        description="phpMyAdmin Login Scanner - Tool to find phpMyAdmin login pages on websites",
        prog="phpmyadmin_login_scanner",
        epilog="Example: python phpmyadmin_login_scanner.py -u https://example.com -r",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    # Create a group for required arguments
    required_group = parser.add_argument_group("required arguments (one of -u or -f)")
    group = required_group.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "-u",
        "--url",
        help="URL to scan for phpMyAdmin login page",
        metavar="URL",
        dest="target_url",
    )

    group.add_argument(
        "-f",
        "--file",
        help="File containing URLs to scan for phpMyAdmin login pages (one URL per line)",
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
        "-d",
        "--debug",
        help="Enable debug output (more detailed than verbose)",
        action="store_true",
        dest="debug",
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0",
    )

    args = parser.parse_args()
    
    # Setup logging based on command line arguments
    log_level = logging.WARNING
    if args.verbose:
        log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG
        
    LoggerSetup.setup_logging(level=log_level, debug=args.debug)
    logger.debug("Logging configured with level: " + logging.getLevelName(log_level))
    logger.debug(f"Command line arguments: {args}")

    # Initialize URLs list
    urls = []

    # Handle single URL input
    if args.target_url:
        logger.debug(f"Processing single URL input: {args.target_url}")
        target_url = PhpMyAdminLoginScanner.validate_url(args.target_url)
        if not target_url:
            logger.error(f"Invalid URL: {args.target_url}")
            parser.error(f"Invalid URL: {args.target_url}")

        urls.append(target_url)
        logger.debug(f"Added validated URL: {target_url}")

        # Handle reverse IP lookup if requested
        if args.reverse_ip:
            logger.info("Performing reverse IP lookup...")
            related_urls = PhpMyAdminLoginScanner.do_reverse_ip_lookup(
                target_url, 
                verbose=args.verbose, 
                debug=args.debug
            )
            if related_urls:
                urls.extend(related_urls)
                logger.warning(f"Found {len(related_urls)} related websites.")
            else:
                logger.warning("No additional websites found.")

    # Handle file input
    elif args.url_file:
        logger.debug(f"Processing URL file: {args.url_file}")
        if args.reverse_ip:
            logger.error("You cannot use -f/--file with -r/--reverse at the same time")
            parser.error("You cannot use -f/--file with -r/--reverse at the same time")

        file_urls = read_urls_from_file(
            args.url_file, 
            verbose=args.verbose, 
            debug=args.debug
        )
        if not file_urls:
            logger.error(f"No valid URLs found in file: {args.url_file}")
            parser.error(f"No valid URLs found in file: {args.url_file}")

        # Validate all URLs
        for url in file_urls:
            valid_url = PhpMyAdminLoginScanner.validate_url(url)
            if valid_url:
                urls.append(valid_url)
                logger.debug(f"Added validated URL from file: {valid_url}")
            else:
                logger.info(f"Skipping invalid URL from file: {url}")

    # Final check
    if not urls:
        logger.error("No valid URLs provided for scanning")
        parser.error("No valid URLs provided for scanning")

    # Remove duplicates
    original_count = len(urls)
    urls = list(set(urls))
    if original_count != len(urls):
        logger.info(f"Removed {original_count - len(urls)} duplicate URLs")
    
    logger.warning(f"Scanning {len(urls)} URLs for phpMyAdmin login pages...")

    # Create and start the scanner
    logger.debug("Initializing scanner with configuration: " + 
                f"threads={args.threads}, timeout={args.timeout}, " +
                f"output_file={args.output_file}, verbose={args.verbose}, " +
                f"debug={args.debug}")
                
    scanner = PhpMyAdminLoginScanner(
        urls=urls,
        threads=args.threads,
        timeout=args.timeout,
        output_file=args.output_file,
        verbose=args.verbose,
        debug=args.debug,
    )

    results = scanner.start()

    if results:
        logger.warning("\nFound phpMyAdmin login pages:")
        for url in results:
            logger.warning(f"  - {url}")

        if args.output_file:
            logger.warning(f"\nResults saved to: {args.output_file}")
    else:
        logger.warning("\nNo phpMyAdmin login pages found.")

    logger.warning("\nphpMyAdmin Login Scanner - Scan completed.")



if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("\nOperation cancelled by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        logger.debug("Exception details:", exc_info=True)
        sys.exit(1)
