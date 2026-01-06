#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ghost-Dir - Web Directory & File Fuzzer Tool
Author: egnake
GitHub: https://github.com/egnake
Version: 1.0.0
License: MIT
"""

import argparse
import sys
import os
import time
import json
import csv
import random
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] 'requests' modülü bulunamadı. Yüklemek için: pip install requests")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import colorama
    colorama.init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


BANNER = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗      ██████╗ ██╗██████╗          ║
║  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝      ██╔══██╗██║██╔══██╗         ║
║  ██║  ███╗███████║██║   ██║███████╗   ██║   █████╗██║  ██║██║██████╔╝         ║
║  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ╚════╝██║  ██║██║██╔══██╗         ║
║  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║         ██████╔╝██║██║  ██║         ║
║   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝         ╚═════╝ ╚═╝╚═╝  ╚═╝         ║
║                                                                               ║
║                    Web Directory & File Fuzzer Tool                           ║
║                         Author: egnake | v1.0.0                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]


@dataclass
class ScanResult:
    url: str
    status_code: int
    content_length: int
    redirect_url: Optional[str] = None
    response_time: float = 0.0
    content_type: Optional[str] = None


@dataclass
class ScanStatistics:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    redirects: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.time)
    
    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time
    
    @property
    def requests_per_second(self) -> float:
        if self.elapsed_time > 0:
            return self.total_requests / self.elapsed_time
        return 0.0


class Colors:
    if COLORAMA_AVAILABLE:
        RED = colorama.Fore.RED
        GREEN = colorama.Fore.GREEN
        YELLOW = colorama.Fore.YELLOW
        BLUE = colorama.Fore.BLUE
        MAGENTA = colorama.Fore.MAGENTA
        CYAN = colorama.Fore.CYAN
        WHITE = colorama.Fore.WHITE
        RESET = colorama.Style.RESET_ALL
        BOLD = colorama.Style.BRIGHT
    else:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = BOLD = ""


class GhostDir:
    VERSION = "1.0.0"
    AUTHOR = "egnake"
    
    def __init__(
        self,
        target_url: str,
        wordlist_path: str,
        threads: int = 10,
        extensions: Optional[List[str]] = None,
        status_codes: Optional[List[int]] = None,
        exclude_codes: Optional[List[int]] = None,
        timeout: int = 10,
        delay: float = 0,
        proxy: Optional[str] = None,
        cookies: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        user_agent: Optional[str] = None,
        random_agent: bool = False,
        follow_redirects: bool = False,
        recursive: bool = False,
        recursive_depth: int = 2,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        output_file: Optional[str] = None,
        output_format: str = "txt",
        quiet: bool = False,
        no_color: bool = False,
        verify_ssl: bool = True,
        auth: Optional[Tuple[str, str]] = None,
        exclude_length: Optional[List[int]] = None,
        match_string: Optional[str] = None,
        exclude_string: Optional[str] = None,
    ):
        self.target_url = self._normalize_url(target_url)
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.extensions = extensions or []
        self.status_codes = status_codes or [200, 201, 202, 204, 301, 302, 307, 308, 401, 403]
        self.exclude_codes = exclude_codes or []
        self.timeout = timeout
        self.delay = delay
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.cookies = self._parse_cookies(cookies) if cookies else None
        self.headers = headers or {}
        self.user_agent = user_agent
        self.random_agent = random_agent
        self.follow_redirects = follow_redirects
        self.recursive = recursive
        self.recursive_depth = recursive_depth
        self.min_length = min_length
        self.max_length = max_length
        self.output_file = output_file
        self.output_format = output_format.lower()
        self.quiet = quiet
        self.no_color = no_color
        self.verify_ssl = verify_ssl
        self.auth = auth
        self.exclude_length = exclude_length or []
        self.match_string = match_string
        self.exclude_string = exclude_string
        
        self.results: List[ScanResult] = []
        self.stats = ScanStatistics()
        self.scanned_dirs: Set[str] = set()
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        
        self.console = Console() if RICH_AVAILABLE else None
        self.session = self._create_session()
        
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/")
    
    def _parse_cookies(self, cookies_str: str) -> Dict[str, str]:
        cookies = {}
        for cookie in cookies_str.split(";"):
            if "=" in cookie:
                key, value = cookie.strip().split("=", 1)
                cookies[key.strip()] = value.strip()
        return cookies
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=self.threads + 10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        if self.auth:
            session.auth = self.auth
        if self.cookies:
            session.cookies.update(self.cookies)
        return session
    
    def _get_user_agent(self) -> str:
        if self.random_agent:
            return random.choice(USER_AGENTS)
        return self.user_agent or USER_AGENTS[0]
    
    def _signal_handler(self, signum, frame):
        self.stop_event.set()
        self._print_warning("\n[!] Tarama durduruldu. Sonuçlar kaydediliyor...")
        self._save_results()
        sys.exit(0)
    
    def _print_banner(self):
        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(Text(BANNER, style="bold cyan"))
        else:
            print(f"{Colors.CYAN}{BANNER}{Colors.RESET}")
    
    def _print_config(self):
        config_text = f"""
[*] Hedef URL     : {self.target_url}
[*] Wordlist      : {self.wordlist_path}
[*] Thread Sayısı : {self.threads}
[*] Uzantılar     : {', '.join(self.extensions) if self.extensions else 'Yok'}
[*] Durum Kodları : {', '.join(map(str, self.status_codes))}
[*] Timeout       : {self.timeout}s
[*] Proxy         : {self.proxy['http'] if self.proxy else 'Yok'}
[*] Recursive     : {'Evet (Derinlik: ' + str(self.recursive_depth) + ')' if self.recursive else 'Hayır'}
[*] SSL Doğrulama : {'Evet' if self.verify_ssl else 'Hayır'}
{'=' * 70}"""
        
        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(Panel(config_text, title="[bold green]Tarama Yapılandırması[/bold green]", border_style="green"))
        else:
            print(f"{Colors.GREEN}{config_text}{Colors.RESET}")
    
    def _print_success(self, message: str):
        if self.quiet:
            return
        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(f"[bold green]{message}[/bold green]")
        else:
            print(f"{Colors.GREEN}{message}{Colors.RESET}")
    
    def _print_warning(self, message: str):
        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(f"[bold yellow]{message}[/bold yellow]")
        else:
            print(f"{Colors.YELLOW}{message}{Colors.RESET}")
    
    def _print_error(self, message: str):
        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(f"[bold red]{message}[/bold red]")
        else:
            print(f"{Colors.RED}{message}{Colors.RESET}")
    
    def _print_info(self, message: str):
        if self.quiet:
            return
        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(f"[bold blue]{message}[/bold blue]")
        else:
            print(f"{Colors.BLUE}{message}{Colors.RESET}")
    
    def _print_result(self, result: ScanResult):
        if self.quiet:
            return
        
        status = result.status_code
        if status in [200, 201, 202, 204]:
            color, rich_color = Colors.GREEN, "green"
        elif status in [301, 302, 307, 308]:
            color, rich_color = Colors.CYAN, "cyan"
        elif status in [401, 403]:
            color, rich_color = Colors.YELLOW, "yellow"
        else:
            color, rich_color = Colors.WHITE, "white"
        
        redirect_info = f" -> {result.redirect_url}" if result.redirect_url else ""
        path = result.url.replace(self.target_url, '').lstrip('/')
        
        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(
                f"[{rich_color}]/{path}[/{rich_color}] "
                f"[dim](Status: {status} | Size: {result.content_length} | Time: {result.response_time:.2f}s{redirect_info})[/dim]"
            )
        else:
            print(f"{color}[{status}] /{path} (Size: {result.content_length} | Time: {result.response_time:.2f}s){redirect_info}{Colors.RESET}")
    
    def _load_wordlist(self) -> List[str]:
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            return words
        except FileNotFoundError:
            self._print_error(f"[!] Wordlist bulunamadı: {self.wordlist_path}")
            sys.exit(1)
        except Exception as e:
            self._print_error(f"[!] Wordlist okuma hatası: {e}")
            sys.exit(1)
    
    def _generate_paths(self, words: List[str], base_url: str = "") -> List[str]:
        paths = []
        base = base_url or self.target_url
        for word in words:
            paths.append(urljoin(base + "/", word))
            for ext in self.extensions:
                ext = ext.lstrip(".")
                paths.append(urljoin(base + "/", f"{word}.{ext}"))
        return paths
    
    def _check_target(self) -> bool:
        try:
            headers = {"User-Agent": self._get_user_agent()}
            headers.update(self.headers)
            response = self.session.get(
                self.target_url, headers=headers, timeout=self.timeout,
                verify=self.verify_ssl, proxies=self.proxy, allow_redirects=True
            )
            self._print_success(f"[+] Hedef erişilebilir: {self.target_url} (Status: {response.status_code})")
            return True
        except requests.exceptions.RequestException as e:
            self._print_error(f"[!] Hedef erişilemez: {e}")
            return False
    
    def _scan_path(self, url: str) -> Optional[ScanResult]:
        if self.stop_event.is_set():
            return None
        
        try:
            headers = {"User-Agent": self._get_user_agent()}
            headers.update(self.headers)
            
            start_time = time.time()
            response = self.session.get(
                url, headers=headers, timeout=self.timeout,
                verify=self.verify_ssl, proxies=self.proxy, allow_redirects=self.follow_redirects
            )
            response_time = time.time() - start_time
            
            status_code = response.status_code
            content_length = len(response.content)
            content_type = response.headers.get("Content-Type", "")
            redirect_url = response.headers.get("Location") if status_code in [301, 302, 307, 308] else None
            
            with self.lock:
                self.stats.total_requests += 1
            
            if self.exclude_codes and status_code in self.exclude_codes:
                return None
            if status_code not in self.status_codes:
                return None
            if self.min_length and content_length < self.min_length:
                return None
            if self.max_length and content_length > self.max_length:
                return None
            if self.exclude_length and content_length in self.exclude_length:
                return None
            if self.match_string and self.match_string not in response.text:
                return None
            if self.exclude_string and self.exclude_string in response.text:
                return None
            
            result = ScanResult(
                url=url, status_code=status_code, content_length=content_length,
                redirect_url=redirect_url, response_time=response_time, content_type=content_type
            )
            
            with self.lock:
                self.stats.successful_requests += 1
                self.results.append(result)
            
            if self.delay > 0:
                time.sleep(self.delay)
            
            return result
            
        except requests.exceptions.Timeout:
            with self.lock:
                self.stats.errors += 1
            return None
        except requests.exceptions.RequestException:
            with self.lock:
                self.stats.errors += 1
            return None
    
    def _recursive_scan(self, found_dirs: List[str], depth: int = 1):
        if depth > self.recursive_depth or not found_dirs:
            return
        
        words = self._load_wordlist()
        
        for dir_url in found_dirs:
            if self.stop_event.is_set():
                break
            if dir_url in self.scanned_dirs:
                continue
            
            self.scanned_dirs.add(dir_url)
            self._print_info(f"\n[*] Recursive tarama: {dir_url} (Derinlik: {depth})")
            
            paths = self._generate_paths(words, dir_url)
            new_dirs = []
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._scan_path, path): path for path in paths}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        self._print_result(result)
                        if result.status_code in [200, 301, 302, 307, 308]:
                            if not any(result.url.endswith(f".{ext}") for ext in self.extensions):
                                new_dirs.append(result.url.rstrip("/"))
            
            if new_dirs and depth < self.recursive_depth:
                self._recursive_scan(new_dirs, depth + 1)
    
    def _save_results(self):
        if not self.output_file or not self.results:
            return
        try:
            if self.output_format == "json":
                self._save_json()
            elif self.output_format == "csv":
                self._save_csv()
            else:
                self._save_txt()
            self._print_success(f"[+] Sonuçlar kaydedildi: {self.output_file}")
        except Exception as e:
            self._print_error(f"[!] Sonuç kaydetme hatası: {e}")
    
    def _save_json(self):
        data = {
            "target": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "author": self.AUTHOR,
            "statistics": {
                "total_requests": self.stats.total_requests,
                "found": len(self.results),
                "errors": self.stats.errors,
                "elapsed_time": self.stats.elapsed_time
            },
            "results": [
                {
                    "url": r.url, "status_code": r.status_code, "content_length": r.content_length,
                    "redirect_url": r.redirect_url, "response_time": r.response_time, "content_type": r.content_type
                }
                for r in self.results
            ]
        }
        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _save_csv(self):
        with open(self.output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["URL", "Status Code", "Content Length", "Redirect URL", "Response Time", "Content Type"])
            for r in self.results:
                writer.writerow([r.url, r.status_code, r.content_length, r.redirect_url or "", f"{r.response_time:.2f}", r.content_type or ""])
    
    def _save_txt(self):
        with open(self.output_file, "w", encoding="utf-8") as f:
            f.write(f"Ghost-Dir Scan Results | Author: {self.AUTHOR}\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"{'=' * 70}\n\n")
            for r in self.results:
                redirect_info = f" -> {r.redirect_url}" if r.redirect_url else ""
                f.write(f"[{r.status_code}] {r.url} (Size: {r.content_length}){redirect_info}\n")
    
    def _print_summary(self):
        elapsed = self.stats.elapsed_time
        summary = f"""
{'=' * 70}
                           TARAMA ÖZETİ
{'=' * 70}
[*] Toplam İstek     : {self.stats.total_requests}
[*] Bulunan          : {len(self.results)}
[*] Hatalar          : {self.stats.errors}
[*] Geçen Süre       : {elapsed:.2f} saniye
[*] İstek/Saniye     : {self.stats.requests_per_second:.2f}
{'=' * 70}"""
        
        if RICH_AVAILABLE and self.console and not self.no_color:
            self.console.print(Panel(summary, title="[bold magenta]Tarama Tamamlandı[/bold magenta]", border_style="magenta"))
        else:
            print(f"{Colors.MAGENTA}{summary}{Colors.RESET}")
        
        if self.results and not self.quiet:
            self._print_info("\n[*] Bulunan Dizin/Dosyalar:")
            
            if RICH_AVAILABLE and self.console and not self.no_color:
                table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED)
                table.add_column("URL", style="green")
                table.add_column("Status", justify="center")
                table.add_column("Size", justify="right")
                table.add_column("Type", style="dim")
                
                for r in self.results[:50]:
                    path = r.url.replace(self.target_url, "")
                    status_style = "green" if r.status_code == 200 else "yellow" if r.status_code in [301, 302] else "red"
                    table.add_row(path, f"[{status_style}]{r.status_code}[/{status_style}]", str(r.content_length), (r.content_type or "")[:30])
                
                self.console.print(table)
                if len(self.results) > 50:
                    self.console.print(f"[dim]... ve {len(self.results) - 50} sonuç daha[/dim]")
            else:
                for r in self.results:
                    print(f"  [{r.status_code}] {r.url}")
    
    def scan(self):
        self._print_banner()
        self._print_config()
        
        if not self._check_target():
            return
        
        words = self._load_wordlist()
        self._print_info(f"[*] Wordlist yüklendi: {len(words)} kelime")
        
        paths = self._generate_paths(words)
        total_paths = len(paths)
        self._print_info(f"[*] Toplam taranacak path: {total_paths}")
        self._print_info(f"\n[*] Tarama başlıyor...\n")
        
        found_dirs = []
        
        if RICH_AVAILABLE and self.console and not self.quiet and not self.no_color:
            with Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                BarColumn(), TaskProgressColumn(), TimeRemainingColumn(), console=self.console
            ) as progress:
                task = progress.add_task("[cyan]Taranıyor...", total=total_paths)
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {executor.submit(self._scan_path, path): path for path in paths}
                    for future in as_completed(futures):
                        if self.stop_event.is_set():
                            executor.shutdown(wait=False)
                            break
                        result = future.result()
                        if result:
                            self._print_result(result)
                            if result.status_code in [200, 301, 302, 307, 308]:
                                if not any(result.url.endswith(f".{ext}") for ext in self.extensions):
                                    found_dirs.append(result.url.rstrip("/"))
                        progress.update(task, advance=1)
        else:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._scan_path, path): path for path in paths}
                completed = 0
                for future in as_completed(futures):
                    if self.stop_event.is_set():
                        executor.shutdown(wait=False)
                        break
                    result = future.result()
                    if result:
                        self._print_result(result)
                        if result.status_code in [200, 301, 302, 307, 308]:
                            if not any(result.url.endswith(f".{ext}") for ext in self.extensions):
                                found_dirs.append(result.url.rstrip("/"))
                    completed += 1
                    if completed % 100 == 0:
                        print(f"\r[*] İlerleme: {completed}/{total_paths}", end="")
                print()
        
        if self.recursive and found_dirs:
            self._print_info(f"\n[*] Recursive tarama başlıyor ({len(found_dirs)} dizin)...")
            self._recursive_scan(found_dirs)
        
        self._save_results()
        self._print_summary()


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ghost-Dir - Web Directory & File Fuzzer Tool by egnake",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://target.com -w wordlist.txt
  %(prog)s -u https://target.com -w wordlist.txt -x php,html,txt
  %(prog)s -u https://target.com -w wordlist.txt -t 50 -o results.json --format json
  %(prog)s -u https://target.com -w wordlist.txt -r --recursive-depth 3
  %(prog)s -u https://target.com -w wordlist.txt --proxy http://127.0.0.1:8080

Author: egnake | GitHub: https://github.com/egnake
        """
    )
    
    target = parser.add_argument_group("Target")
    target.add_argument("-u", "--url", required=True, help="Target URL")
    target.add_argument("-w", "--wordlist", required=True, help="Wordlist file path")
    
    scan = parser.add_argument_group("Scan Options")
    scan.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    scan.add_argument("-x", "--extensions", help="File extensions (comma-separated)")
    scan.add_argument("-s", "--status-codes", help="Status codes to show (comma-separated)")
    scan.add_argument("-e", "--exclude-codes", help="Status codes to exclude")
    scan.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    scan.add_argument("--delay", type=float, default=0, help="Delay between requests")
    scan.add_argument("-r", "--recursive", action="store_true", help="Recursive scan")
    scan.add_argument("--recursive-depth", type=int, default=2, help="Recursive depth (default: 2)")
    
    filt = parser.add_argument_group("Filtering")
    filt.add_argument("--min-length", type=int, help="Minimum response length")
    filt.add_argument("--max-length", type=int, help="Maximum response length")
    filt.add_argument("--exclude-length", help="Exclude response lengths (comma-separated)")
    filt.add_argument("--match-string", help="Match string in response")
    filt.add_argument("--exclude-string", help="Exclude string in response")
    
    http = parser.add_argument_group("HTTP Options")
    http.add_argument("--proxy", help="Proxy URL")
    http.add_argument("--cookies", help="Cookie string")
    http.add_argument("-H", "--header", action="append", help="Custom header")
    http.add_argument("-A", "--user-agent", help="Custom User-Agent")
    http.add_argument("--random-agent", action="store_true", help="Random User-Agent")
    http.add_argument("-L", "--follow-redirects", action="store_true", help="Follow redirects")
    http.add_argument("-k", "--insecure", action="store_true", help="Skip SSL verification")
    http.add_argument("--auth", help="Basic auth (user:pass)")
    
    output = parser.add_argument_group("Output")
    output.add_argument("-o", "--output", help="Output file")
    output.add_argument("--format", choices=["txt", "json", "csv"], default="txt", help="Output format")
    output.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    output.add_argument("--no-color", action="store_true", help="Disable colors")
    
    return parser.parse_args()


def main():
    args = parse_arguments()
    
    extensions = args.extensions.split(",") if args.extensions else None
    status_codes = [int(x) for x in args.status_codes.split(",")] if args.status_codes else None
    exclude_codes = [int(x) for x in args.exclude_codes.split(",")] if args.exclude_codes else None
    exclude_length = [int(x) for x in args.exclude_length.split(",")] if args.exclude_length else None
    
    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()
    
    auth = tuple(args.auth.split(":", 1)) if args.auth and ":" in args.auth else None
    
    scanner = GhostDir(
        target_url=args.url, wordlist_path=args.wordlist, threads=args.threads,
        extensions=extensions, status_codes=status_codes, exclude_codes=exclude_codes,
        timeout=args.timeout, delay=args.delay, proxy=args.proxy, cookies=args.cookies,
        headers=headers, user_agent=args.user_agent, random_agent=args.random_agent,
        follow_redirects=args.follow_redirects, recursive=args.recursive,
        recursive_depth=args.recursive_depth, min_length=args.min_length,
        max_length=args.max_length, output_file=args.output, output_format=args.format,
        quiet=args.quiet, no_color=args.no_color, verify_ssl=not args.insecure,
        auth=auth, exclude_length=exclude_length, match_string=args.match_string,
        exclude_string=args.exclude_string,
    )
    scanner.scan()


if __name__ == "__main__":
    main()
