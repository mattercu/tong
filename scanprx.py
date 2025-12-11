#!/usr/bin/env python3
“””
DarkJPT Proxy Scanner - Advanced Edition
Professional proxy scanning and classification system
“””

import json
import argparse
import requests
import time
import sys
import random
import re
import os
import shutil
from queue import Queue
from threading import Thread, Lock, Event
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color codes

class C:
R = ‘\033[91m’
G = ‘\033[92m’
Y = ‘\033[93m’
B = ‘\033[94m’
M = ‘\033[95m’
C = ‘\033[96m’
W = ‘\033[97m’
N = ‘\033[0m’
BOLD = ‘\033[1m’
COLORS = [R, G, Y, B, M, C, W]

class AnimatedBanner:
def **init**(self):
self.banner_text = “DarkJPT”
self.stop_event = Event()
self.lock = Lock()

```
def get_banner_frame(self, text_parts, color=C.W):
    """Create ASCII art banner"""
    lines = [
        "╔═══════════════════════════════════════════════════════════╗",
        "║                                                           ║",
        "║     ██████╗  █████╗ ██████╗ ██╗  ██╗     ██╗██████╗     ║",
        "║     ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝     ██║██╔══██╗    ║",
        "║     ██║  ██║███████║██████╔╝█████╔╝      ██║██████╔╝    ║",
        "║     ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██   ██║██╔═══╝     ║",
        "║     ██████╔╝██║  ██║██║  ██║██║  ██╗╚█████╔╝██║         ║",
        "║     ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚════╝ ╚═╝         ║",
        "║                                                           ║",
        "║         Advanced Proxy Scanner & Validator v3.0           ║",
        "║                Professional Edition                        ║",
        "║                                                           ║",
        "╚═══════════════════════════════════════════════════════════╝"
    ]
    
    # Apply color
    colored_lines = [color + line + C.N for line in lines]
    return '\n'.join(colored_lines)

def animate_disappear(self):
    """Animate text disappearing letter by letter"""
    for i in range(len(self.banner_text), 0, -1):
        if self.stop_event.is_set():
            return
        partial = self.banner_text[:i]
        os.system('clear' if os.name != 'nt' else 'cls')
        print(self.get_banner_frame(partial))
        time.sleep(10 / len(self.banner_text))

def animate_appear(self):
    """Animate text appearing letter by letter"""
    for i in range(1, len(self.banner_text) + 1):
        if self.stop_event.is_set():
            return
        partial = self.banner_text[:i]
        os.system('clear' if os.name != 'nt' else 'cls')
        print(self.get_banner_frame(partial))
        time.sleep(10 / len(self.banner_text))

def animate_rainbow(self):
    """Cycle through rainbow colors"""
    duration = 30
    steps = 60
    for i in range(steps):
        if self.stop_event.is_set():
            return
        color = C.COLORS[i % len(C.COLORS)]
        os.system('clear' if os.name != 'nt' else 'cls')
        print(self.get_banner_frame(self.banner_text, color))
        time.sleep(duration / steps)

def run_animation(self):
    """Main animation loop"""
    while not self.stop_event.is_set():
        self.animate_disappear()  # 10s
        if self.stop_event.is_set(): break
        self.animate_appear()      # 10s
        if self.stop_event.is_set(): break
        self.animate_rainbow()     # 30s

def stop(self):
    self.stop_event.set()
```

class Logger:
“”“Professional logging system”””
def **init**(self, log_file=‘scanner.log’, enable_file_log=False):
self.log_file = log_file
self.enable_file_log = enable_file_log
self.lock = Lock()

```
    if self.enable_file_log:
        # Create logs directory
        Path('logs').mkdir(exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = f'logs/scan_{timestamp}.log'
        
def _format_message(self, level, component, message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    return f"[{timestamp}] [{level:>8}] [{component:>15}] {message}"

def _get_color(self, level):
    colors = {
        'INFO': C.C,
        'SUCCESS': C.G,
        'WARNING': C.Y,
        'ERROR': C.R,
        'DEBUG': C.M,
        'PROGRESS': C.B
    }
    return colors.get(level, C.W)

def log(self, level, component, message):
    with self.lock:
        formatted = self._format_message(level, component, message)
        color = self._get_color(level)
        
        # Console output
        print(f"{color}{formatted}{C.N}")
        
        # File output
        if self.enable_file_log:
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(formatted + '\n')
            except:
                pass

def info(self, component, message):
    self.log('INFO', component, message)

def success(self, component, message):
    self.log('SUCCESS', component, message)

def warning(self, component, message):
    self.log('WARNING', component, message)

def error(self, component, message):
    self.log('ERROR', component, message)

def debug(self, component, message):
    self.log('DEBUG', component, message)

def progress(self, component, message):
    self.log('PROGRESS', component, message)
```

class ProxyDownloader:
“”“Download proxy lists from sources”””
def **init**(self, logger):
self.logger = logger
self.output_dir = Path(‘tho’)
self.output_dir.mkdir(exist_ok=True)

```
def download_from_scrapers(self, scrapers):
    """Download proxy lists to files"""
    self.logger.info('DOWNLOADER', f'Starting download from {len(scrapers)} sources')
    
    downloaded_files = []
    success_count = 0
    
    for idx, scraper in enumerate(scrapers, 1):
        try:
            url = scraper.get('url')
            method = scraper.get('method', 'http')
            
            self.logger.debug('DOWNLOADER', f'[{idx}/{len(scrapers)}] Fetching {url[:60]}...')
            
            headers = {'User-Agent': self._get_user_agent()}
            response = requests.get(url, headers=headers, timeout=15, verify=False)
            
            if response.status_code == 200:
                # Extract proxies
                pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}'
                proxies = re.findall(pattern, response.text)
                
                if proxies:
                    # Save to file
                    filename = f"{method}_{idx}_{int(time.time())}.txt"
                    filepath = self.output_dir / filename
                    
                    with open(filepath, 'w') as f:
                        for proxy in proxies:
                            f.write(f"{proxy}|{method}\n")
                    
                    downloaded_files.append(str(filepath))
                    success_count += 1
                    
                    self.logger.success('DOWNLOADER', 
                        f'✓ Saved {len(proxies)} proxies to {filename}')
                else:
                    self.logger.warning('DOWNLOADER', f'✗ No proxies found in {url[:40]}')
            else:
                self.logger.warning('DOWNLOADER', 
                    f'✗ HTTP {response.status_code} from {url[:40]}')
                
        except Exception as e:
            self.logger.error('DOWNLOADER', f'✗ Failed {url[:40]}: {str(e)[:50]}')
    
    self.logger.success('DOWNLOADER', 
        f'Download complete: {success_count}/{len(scrapers)} sources successful')
    
    return downloaded_files

def _get_user_agent(self):
    agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ]
    return random.choice(agents)
```

class ProxyClassifier:
“”“Advanced proxy classification system”””
def **init**(self, logger):
self.logger = logger
self.base_dir = Path(‘classified_proxies’)
self._setup_directories()

```
def _setup_directories(self):
    """Create classification directories"""
    categories = [
        'by_speed/fast',
        'by_speed/medium', 
        'by_speed/slow',
        'by_anonymity/elite',
        'by_anonymity/anonymous',
        'by_anonymity/transparent',
        'by_type/http',
        'by_type/https',
        'by_type/socks4',
        'by_type/socks5',
        'by_country',
        'all_working'
    ]
    
    for cat in categories:
        (self.base_dir / cat).mkdir(parents=True, exist_ok=True)

def classify_and_save(self, proxy_info):
    """Classify single proxy into appropriate directories"""
    address = proxy_info['address']
    
    # All working proxies
    self._append_to_file(self.base_dir / 'all_working' / 'proxies.txt', proxy_info)
    
    # By speed
    speed_path = self.base_dir / 'by_speed' / proxy_info['speed']
    self._append_to_file(speed_path / f"{proxy_info['type']}.txt", proxy_info)
    
    # By anonymity
    anon_path = self.base_dir / 'by_anonymity' / proxy_info['anonymity']
    self._append_to_file(anon_path / f"{proxy_info['type']}.txt", proxy_info)
    
    # By type
    type_path = self.base_dir / 'by_type' / proxy_info['type']
    self._append_to_file(type_path / 'proxies.txt', proxy_info)
    
    # By country
    country_safe = re.sub(r'[^\w\s-]', '', proxy_info['country'])
    country_path = self.base_dir / 'by_country' / f"{country_safe}.txt"
    self._append_to_file(country_path, proxy_info)

def _append_to_file(self, filepath, proxy_info):
    """Append proxy to file"""
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, 'a') as f:
            f.write(f"{proxy_info['address']}|{proxy_info['type']}|"
                   f"{proxy_info['country']}|{proxy_info['time']:.3f}s|"
                   f"{proxy_info['speed']}|{proxy_info['anonymity']}\n")
    except Exception as e:
        pass

def generate_summary(self):
    """Generate classification summary"""
    summary = {
        'total_files': 0,
        'by_category': {}
    }
    
    for root, dirs, files in os.walk(self.base_dir):
        for file in files:
            if file.endswith('.txt'):
                filepath = Path(root) / file
                count = sum(1 for _ in open(filepath))
                rel_path = filepath.relative_to(self.base_dir)
                summary['by_category'][str(rel_path)] = count
                summary['total_files'] += 1
    
    return summary
```

class ProxyScanner:
def **init**(self, args, logger):
self.args = args
self.logger = logger
self.proxy_types = args.type.split(’,’)
self.threads_count = args.threads
self.timeout = args.timeout / 1000
self.batch_size = args.batch
self.check_times = args.check

```
    # Thread-safe structures
    self.proxy_queue = Queue()
    self.lock = Lock()
    
    # Components
    self.classifier = ProxyClassifier(logger)
    self.downloader = ProxyDownloader(logger)
    
    # Check websites
    self.check_websites = [
        'http://httpbin.org/ip',
        'https://api.ipify.org?format=json',
        'http://ip-api.com/json/'
    ]
    
    # Statistics
    self.stats = {
        'downloaded': 0,
        'total_loaded': 0,
        'after_dedupe': 0,
        'total_checked': 0,
        'valid': 0,
        'invalid': 0,
        'by_country': defaultdict(int),
        'by_speed': {'fast': 0, 'medium': 0, 'slow': 0},
        'by_type': defaultdict(int),
        'by_anonymity': defaultdict(int)
    }
    
    self.start_time = time.time()

def load_scrapers(self):
    """Load scraper configurations"""
    self.logger.info('LOADER', 'Loading scraper configurations...')
    
    try:
        with open('tt/scrapers.json', 'r') as f:
            scrapers = json.load(f)
        
        # Filter by requested types
        filtered = [s for s in scrapers if s.get('method') in self.proxy_types]
        
        self.logger.success('LOADER', 
            f'Loaded {len(filtered)}/{len(scrapers)} scrapers for: {", ".join(self.proxy_types)}')
        
        return filtered
    except Exception as e:
        self.logger.error('LOADER', f'Failed to load scrapers: {e}')
        return []

def load_proxies_from_files(self):
    """Load proxies from downloaded files"""
    self.logger.info('LOADER', 'Loading proxies from tho directory...')
    
    proxy_list = []
    files = list(Path('tho').glob('*.txt'))
    
    self.logger.debug('LOADER', f'Found {len(files)} proxy files')
    
    for filepath in files:
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '|' in line:
                        parts = line.split('|')
                        proxy_list.append({
                            'address': parts[0],
                            'type': parts[1] if len(parts) > 1 else 'http'
                        })
        except Exception as e:
            self.logger.error('LOADER', f'Error reading {filepath.name}: {e}')
    
    self.stats['total_loaded'] = len(proxy_list)
    self.logger.success('LOADER', f'Loaded {len(proxy_list)} proxies from files')
    
    return proxy_list

def remove_duplicates(self, proxy_list):
    """Remove duplicate proxies"""
    self.logger.info('DEDUPLICATOR', 'Removing duplicates...')
    
    unique = []
    seen = set()
    
    for p in proxy_list:
        key = f"{p['address']}:{p['type']}"
        if key not in seen:
            seen.add(key)
            unique.append(p)
    
    removed = len(proxy_list) - len(unique)
    self.stats['after_dedupe'] = len(unique)
    
    self.logger.success('DEDUPLICATOR', 
        f'Removed {removed} duplicates, {len(unique)} unique proxies remain')
    
    return unique

def process_batch(self, proxy_list):
    """Apply batch limit and shuffle"""
    if len(proxy_list) > self.batch_size:
        proxy_list = proxy_list[:self.batch_size]
        self.logger.info('BATCH', f'Limited to {self.batch_size} proxies')
    
    random.shuffle(proxy_list)
    self.logger.info('BATCH', f'Shuffled {len(proxy_list)} proxies')
    
    return proxy_list

def start_workers(self, num_workers):
    """Start worker threads"""
    self.logger.info('WORKER_MANAGER', f'Starting {num_workers} worker threads...')
    
    workers = []
    for i in range(num_workers):
        t = Thread(target=self.worker, daemon=True, name=f'Worker-{i+1}')
        t.start()
        workers.append(t)
    
    self.logger.success('WORKER_MANAGER', f'Started {len(workers)} workers')
    return workers

def worker(self):
    """Worker thread for checking proxies"""
    while True:
        try:
            proxy_data = self.proxy_queue.get(timeout=1)
            if proxy_data is None:
                break
            
            self.check_proxy(proxy_data)
            self.proxy_queue.task_done()
        except:
            break

def check_proxy(self, proxy_data):
    """Check proxy validity with multiple attempts"""
    address = proxy_data['address']
    ptype = proxy_data['type']
    
    results = []
    for attempt in range(self.check_times):
        result = self.test_proxy_once(address, ptype)
        if result:
            results.append(result)
    
    with self.lock:
        self.stats['total_checked'] += 1
    
    # Determine if proxy is valid
    if len(results) >= max(1, self.check_times // 2):
        # Calculate metrics
        avg_time = sum(r['time'] for r in results) / len(results)
        country = results[0].get('country', 'Unknown')
        anonymity = results[0].get('anonymity', 'unknown')
        
        # Classify speed
        if avg_time < 1:
            speed = 'fast'
        elif avg_time < 3:
            speed = 'medium'
        else:
            speed = 'slow'
        
        proxy_info = {
            'address': address,
            'type': ptype,
            'country': country,
            'time': avg_time,
            'speed': speed,
            'anonymity': anonymity,
            'success_rate': round((len(results) / self.check_times) * 100, 1)
        }
        
        # Update stats and classify
        with self.lock:
            self.stats['valid'] += 1
            self.stats['by_country'][country] += 1
            self.stats['by_speed'][speed] += 1
            self.stats['by_type'][ptype] += 1
            self.stats['by_anonymity'][anonymity] += 1
            
            # Classify and save
            self.classifier.classify_and_save(proxy_info)
        
        # Log valid proxy
        color = C.G if speed == 'fast' else C.Y if speed == 'medium' else C.M
        self.logger.log('VALID', 'CHECKER', 
            f"{address:>21} | {ptype:>7} | {country:>15} | {avg_time:.3f}s | {speed.upper():>6} | {anonymity}")
    else:
        with self.lock:
            self.stats['invalid'] += 1

def test_proxy_once(self, address, ptype):
    """Test proxy once"""
    try:
        url = random.choice(self.check_websites)
        proxies = {
            'http': f'{ptype}://{address}',
            'https': f'{ptype}://{address}'
        }
        
        start = time.time()
        resp = requests.get(url, proxies=proxies, timeout=self.timeout, verify=False)
        elapsed = time.time() - start
        
        if resp.status_code == 200:
            country = 'Unknown'
            try:
                if 'ip-api.com' in url:
                    country = resp.json().get('country', 'Unknown')
            except:
                pass
            
            # Detect anonymity
            anonymity = 'unknown'
            try:
                headers_str = str(resp.headers).lower()
                if 'x-forwarded-for' in headers_str or 'via' in headers_str:
                    anonymity = 'transparent'
                elif 'proxy' in headers_str:
                    anonymity = 'anonymous'
                else:
                    anonymity = 'elite'
            except:
                pass
            
            return {
                'time': elapsed,
                'country': country,
                'anonymity': anonymity
            }
    except:
        pass
    
    return None

def monitor_progress(self, workers):
    """Monitor and display progress"""
    total = self.stats['after_dedupe']
    if total == 0:
        return
    
    self.logger.info('MONITOR', 'Starting progress monitoring...')
    
    while any(w.is_alive() for w in workers) or not self.proxy_queue.empty():
        checked = self.stats['total_checked']
        valid = self.stats['valid']
        invalid = self.stats['invalid']
        
        if total > 0:
            progress = (checked / total) * 100
            bar_length = 50
            filled = int(bar_length * checked / total)
            bar = '█' * filled + '░' * (bar_length - filled)
            
            # Calculate rates
            elapsed = time.time() - self.start_time
            rate = checked / elapsed if elapsed > 0 else 0
            eta = (total - checked) / rate if rate > 0 else 0
            
            print(f"\r{C.BOLD}{C.C}[PROGRESS]{C.N} [{bar}] {progress:.1f}% | "
                  f"Checked: {C.B}{checked}/{total}{C.N} | "
                  f"Valid: {C.G}{valid}{C.N} | "
                  f"Invalid: {C.R}{invalid}{C.N} | "
                  f"Rate: {C.Y}{rate:.1f}/s{C.N} | "
                  f"ETA: {C.M}{int(eta)}s{C.N}", end='', flush=True)
        
        time.sleep(0.5)
    
    print()
    self.logger.success('MONITOR', 'Progress monitoring completed')

def print_final_stats(self):
    """Print comprehensive final statistics"""
    elapsed = time.time() - self.start_time
    
    print(f"\n{C.BOLD}{C.C}╔══════════════════════════════════════════════════════════════╗")
    print(f"║                    SCAN RESULTS                              ║")
    print(f"╚══════════════════════════════════════════════════════════════╝{C.N}\n")
    
    print(f"{C.BOLD}{C.Y}📊 General Statistics:{C.N}")
    print(f"  Total Downloaded: {C.C}{self.stats['downloaded']}{C.N}")
    print(f"  Total Loaded: {C.C}{self.stats['total_loaded']}{C.N}")
    print(f"  After Deduplication: {C.C}{self.stats['after_dedupe']}{C.N}")
    print(f"  Total Checked: {C.C}{self.stats['total_checked']}{C.N}")
    print(f"  Valid Proxies: {C.G}{self.stats['valid']}{C.N}")
    print(f"  Invalid Proxies: {C.R}{self.stats['invalid']}{C.N}")
    
    if self.stats['total_checked'] > 0:
        success_rate = (self.stats['valid'] / self.stats['total_checked']) * 100
        print(f"  Success Rate: {C.G}{success_rate:.2f}%{C.N}")
    
    print(f"\n{C.BOLD}{C.Y}🚀 By Speed:{C.N}")
    print(f"  Fast (<1s): {C.G}{self.stats['by_speed']['fast']}{C.N}")
    print(f"  Medium (1-3s): {C.Y}{self.stats['by_speed']['medium']}{C.N}")
    print(f"  Slow (>3s): {C.R}{self.stats['by_speed']['slow']}{C.N}")
    
    print(f"\n{C.BOLD}{C.Y}🔒 By Anonymity:{C.N}")
    for anon_type, count in self.stats['by_anonymity'].items():
        print(f"  {anon_type.capitalize()}: {C.C}{count}{C.N}")
    
    print(f"\n{C.BOLD}{C.Y}🌐 By Type:{C.N}")
    for ptype, count in self.stats['by_type'].items():
        print(f"  {ptype.upper()}: {C.C}{count}{C.N}")
    
    print(f"\n{C.BOLD}{C.Y}🌍 Top 15 Countries:{C.N}")
    top_countries = sorted(self.stats['by_country'].items(), 
                         key=lambda x: x[1], reverse=True)[:15]
    for country, count in top_countries:
        print(f"  {country:>20}: {C.G}{count}{C.N}")
    
    # Classification summary
    summary = self.classifier.generate_summary()
    print(f"\n{C.BOLD}{C.Y}📁 Classification Summary:{C.N}")
    print(f"  Total files created: {C.C}{summary['total_files']}{C.N}")
    print(f"  Results saved in: {C.G}classified_proxies/{C.N}")
    
    print(f"\n{C.BOLD}{C.Y}⏱️  Performance:{C.N}")
    print(f"  Total time: {C.C}{elapsed:.2f}s{C.N}")
    if elapsed > 0:
        rate = self.stats['total_checked'] / elapsed
        print(f"  Average rate: {C.C}{rate:.2f} proxies/sec{C.N}")
    
    print(f"\n{C.BOLD}{C.G}✅ Scan completed successfully!{C.N}\n")

def run(self):
    """Main execution flow"""
    # Step 1: Load scrapers
    scrapers = self.load_scrapers()
    if not scrapers:
        self.logger.error('MAIN', 'No scrapers loaded. Exiting.')
        return
    
    # Step 2: Download proxies
    self.logger.info('MAIN', 'Starting proxy download phase...')
    files = self.downloader.download_from_scrapers(scrapers)
    self.stats['downloaded'] = len(files)
    
    if not files:
        self.logger.error('MAIN', 'No proxy files downloaded. Exiting.')
        return
    
    # Step 3: Load proxies from files
    proxy_list = self.load_proxies_from_files()
    if not proxy_list:
        self.logger.error('MAIN', 'No proxies loaded. Exiting.')
        return
    
    # Step 4: Remove duplicates
    proxy_list = self.remove_duplicates(proxy_list)
    
    # Step 5: Process batch
    proxy_list = self.process_batch(proxy_list)
    
    # Step 6: Start workers
    workers = self.start_workers(self.threads_count)
    
    # Step 7: Queue proxies
    self.logger.info('MAIN', f'Queuing {len(proxy_list)} proxies for checking...')
    for proxy in proxy_list:
        self.proxy_queue.put(proxy)
    
    # Step 8: Monitor progress
    self.monitor_progress(workers)
    
    # Wait for completion
    self.proxy_queue.join()
    
    # Stop workers
    for _ in range(self.threads_count):
        self.proxy_queue.put(None)
    
    for w in workers:
        w.join()
    
    # Step 9: Print results
    self.print_final_stats()
    
    self.logger.success('MAIN', 'Scanner completed successfully!')
```

def main():
parser = argparse.ArgumentParser(
description=‘DarkJPT Advanced Proxy Scanner’,
formatter_class=argparse.RawDescriptionHelpFormatter,
epilog=”””
Examples:
python scanprx.py –type http,https –threads 200
python scanprx.py –type socks5 –log –batch 500
python scanprx.py –type http,https,socks4,socks5 –log –threads 300
“””
)

```
parser.add_argument('--type', default='http,https,socks4,socks5',
                   help='Proxy types to scan (comma separated)')
parser.add_argument('--threads', type=int, default=100,
                   help='Number of worker threads (default: 100)')
parser.add_argument('--timeout', type=int, default=5000,
                   help='Timeout in milliseconds (default: 5000)')
parser.add_argument('--batch', type=int, default=1000,
                   help='Maximum proxies to check (default: 1000)')
parser.add_argument('--check', type=int, default=1,
                   help='Number of validation attempts per proxy (default: 1)')
parser.add_argument('--log', action='store_true',
                   help='Enable detailed file logging and animated banner')

args = parser.parse_args()

# Initialize logger
logger = Logger(enable_file_log=args.log)

# Show animated banner if --log is enabled
if args.log:
    banner = AnimatedBanner()
    banner_thread = Thread(target=banner.run_animation, daemon=True)
    banner_thread.start()
    
    # Let banner run then stop it
    time.sleep(50)  # 10s disappear + 10s appear + 30s rainbow
    banner.stop()
    banner_thread.join(timeout=1)
    
    # Clear screen for main output
    os.system('clear' if os.name != 'nt' else 'cls')

# Print static banner
print(f"{C.C}{C.BOLD}")
print("╔═══════════════════════════════════════════════════════════╗")
print("║                                                           ║")
print("║     ██████╗  █████╗ ██████╗ ██╗  ██╗     ██╗██████╗     ║")
print("║     ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝     ██║██╔══██╗    ║")
print("║     ██║  ██║███████║██████╔╝█████╔╝      ██║██████╔╝    ║")
print("║     ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██   ██║██╔═══╝     ║")
print("║     ██████╔╝██║  ██║██║  ██║██║  ██╗╚█████╔╝██║         ║")
print("║     ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚════╝ ╚═╝         ║")
print("║                                                           ║")
print("║         Advanced Proxy Scanner & Validator v3.0           ║")
print("║                Professional Edition                        ║")
print("║                                                           ║")
print("╚═══════════════════════════════════════════════════════════╝")
print(f"{C.N}\n")

logger.info('STARTUP', 'DarkJPT Proxy Scanner initialized')
logger.info('STARTUP', f'Configuration: Types={args.type}, Threads={args.threads}, '
            f'Timeout={args.timeout}ms, Batch={args.batch}')

# Create scanner and run
scanner = ProxyScanner(args, logger)

try:
    scanner.run()
except KeyboardInterrupt:
    logger.warning('MAIN', 'Scan interrupted by user')
    print(f"\n{C.Y}Scan interrupted. Partial results saved.{C.N}\n")
except Exception as e:
    logger.error('MAIN', f'Fatal error: {e}')
    print(f"\n{C.R}Fatal error occurred: {e}{C.N}\n")
```

if **name** == ‘**main**’:
main()
