"""
Module 1: RECON — Passive Reconnaissance & Asset Discovery
Chains: subfinder → dnsx → httpx → theHarvester → structured JSON database

Usage:
    python3 modules/recon.py --target example.com
    python3 modules/recon.py --target example.com --output report.json
"""

import sys, os, json, subprocess, sqlite3, time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


class ReconModule:
    """Passive reconnaissance module — finds everything about a target without touching it"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or str(Path(__file__).parent.parent / "db" / "recon.db")
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
        
    def _init_db(self):
        """Initialize persistent knowledge base"""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT UNIQUE,
                    first_seen TEXT,
                    last_seen TEXT,
                    status TEXT DEFAULT 'active'
                );
                CREATE TABLE IF NOT EXISTS subdomains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    subdomain TEXT,
                    resolved_ip TEXT,
                    http_status INTEGER,
                    http_title TEXT,
                    tech_stack TEXT,
                    first_seen TEXT,
                    UNIQUE(target, subdomain)
                );
                CREATE TABLE IF NOT EXISTS dns_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    subdomain TEXT,
                    record_type TEXT,
                    record_value TEXT
                );
                CREATE TABLE IF NOT EXISTS osint_emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    email TEXT,
                    source TEXT,
                    first_seen TEXT
                );
                CREATE TABLE IF NOT EXISTS recon_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    subdomains_found INTEGER,
                    live_hosts_found INTEGER,
                    emails_found INTEGER,
                    status TEXT
                );
            """)
    
    # ─── PHASE 1: Subdomain Enumeration ───────────────────
    
    def enumerate_subdomains(self, target: str, timeout: int = 120) -> Dict[str, Any]:
        """Use subfinder + alternative methods to find all subdomains"""
        result = {
            'tool': 'subfinder',
            'target': target,
            'subdomains': [],
            'status': 'unknown',
            'error': None
        }
        
        try:
            if os.path.isfile('/usr/local/bin/subfinder'):
                proc = subprocess.run(
                    ['/usr/local/bin/subfinder', '-d', target, '-silent', '-json'],
                    capture_output=True, text=True, timeout=timeout
                )
                for line in proc.stdout.strip().splitlines():
                    try:
                        data = json.loads(line)
                        sub = data.get('host', data.get('subdomain', ''))
                        if sub and sub not in result['subdomains']:
                            result['subdomains'].append(sub)
                    except:
                        if line.strip() and line.strip() not in result['subdomains']:
                            result['subdomains'].append(line.strip())
                
                result['status'] = 'success'
                result['count'] = len(result['subdomains'])
            
            else:
                # Fallback: use pure Python DNS brute-forcing
                result['status'] = 'fallback_python'
                result['subdomains'] = self._python_subdomain_enum(target)
                result['count'] = len(result['subdomains'])
                
        except subprocess.TimeoutExpired:
            result['status'] = 'timeout'
            result['error'] = f'Subfinder timed out after {timeout}s'
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
            result['subdomains'] = self._python_subdomain_enum(target)
        
        # Save to database
        self._save_subdomains(target, result['subdomains'])
        return result
    
    def _python_subdomain_enum(self, target: str) -> List[str]:
        """Fallback: DNS-based subdomain enumeration using scapy/socket"""
        import socket, concurrent.futures
        
        common_prefixes = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
            'blog', 'wiki', 'dev', 'staging', 'test', 'api', 'cdn',
            'app', 'admin', 'portal', 'dashboard', 'status', 'docs',
            'help', 'support', 'news', 'shop', 'store', 'forum',
            'git', 'jira', 'confluence', 'slack', 'mattermost',
            'monitoring', 'grafana', 'prometheus', 'jenkins',
            's3', 'assets', 'static', 'media', 'images',
            'auth', 'login', 'sso', 'oauth', 'idp',
            'db', 'mysql', 'postgres', 'redis', 'mongo',
            'vpn', 'ssh', 'proxy', 'lb', 'loadbalancer',
        ]
        
        found = []
        
        def check_sub(prefix):
            subdomain = f"{prefix}.{target}"
            try:
                socket.getaddrinfo(subdomain, None)
                return subdomain
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_sub, p): p for p in common_prefixes}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        
        return found
    
    # ─── PHASE 2: DNS Verification ────────────────────────
    
    def dns_verify(self, target: str, subdomains: List[str], timeout: int = 60) -> Dict[str, Any]:
        """Verify DNS records and resolve IPs using dnsx or Python fallback"""
        result = {
            'verified_subdomains': [],
            'failed_subdomains': [],
            'dns_records': {},
        }
        
        try:
            if os.path.isfile('/usr/local/bin/dnsx'):
                subs_str = '\n'.join(subdomains)
                proc = subprocess.run(
                    ['/usr/local/bin/dnsx', '-silent', '-resp', '-a', '-aaaa', '-cname', '-mx', '-ns', '-soa', '-txt'],
                    input=subs_str, capture_output=True, text=True, timeout=timeout
                )
                
                for line in proc.stdout.strip().splitlines():
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        sub = parts[0]
                        result['verified_subdomains'].append(sub)
                        result['dns_records'][sub] = line
            else:
                # Python fallback
                import socket
                for sub in subdomains:
                    try:
                        addrs = socket.getaddrinfo(sub, None)
                        ips = list(set(a[4][0] for a in addrs))
                        result['verified_subdomains'].append(sub)
                        result['dns_records'][sub] = str(ips)
                    except:
                        result['failed_subdomains'].append(sub)
                        
                    if len(result) >= 10000:
                        break
        
        except Exception as e:
            result['error'] = str(e)
            if not result['verified_subdomains']:
                import socket
                for sub in subdomains:
                    try:
                        addrs = socket.getaddrinfo(sub, None)
                        ips = list(set(a[4][0] for a in addrs))
                        result['verified_subdomains'].append(sub)
                        result['dns_records'][sub] = str(ips)
                    except:
                        result['failed_subdomains'].append(sub)
        
        return result
    
    # ─── PHASE 3: HTTP Probing ────────────────────────────
    
    def http_probe(self, subdomains: List[str], timeout: int = 120) -> Dict[str, Any]:
        """Probe HTTP/HTTPS services on all verified subdomains"""
        result = {
            'live_hosts': [],
            'dead_hosts': [],
            'technologies': {},
        }
        
        try:
            if os.path.isfile('/usr/local/bin/httpx'):
                subs_str = '\n'.join(subdomains)
                proc = subprocess.run(
                    ['/usr/local/bin/httpx', '-silent', '-json',
                     '-status-code', '-title', '-tech-detect', '-web-server',
                     '-content-length', '-follow-redirects'],
                    input=subs_str, capture_output=True, text=True, timeout=timeout
                )
                
                for line in proc.stdout.strip().splitlines():
                    try:
                        data = json.loads(line)
                        host = data.get('input', data.get('url', ''))
                        if host:
                            result['live_hosts'].append({
                                'url': data.get('url', host),
                                'host': host,
                                'status_code': data.get('status_code', 0),
                                'title': data.get('title', ''),
                                'tech': data.get('tech', []),
                                'web_server': data.get('webserver', ''),
                                'content_length': data.get('content_length', 0),
                            })
                    except:
                        pass
            else:
                # Python fallback: try HTTP/HTTPS requests
                import requests, concurrent.futures
                schemes = ['https', 'http']
                
                def probe_host(host):
                    for scheme in schemes:
                        url = f"{scheme}://{host}"
                        try:
                            r = requests.get(url, timeout=5, verify=False, 
                                           allow_redirects=True)
                            return {
                                'url': r.url,
                                'host': host,
                                'status_code': r.status_code,
                                'title': getattr(r, 'title', ''),
                                'tech': [],
                                'web_server': r.headers.get('Server', ''),
                                'content_length': len(r.content)
                            }
                        except:
                            continue
                    return None
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    futures = {executor.submit(probe_host, s): s for s in subdomains}
                    for f in concurrent.futures.as_completed(futures):
                        r = f.result()
                        if r:
                            result['live_hosts'].append(r)
                        else:
                            result['dead_hosts'].append(futures[f])
        except Exception as e:
            result['error'] = str(e)
        
        # Save to database
        self._save_http_results(result['live_hosts'])
        return result
    
    # ─── PHASE 4: OSINT ───────────────────────────────────
    
    def osint_gather(self, target: str, timeout: int = 120) -> Dict[str, Any]:
        """Gather OSINT data — emails, URLs, subdomains from public sources"""
        result = {
            'emails': [],
            'urls': [],
            'subdomains': [],
            'ips': [],
            'status': 'unknown',
        }
        
        try:
            # Try theHarvester via python -m
            proc = subprocess.run(
                ['python3', '-m', 'theHarvester', '-d', target, '-b',
                 'google,bing,duckduckgo,brave,baidu',
                 '-l', '200', '-f', '/tmp/osint_results'],
                capture_output=True, text=True, timeout=timeout
            )
            result['status'] = 'success'
            result['raw_output'] = proc.stdout[:5000]
            
            # Parse emails from output
            import re
            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', proc.stdout)
            result['emails'] = list(set(emails))
            self._save_emails(target, result['emails'], 'theHarvester')
            
        except subprocess.TimeoutExpired:
            # Fallback: manual Google/Bing search simulation
            result['status'] = 'timeout_fallback'
        except Exception as e:
            result['status'] = f'error: {e}'
        
        return result
    
    # ─── PHASE 5: Web Crawling ────────────────────────────
    
    def web_crawl(self, urls: List[str], depth: int = 1, timeout: int = 180) -> Dict[str, Any]:
        """Crawl web applications to find all endpoints"""
        result = {
            'urls_found': [],
            'forms': [],
            'js_files': [],
            'params': [],
        }
        
        for url in urls[:10]:  # Limit to 10 URLs
            try:
                if os.path.isfile('/usr/local/bin/katana'):
                    proc = subprocess.run(
                        ['/usr/local/bin/katana', '-u', url, 
                         '-d', str(depth), '-silent', '-f', 'json',
                         '-o', f'/tmp/katana_{url.replace("://","_").replace("/","_")}.json'],
                        capture_output=True, text=True, timeout=timeout
                    )
                    
                    import os
                    output_file = f'/tmp/katana_{url.replace("://","_").replace("/","_")}.json'
                    if os.path.exists(output_file):
                        with open(output_file) as f:
                            for line in f:
                                try:
                                    data = json.loads(line)
                                    result['urls_found'].append(data)
                                except:
                                    pass
                    
                else:
                    # Python fallback: use BeautifulSoup
                    import requests
                    from bs4 import BeautifulSoup
                    from urllib.parse import urljoin, urlparse
                    
                    r = requests.get(url, timeout=10, verify=False)
                    soup = BeautifulSoup(r.content, 'html.parser')
                    
                    # Extract all links
                    for link in soup.find_all('a', href=True):
                        full_url = urljoin(url, link['href'])
                        result['urls_found'].append(full_url)
                    
                    # Extract forms
                    for form in soup.find_all('form'):
                        result['forms'].append({
                            'action': form.get('action', ''),
                            'method': form.get('method', 'get'),
                            'inputs': [(i.get('name'), i.get('type')) 
                                      for i in form.find_all('input')]
                        })
                    
                    # Extract JS files
                    for script in soup.find_all('script', src=True):
                        result['js_files'].append(urljoin(url, script['src']))
                        
                    # Extract parameters from URLs
                    for u in result['urls_found']:
                        if '?' in str(u):
                            parsed = urlparse(str(u))
                            for param, value in parsed.params.split('&'):
                                result['params'].append({'url': str(u), 'param': param, 'value': value})
                            
            except Exception as e:
                result[f'error_{url}'] = str(e)
        
        return result
    
    # ─── FULL RECON PIPELINE ─────────────────────────────
    
    def run_full_recon(self, target: str, verbose: bool = True) -> Dict[str, Any]:
        """Execute complete reconnaissance chain"""
        if verbose:
            print(f"🎯 ZETA ∞ RECON: {target}")
            print("=" * 60)
        
        recon_data = {'target': target, 'start_time': datetime.utcnow().isoformat()}
        
        # Step 1: Subdomain Enumeration
        if verbose: print(f"\n[1/5] Enumerating subdomains...")
        subs = self.enumerate_subdomains(target)
        recon_data['subdomains'] = subs
        if verbose: print(f"  Found {subs.get('count', len(subs.get('subdomains', [])))} subdomains")
        
        # Step 2: DNS Verification
        if subs.get('subdomains'):
            if verbose: print(f"\n[2/5] Verifying DNS...")
            dns = self.dns_verify(target, subs['subdomains'])
            recon_data['dns'] = dns
            if verbose: print(f"  Verified {len(dns.get('verified_subdomains', []))} domains")
            
            verified = dns.get('verified_subdomains', subs['subdomains'])
        else:
            verified = []
        
        # Step 3: HTTP Probing
        if verified:
            if verbose: print(f"\n[3/5] Probing HTTP services...")
            http = self.http_probe(verified)
            recon_data['http'] = http
            if verbose: print(f"  Found {len(http.get('live_hosts', []))} live hosts")
        
        # Step 4: OSINT
        if verbose: print(f"\n[4/5] Gathering OSINT...")
        osint = self.osint_gather(target)
        recon_data['osint'] = osint
        if verbose: print(f"  Found {len(osint.get('emails', []))} emails")
        
        # Step 5: Web Crawling (if live hosts found)
        if http and http.get('live_hosts'):
            if verbose: print(f"\n[5/5] Crawling web apps...")
            urls = [h.get('url', h.get('host')) for h in http['live_hosts'][:5]]
            crawl = self.web_crawl(urls)
            recon_data['crawl'] = crawl
            if verbose: print(f"  Found {len(crawl.get('urls_found', []))} URLs, {len(crawl.get('forms', []))} forms")
        
        recon_data['end_time'] = datetime.utcnow().isoformat()
        recon_data['summary'] = self._generate_summary(recon_data)
        
        if verbose:
            print("\n============================================================")

            print(f"\n📊 SUMMARY:")
            for k, v in recon_data['summary'].items():
                print(f"  {k}: {v}")
        
        return recon_data
    
    def _generate_summary(self, recon_data: Dict) -> Dict:
        """Generate human-readable summary"""
        return {
            'total_subdomains': len(recon_data.get('subdomains', {}).get('subdomains', [])),
            'verified_dns': len(recon_data.get('dns', {}).get('verified_subdomains', [])),
            'live_http_hosts': len(recon_data.get('http', {}).get('live_hosts', [])),
            'osint_emails': len(recon_data.get('osint', {}).get('emails', [])),
            'crawled_urls': len(recon_data.get('crawl', {}).get('urls_found', [])),
            'crawled_forms': len(recon_data.get('crawl', {}).get('forms', [])),
        }
    
    # ─── Database Helpers ─────────────────────────────────
    
    def _save_subdomains(self, target: str, subdomains: List[str]):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO targets (target, first_seen, last_seen) VALUES (?,?,?)",
                        (target, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))
            for sub in subdomains:
                try:
                    conn.execute("INSERT OR IGNORE INTO subdomains (target, subdomain, first_seen) VALUES (?,?,?)",
                                (target, sub, datetime.utcnow().isoformat()))
                except:
                    pass
    
    def _save_http_results(self, hosts: List[Dict]):
        with sqlite3.connect(self.db_path) as conn:
            for h in hosts:
                try:
                    conn.execute("""
                        INSERT OR REPLACE INTO subdomains 
                        (target, subdomain, resolved_ip, http_status, http_title, tech_stack, first_seen)
                        VALUES (?,?,?,?,?,?,?)
                    """, (
                        h.get('host', '').split(':')[0],
                        h.get('url', h.get('host')),
                        h.get('status_code'),
                        h.get('title', ''),
                        json.dumps(h.get('tech', [])),
                        datetime.utcnow().isoformat()
                    ))
                except:
                    pass
    
    def _save_emails(self, target: str, emails: List[str], source: str):
        with sqlite3.connect(self.db_path) as conn:
            for email in emails:
                conn.execute("INSERT OR IGNORE INTO osint_emails (target, email, source, first_seen) VALUES (?,?,?,?)",
                            (target, email, source, datetime.utcnow().isoformat()))
    
    def _save_run(self, target: str, summary: Dict):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO recon_runs 
                (target, start_time, end_time, subdomains_found, live_hosts_found, emails_found, status)
                VALUES (?,?,?,?,?,?,?)
            """, (target, datetime.utcnow().isoformat(), datetime.utcnow().isoformat(),
                 summary.get('total_subdomains', 0),
                 summary.get('live_http_hosts', 0),
                 summary.get('osint_emails', 0),
                 'completed'))


# ─── CLI Entry Point ──────────────────────────────────────────
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="ZETA ∞ Recon Module")
    parser.add_argument('--target', '-t', required=True)
    parser.add_argument('--output', '-o', help='Save to JSON file')
    parser.add_argument('--db', help='Database path', default=str(Path(__file__).parent.parent / "db" / "recon.db"))
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress output')
    args = parser.parse_args()
    
    recon = ReconModule(db_path=args.db)
    result = recon.run_full_recon(args.target, verbose=not args.quiet)
    
    if args.output:
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        if not args.quiet:
            print(f"\n📁 Report saved to: {args.output}")
