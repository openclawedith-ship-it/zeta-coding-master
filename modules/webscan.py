#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════
  WEBSCAN — Web Application Vulnerability Scanner
═══════════════════════════════════════════════════════════
Chains: sqlmap → gobuster/ffuf → sslyze → wpscan
        + Python native fallbacks for ALL of them

Think of this as nikto/dirbuster/whatweb/sqlmap combined
into one module that degrades gracefully when tools are
missing — the Python fallbacks always work.

Usage:
    python3 modules/webscan.py --target https://example.com
    python3 modules/webscan.py --target https://example.com -o report.json
    python3 modules/webscan.py --target https://example.com --quick   # tech + headers only
"""

import os, sys, json, subprocess, ssl, socket
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Bootstrap ─────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
from knowledge import KnowledgeBase

class WebscanModule:
    """Web application vulnerability scanner — auto-chains tools + Python fallbacks"""

    WORDLIST_WEB = [
        # Auth
        "admin", "admin/", "admin.php", "login", "login.php",
        "login.html", "register", "auth", "authenticate",
        "signin", "signup", "account", "user", "dashboard",
        # Files & Config
        ".git", ".git/config", ".env", ".env.bak", "config.php",
        "config.json", "config.yml", "config.xml", ".htaccess",
        ".htpasswd", "robots.txt", "sitemap.xml", "crossdomain.xml",
        # CMS
        "wp-admin", "wp-login.php", "wp-content", "wp-includes",
        "wp-json", "xmlrpc.php", "administrator", "joomla",
        "joomla/administrator",
        # APIs
        "api", "api/v1", "api/v2", "api/v3", "graphql", "graphiql",
        "swagger", "swagger-ui.html", "swagger.json", "api-docs",
        "swagger-ui", "openapi.json", "redoc",
        # Server
        "phpmyadmin", "phpMyAdmin", "pma", "server-status",
        "server-info", "phpinfo.php", "info.php", "test.php",
        "debug", "console", "trace", "elmah.axd",
        # Backups & Leaks
        "backup", "backup.zip", "backup.sql", "db.sql", "dump.sql",
        "database.sql", "backup.tar.gz", "backup.tgz", ".backup",
        "old", "temp", "tmp", "test", "dev", "staging",
        # Misc
        "uploads", "upload", "download", "files", "documents",
        "phpinfo.php", "install.php", "setup.php",
    ]

    SENSITIVE_PATHS = {
        ".git": ("critical", "Git repository exposed"),
        ".env": ("critical", "Environment file with secrets"),
        ".htaccess": ("medium", "Apache configuration exposed"),
        ".htpasswd": ("critical", "Password file exposed"),
        "config.php": ("high", "PHP config file exposed"),
        "config.json": ("high", "Configuration file exposed"),
        "phpmyadmin": ("high", "PhpMyAdmin exposed"),
        "server-status": ("medium", "Apache server-status exposed"),
        "phpinfo.php": ("medium", "PHP info exposed"),
        "debug": ("medium", "Debug endpoint exposed"),
        "console": ("medium", "Admin console exposed"),
    }

    def __init__(self):
        self.wordlist = _ROOT / "data" / "wordlist_web.txt"
        self._ensure_wordlist()
        self.kb = KnowledgeBase()
        self._session_id = f"webscan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        self.findings: List[Dict] = []

    def _ensure_wordlist(self):
        wl_dir = self.wordlist.parent
        if not wl_dir.is_dir():
            wl_dir.mkdir(parents=True, exist_ok=True)
        if not self.wordlist.is_file():
            with open(self.wordlist, 'w') as f:
                f.write('\n'.join(self.WORDLIST_WEB))

    @staticmethod
    def _has(bin_name: str) -> bool:
        try:
            return subprocess.run(
                ['which', bin_name], capture_output=True
            ).returncode == 0
        except Exception:
            return False

    def _add_finding(self, target: str, tool: str,
                      severity: str, vuln_name: str,
                      detail: str, url: str = ""):
        entry = dict(
            module='webscan', target=target, tool=tool,
            severity=severity, vulnerability=vuln_name,
            finding=detail, url=url or target,
            timestamp=datetime.utcnow().isoformat())
        self.findings.append(entry)
        self.kb.add_vulnerability(entry)
        return entry

    # ├── Phase 1: Technology Detection ────────────────────────

    def detect_tech(self, target: str) -> Dict:
        """Detect server, framework, CMS, language — uses requests + header analysis"""
        import requests
        result = dict(target=target, tool='tech_detect',
                      technologies=[], missing_headers=[],
                      status=None)
        try:
            resp = requests.get(
                target, timeout=10, verify=False,
                allow_redirects=True)
            headers = {k.lower(): v
                        for k, v in resp.headers.items()}
            result['status'] = resp.status_code
            html = resp.text.lower()[:20000]

            # Server
            srv = headers.get('server', '')
            if srv:
                result['server'] = srv

            # Power header
            xpb = headers.get('x-powered-by', '')
            if xpb:
                result['x_powered_by'] = xpb

            # Tech detection rules
            rules = {
                'WordPress': ['wp-content', 'wp-includes',
                              'wp-json', '/wp-'],
                'Drupal': ['Drupal', 'drupal.js'],
                'Joomla': ['joomla', '/media/jui/'],
                'Laravel': ['laravel_session',
                            'laravel_token'],
                'Django': ['csrftoken', 'Django'],
                'React': ['<div id="root"', '"react"',
                          'react-dom'],
                'Vue.js': ['<div id="app"', 'vue.js',
                           '__vue__'],
                'Angular': ['ng-app', 'ng-version',
                            'angular.js'],
                'jQuery': ['jquery'],
                'Bootstrap': ['bootstrap.css', 'bootstrap.js'],
                'Cloudflare': ['cloudflare', 'cf-ray'],
                'Nginx': ['nginx'] if 'nginx' in headers.get('server', '').lower() else [],
                'Apache': ['apache'] if 'apache' in headers.get('server', '').lower() else [],
                'IIS': ['iis'] if 'iis' in headers.get('server', '').lower() else [],
            }
            for tech, indicators in rules.items():
                if indicators and any(ind in html for ind in indicators):
                    result['technologies'].append(tech)
                    self._add_finding(
                        target, 'tech_detect', 'info',
                        'Technology Detected',
                        f"Detected {tech}", target)

            # Language via cookie/headers
            cookies = headers.get('set-cookie', '').lower()
            if 'phpsessid' in cookies:
                result['technologies'].append('PHP')
            if 'jsessionid' in cookies:
                result['technologies'].append('Java')
            if 'asp.net' in cookies or 'asp.net' in headers.get('x-aspnet-version', ''):
                result['technologies'].append('ASP.NET')

            # Security headers check
            required = [
                'strict-transport-security',
                'content-security-policy',
                'x-frame-options',
                'x-content-type-options',
                'x-xss-protection']
            for rh in required:
                if rh not in headers:
                    result['missing_headers'].append(rh)
            if result['missing_headers']:
                self._add_finding(
                    target, 'headers', 'low',
                    'Missing Security Headers',
                    f"Missing: {', '.join(result['missing_headers'])}",
                    target)

        except Exception as e:
            result['error'] = str(e)
        return result

    # ├── Phase 2: Directory/File Discovery ───────────────────

    def scan_directories(self, target: str,
                          threads: int = 20) -> List[Dict]:
        """Find hidden paths using gobuster → ffuf → Python fallback"""
        base = target.rstrip('/')
        results = []

        if self._has('gobuster'):
            wl = str(self.wordlist)
            cmd = [
                'gobuster', 'dir', '-u', base,
                '-w', wl, '-t', str(threads),
                '-q', '--no-error', '-k',
                '-x', 'php,html,txt,js,json,xml,bak,zip,tar.gz,sql,env,config']
            try:
                p = subprocess.run(cmd, capture_output=True,
                                    text=True, timeout=120)
                for line in p.stdout.splitlines():
                    if '(Status:' not in line:
                        continue
                    parts = line.split()
                    status = 0
                    path = parts[-1] if parts else ''
                    for p in parts:
                        if 'Status:' in p:
                            try:
                                status = int(
                                    p.replace('(', '').replace(
                                        'Status:', '').replace(')', ''))
                            except ValueError:
                                pass
                    if status and path:
                        sev, desc = self.SENSITIVE_PATHS.get(
                            path, ('medium', f'HTTP {status}'))
                        if status == 200 and desc == f'HTTP {status}':
                            desc = 'Accessible file/directory'
                        self._add_finding(
                            base, 'gobuster', sev,
                            desc, f'{path} returned {status}',
                            f"{base}/{path}")
                        results.append({
                            'path': path, 'status': status,
                            'tool': 'gobuster'})
            except Exception as e:
                print(f"    ⚠  gobuster failed: {e}")

        elif self._has('ffuf'):
            wl = str(self.wordlist)
            out_json = f'/tmp/ffuf_{os.getpid()}.json'
            cmd = [
                'ffuf', '-w', wl,
                '-u', f'{base}/FUZZ',
                '-t', str(threads), '-fc', '404',
                '-o', out_json, '-of', 'json']
            try:
                p = subprocess.run(cmd, capture_output=True,
                                    text=True, timeout=120)
                if os.path.isfile(out_json):
                    with open(out_json) as f:
                        data = json.load(f)
                    for item in data.get('results', []):
                        path = item.get('url', '').replace(
                            base, '').lstrip('/')
                        status = item.get('status', 0)
                        sev, desc = self.SENSITIVE_PATHS.get(
                            path, ('medium', f'HTTP {status}'))
                        self._add_finding(
                            base, 'ffuf', sev, desc,
                            f'{path} returned {status}',
                            item.get('url', ''))
                        results.append({
                            'path': path, 'status': status,
                            'tool': 'ffuf'})
            except Exception as e:
                print(f"    ⚠  ffuf failed: {e}")
        else:
            # ── Python native directory scan ──
            import requests as req
            print(f"    [Python fallback — checking "
                  f"{len(self.WORDLIST_WEB)} paths...]")

            def probe(path_entry):
                try:
                    r = req.get(
                        f"{base}/{path_entry}",
                        timeout=4, verify=False,
                        allow_redirects=False)
                    if r.status_code != 404:
                        sev, desc = self.SENSITIVE_PATHS.get(
                            path_entry,
                            ('medium',
                             f'HTTP {r.status_code}'))
                        self._add_finding(
                            base, 'python', sev, desc,
                            f'{path_entry} → {r.status_code}',
                            f"{base}/{path_entry}")
                        return {
                            'path': path_entry,
                            'status': r.status_code,
                            'tool': 'python'}
                except req.RequestException:
                    pass
                return None

            with ThreadPoolExecutor(
                    max_workers=threads) as pool:
                futures = {
                    pool.submit(probe, p): p
                    for p in self.WORDLIST_WEB}
                for f in as_completed(futures):
                    r = f.result()
                    if r:
                        results.append(r)

        return results

    # ├── Phase 3: SQL Injection ─────────────────────────────

    def scan_sqli(self, target: str) -> List[Dict]:
        """SQL injection testing: sqlmap → python heuristic"""
        import requests
        results = []

        if self._has('sqlmap'):
            print(f"    [Running sqlmap (may take a "
                   f"few minutes)...]")
            try:
                p = subprocess.run(
                    ['sqlmap', '-u', target, '--batch',
                     '--level', '2', '--risk', '2',
                     '--random-agent', '--threads', '3',
                     '--output-dir',
                     f'/tmp/sqlmap_{os.getpid()}',
                     '--technique', 'BEUSTQ',
                     '--timeout', '10', '--retries', '2'],
                    capture_output=True, text=True,
                    timeout=300)
                out = p.stdout + p.stderr
                is_vuln = 'is vulnerable' in out.lower()
                technique = 'unknown'
                if 'boolean' in out.lower():
                    technique = 'boolean blind'
                elif 'time' in out.lower():
                    technique = 'time-based blind'
                elif 'error' in out.lower():
                    technique = 'error-based'
                elif 'union' in out.lower():
                    technique = 'UNION query'
                sev = 'critical' if is_vuln else 'info'
                detail = (
                    f"SQL Injection ({technique})"
                    if is_vuln
                    else 'No SQLi detected')
                self._add_finding(
                    target, 'sqlmap', sev, 'SQL Injection',
                    detail, target)
                results.append({
                    'tool': 'sqlmap',
                    'vulnerable': is_vuln,
                    'technique': technique})
                if is_vuln:
                    print(f"    🔴 CRITICAL: SQL Injection "
                          f"found ({technique})")
            except subprocess.TimeoutExpired:
                results.append({
                    'tool': 'sqlmap', 'error': 'timeout'})
            except Exception as e:
                results.append({
                    'tool': 'sqlmap', 'error': str(e)})

        # ── Python heuristic fallback ──
        tests = [
            ("'", "SQL syntax error"),
            ("\" OR 1=1 --", "Boolean-based"),
            ("\" OR 1=1#", "Boolean-based"),
            ("\" AND 1=0 --", "Differential"),
            ("\" ORDER BY 99999 --",
             "Column count error"),
            ("\" UNION SELECT NULL --",
             "UNION-based"),
        ]
        try:
            base = requests.get(
                target, timeout=10, verify=False)
            base_len = len(base.content)
            base_code = base.status_code
            base_title = ''
            import re as _re
            _m = _re.search(
                r'<title>(.*?)</title>', base.text,
                _re.DOTALL)
            if _m:
                base_title = _m.group(1).strip()

            for payload, label in tests:
                url = target + payload
                try:
                    r = requests.get(
                        url, timeout=8, verify=False)
                    diff = abs(
                        len(r.content) - base_len)
                    if diff > 200 and r.content:
                        self._add_finding(
                            target, 'python_sqli',
                            'medium',
                            f'Possible SQLi ({label})',
                            f'Payload "{payload}" caused '
                            f'response size change '
                            f'({base_len} → '
                            f'{len(r.content)}), '
                            f'status {r.status_code}',
                            url)
                        results.append({
                            'tool': 'python_sqli',
                            'payload': payload,
                            'suspicious': True,
                            'response_diff': diff})
                except requests.RequestException:
                    pass
        except Exception as e:
            results.append({
                'tool': 'python_sqli', 'error': str(e)})

        return results

    # ├── Phase 4: SSL/TLS Audit ─────────────────────────────

    def audit_ssl(self, target: str) -> Dict:
        """SSL/TLS analysis: sslyze → Python native"""
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.hostname or target.replace(
            'https://', '').replace(
            'http://', '').split(':')[0].split('/')[0]
        port = parsed.port or (443 if parsed.scheme == 'https'
                                else 80)
        result = dict(
            host=host, port=port,
            grade=None, protocols=[], ciphers=[])

        if self._has('sslyze'):
            out_json = f'/tmp/sslyze_{os.getpid()}.json'
            try:
                p = subprocess.run(
                    ['sslyze', '--json_out', out_json,
                     '--regular',
                     f'{host}:{port}'],
                    capture_output=True, text=True,
                    timeout=60)
                if os.path.isfile(out_json):
                    with open(out_json) as f:
                        data = json.load(f)
                    for sr in data.get(
                            'server_scan_results', []):
                        cmds = sr.get(
                            'scan_commands_results', {})
                        # Heartbleed
                        hb = cmds.get('heartbleed', {})
                        if hb.get('is_vulnerable'):
                            self._add_finding(
                                target, 'sslyze', 'critical',
                                'Heartbleed',
                                'Server IS vulnerable to '
                                'Heartbleed',
                                f'{host}:{port}')
                        # CCS injection
                        ccs = cmds.get(
                            'openssl_ccs_injection', {})
                        if ccs.get('is_vulnerable'):
                            self._add_finding(
                                target, 'sslyze', 'critical',
                                'CCS Injection',
                                'Server IS vulnerable to '
                                'OpenSSL CCS injection',
                                f'{host}:{port}')
                        # Certificate info
                        cert_info = cmds.get(
                            'certificate_info', {})
                        for dep in cert_info.get(
                                'certificate_deployments',
                                []):
                            chain = dep.get(
                                'received_certificate_chain',
                                [])
                            if chain:
                                cert = chain[0]
                                subj = cert.get(
                                    'subject', {}).get(
                                    'common_name', 'unknown')
                                not_after = cert.get(
                                    'not_valid_after', '')
                                result['cert_subject'] = subj
                                result['cert_expiry'] = \
                                    not_after
            except Exception as e:
                result['sslyze_error'] = str(e)

        # ── Python native SSL check ──
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(
                    (host, port), timeout=10) as sock:
                with ctx.wrap_socket(
                        sock, server_hostname=host) as s:
                    cert = s.getpeercert()
                    result['protocol'] = s.version()
                    result['cipher'] = s.cipher()
                    for rdn in cert.get('subject', ()):
                        for k, v in rdn:
                            if k == 'commonName':
                                result['cert_cn'] = v
                    for rdn in cert.get('issuer', ()):
                        for k, v in rdn:
                            if k == 'commonName':
                                result['issuer_cn'] = v
                    not_after = cert.get('notAfter', '')
                    result['cert_not_after'] = not_after
        except Exception as e:
            result['python_ssl_error'] = str(e)

        return result

    # ├── Phase 5: WordPress Scan ────────────────────────────

    def scan_wordpress(self, target: str) -> Dict:
        """WordPress vulnerability scan: wpscan → Python heuristic"""
        result = dict(target=target, is_wp=False,
                      version=None, plugins=[],
                      vulns_found=0)

        if self._has('wpscan'):
            print(f"    [Running wpscan...]")
            out_json = f'/tmp/wpscan_{os.getpid()}.json'
            try:
                p = subprocess.run(
                    ['wpscan', '--url', target,
                     '--random-user-agent',
                     '--enumerate', 'ap,p,tt,u,vt',
                     '--no-banner',
                     '--disable-tls-checks',
                     '-o', out_json, '-f', 'json',
                     '--no-update'],
                    capture_output=True, text=True,
                    timeout=180)
                if os.path.isfile(out_json):
                    with open(out_json) as f:
                        wp = json.load(f)
                    result['is_wp'] = True
                    ver = wp.get('version', {})
                    if ver.get('number'):
                        result['version'] = ver['number']
                    # Plugins
                    for pname, pdata in wp.get(
                            'plugins', {}).items():
                        plugin_entry = {
                            'name': pname,
                            'version': pdata.get(
                                'version', {}).get(
                                'number', 'unknown'),
                            'vulnerabilities': []}
                        for v in pdata.get(
                                'vulnerabilities', []):
                            plugin_entry[
                                'vulnerabilities'].append(
                                dict(
                                    title=v.get('title', ''),
                                    cve=v.get('references',
                                              {}).get(
                                            'cve', []),
                                    severity=v.get('cvss',
                                                   {}).get(
                                            'score', 'N/A')))
                            result['vulns_found'] += 1
                            self._add_finding(
                                target, 'wpscan', 'high',
                                'WP Plugin Vulnerability',
                                f"{pname}: {v.get('title')}",
                                target)
                        result['plugins'].append(
                            plugin_entry)
                    # WordPress vulns
                    for v in wp.get('main_theme', {}).get(
                            'vulnerabilities', []):
                        result['vulns_found'] += 1
                        self._add_finding(
                            target, 'wpscan', 'high',
                            'WP Theme Vulnerability',
                            v.get('title', ''), target)

            except Exception as e:
                result['wpscan_error'] = str(e)

        # ── Python fallback ──
        if not result['is_wp']:
            import requests as req
            try:
                paths_to_check = {
                    '/': 'wp-content',
                    '/wp-login.php': False,
                    '/wp-content/': True,
                    '/wp-includes/': True,
                    '/feed/': True,
                    '/robots.txt': True,
                }
                for path, check_200 in paths_to_check.items():
                    r = req.get(
                        target.rstrip('/') + path,
                        timeout=5, verify=False,
                        allow_redirects=False)
                    if check_200 and r.status_code == 200:
                        result['is_wp'] = True
                    elif not check_200 and (
                            'wp-content' in r.text or
                            'wordpress' in r.text.lower()
                            ):
                        result['is_wp'] = True
                if result['is_wp']:
                    self._add_finding(
                        target, 'python', 'info',
                        'WordPress Detected',
                        'WordPress indicators found',
                        target)
            except Exception:
                pass

        return result

    # ─── Master Orchestration ─────────────────────────────

    def scan(self, target: str, quick: bool = False
             ) -> Dict[str, Any]:
        """
        Full web application vulnerability scan.
        5 phases, each with tool chain + Python fallback.

        Returns a dict with:
          - target, scan_id, timestamp
          - findings: list of all findings
          - severity_counts: critical/high/medium/low/info
          - phase_times: how long each phase took
          - summary: one-liner
        """
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target

        print(f"🌐 WEBSCAN: {target}")
        print("═" * 60)

        scan_start = datetime.utcnow()
        scan_id = f"{self._session_id}"
        phase_times = {}

        # Phase 1
        print("  [1/5] Technology detection...")
        t0 = datetime.utcnow()
        tech = self.detect_tech(target)
        phase_times['tech'] = (
            datetime.utcnow() - t0).total_seconds()

        # Phase 2
        print("  [2/5] Directory discovery...")
        t0 = datetime.utcnow()
        dirs = self.scan_directories(target)
        phase_times['dirs'] = ((
            datetime.utcnow() - t0
        ).total_seconds())

        # Phase 3
        if not quick:
            print("  [3/5] SQL Injection...")
            t0 = datetime.utcnow()
            sqli = self.scan_sqli(target)
            phase_times['sqli'] = (
                datetime.utcnow() - t0).total_seconds()
        else:
            sqli = []
            phase_times['sqli'] = 0

        # Phase 4
        print("  [4/5] SSL/TLS audit...")
        t0 = datetime.utcnow()
        ssl_result = self.audit_ssl(target)
        phase_times['ssl'] = (
            datetime.utcnow() - t0).total_seconds()

        # Phase 5
        if not quick:
            print("  [5/5] WordPress scan...")
            t0 = datetime.utcnow()
            wp = self.scan_wordpress(target)
            phase_times['wp'] = (
                datetime.utcnow() - t0).total_seconds()
        else:
            wp = {}
            phase_times['wp'] = 0

        # ── Assemble report ──
        counts = dict(critical=0, high=0, medium=0,
                       low=0, info=0)
        for f in self.findings:
            s = f['severity']
            if s in counts:
                counts[s] += 1
        total = sum(counts.values())

        elapsed = (
            datetime.utcnow() - scan_start
        ).total_seconds()

        report = dict(
            module='webscan',
            scan_id=scan_id,
            target=target,
            timestamp=datetime.utcnow().isoformat(),
            findings=self.findings,
            severity_counts=counts,
            total_findings=total,
            phases_completed={
                'tech': tech,
                'directories': dirs,
                'sqli': sqli,
                'ssl': ssl_result,
                'wordpress': wp},
            phase_times=phase_times,
            elapsed_seconds=round(elapsed, 1),
            summary=(
                f"Webscan of {target}: "
                f"{counts['critical']} critical, "
                f"{counts['high']} high, "
                f"{counts['medium']} medium, "
                f"{counts['low']} low, "
                f"{counts['info']} info"))

        # Print summary
        print("\n" + "═" * 60)
        print(report['summary'])
        if counts['critical']:
            print(f"  🔴 {counts['critical']} CRITICAL")
        if counts['high']:
            print(f"  🟠 {counts['high']} HIGH")
        print(f"  ⏱  {elapsed:.0f}s total")
        print("=" * 60)

        return report


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(
        description="ZETA INFINITY — Web Scanner")
    p.add_argument('--target', '-t', required=True,
                   help='Target URL')
    p.add_argument('--output', '-o',
                   help='Save JSON report')
    p.add_argument('--quick', '-q', action='store_true',
                   help='Skip SQLi + WordPress')
    args = p.parse_args()

    w = WebscanModule()
    report = w.scan(args.target, quick=args.quick)

    if args.output:
        out_dir = os.path.dirname(args.output)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n  Report saved: {args.output}")

    _ROOT.mkdir(parents=True, exist_ok=True)
    report_path = _ROOT / 'reports' / \
        f"webscan_{datetime.utcnow().strftime(
            '%Y%m%d_%H%M%S')}.json"
    _ROOT.mkdir(parents=True, exist_ok=True)
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  Report saved: {report_path}")