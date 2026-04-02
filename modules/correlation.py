"""
Module 5: CORRELATION — Attack Path Detection & Risk Scoring

Takes vulnerabilities and findings from all modules and:
1. Calculates overall risk score (CVSS-like 0-10)
2. Identifies attack chains (vulns that can be combined)
3. Maps MITRE ATT&CK techniques to findings
4. Generates prioritized remediation list
5. Builds network topology from recon data
6. Ranks targets by exploitability
"""

import os, sys, json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple


class Correlator:
    """Correlate all findings into attack paths, risk score, and remediation priority"""

    # MITRE ATT&CK technique mapping
    MITRE_MAP = {
        'MS17-010': ('T1190', 'Exploit Public-Facing Application'),
        'SQL Injection': ('T1190', 'Exploit Public-Facing Application'),
        'Path Traversal': ('T1190', 'Exploit Public-Facing Application'),
        'XSS': ('T1189', 'Drive-by Compromise'),
        'CSRF': ('T1189', 'Drive-by Compromise'),
        'SSRF': ('T1190', 'Exploit Public-Facing Application'),
        'Command Injection': ('T1059', 'Command and Scripting Interpreter'),
        'Authentication Bypass': ('T1078', 'Valid Accounts'),
        'Privilege Escalation': ('T1068', 'Exploitation for Privilege Escalation'),
        'Exposed .git': ('T1005', 'Data from Local System'),
        'Exposed .env': ('T1552', 'Unsecured Credentials'),
        'Directory traversal': ('T1083', 'File and Directory Discovery'),
        'Open port': ('T1046', 'Network Service Scanning'),
        'SSH': ('T1021', 'Remote Services'),
        'RDP': ('T1021', 'Remote Services'),
        'SMB': ('T1021', 'Remote Services'),
        'FTP': ('T1048', 'Exfiltration Over Alternative Protocol'),
        'WordPress': ('T1190', 'Exploit Public-Facing Application'),
        'Outdated': ('T1190', 'Exploit Public-Facing Application'),
        'Missing security headers': ('T1040', 'Network Sniffing'),
        'Default credentials': ('T1078', 'Valid Accounts'),
        'Self-signed certificate': ('T1573', 'Encrypted Channel'),
        'Weak cipher': ('T1573', 'Encrypted Channel'),
        'HTTP': ('T1041', 'Exfiltration Over C2 Channel'),
    }

    # MITRE kill chain stages
    KILL_CHAIN = {
        'Reconnaissance': ['open port', 'subdomain', 'email', 'technology'],
        'Weaponization': ['vulnerability', 'MS17'],
        'Delivery': ['phishing', 'email'],
        'Exploitation': ['SQL Injection', 'XSS', 'Command Injection',
                        'Path Traversal', 'Authentication Bypass',
                        'SSRF', 'CSRF'],
        'Installation': ['backdoor', 'webshell', 'persistence'],
        'Command & Control': ['SSH', 'RDP', 'HTTP', 'reverse shell'],
        'Actions on Objectives': ['data', 'exfiltration', 'privilege escalation'],
    }

    # Chainable vulnerability pairs — if target has both, risk multiplies
    CHAIN_RULES = [
        # Information disclosure → exploitation
        ('Exposed .env', 'SQL Injection', 'Credentials in .env can be used for database access'),
        ('Exposed .git', 'SQL Injection', 'Source code in .git reveals DB structure for SQLi'),
        ('Directory traversal', 'Command Injection', 'Path traversal + RCE = full file access'),
        ('Outdated', 'Default credentials', 'Outdated software + default creds = easy compromise'),
        ('Open port', 'Default credentials', 'Open SSH/SMB + default creds = instant access'),
        ('Authentication Bypass', 'SQL Injection', 'Auth bypass + SQLi = database compromise'),
        ('WordPress', 'Outdated', 'Outdated WordPress is likely vulnerable to known exploits'),
        ('SQL Injection', 'Command Injection', 'SQLi → command injection via xp_cmdshell'),
        ('Exposed .env', 'Authentication Bypass', 'Env secrets may contain JWT/API keys for bypass'),
        ('Self-signed certificate', 'Default credentials', 'Poor security + default creds = likely compromise'),
    ]

    def __init__(self, knowledge_base=None):
        self.kb = knowledge_base

    def correlate(self, scan_data: Dict) -> Dict[str, Any]:
        """
        Main correlation engine. Takes combined scan results
        and produces attack paths, risk assessment, and remediation priority.

        Args:
            scan_data: Dict with keys from all module outputs:
                - recon: subdomains, services, emails
                - webscan: vulnerabilities, technologies
                - exploit: MS17-010 status, credentials
                - findings: list of all discovered findings
        """
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'risk_score': 0.0,
            'severity_counts': {'critical': 0, 'high': 0,
                               'medium': 0, 'low': 0, 'info': 0},
            'attack_chains': [],
            'kill_chain_mapping': {},
            'exploitability_score': 0.0,
            'targets_ranked': [],
            'remediation': {
                'immediate': [],
                'short_term': [],
                'long_term': []
            },
            'network_topology': {},
            'mitre_techniques': [],
        }

        # Extract all findings from all modules
        all_findings = []
        for module_name in ['recon', 'webscan', 'exploit']:
            module_data = scan_data.get(module_name, {})
            if isinstance(module_data, list):
                all_findings.extend(module_data)
            elif isinstance(module_data, dict):
                findings = module_data.get('findings', [])
                if isinstance(findings, list):
                    all_findings.extend(findings)

        # Also check nested structures
        for key, value in scan_data.items():
            if isinstance(value, dict) and 'findings' in value:
                if isinstance(value['findings'], list):
                    for f in value['findings']:
                        if f not in all_findings:
                            all_findings.append(f)

        # If no findings, return early
        if not all_findings:
            result['risk_score'] = 1.0  # Can't assess risk without data
            return result

        # 1. Count severities and calculate risk score
        severity_weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 4.0,
            'low': 2.0,
            'info': 0.5
        }

        for finding in all_findings:
            sev = finding.get('severity', 'info').lower()
            if sev in result['severity_counts']:
                result['severity_counts'][sev] += 1

        weighted_sum = sum(
            severity_weights.get(sev, 0.5) * count
            for sev, count in result['severity_counts'].items()
        )
        total = sum(result['severity_counts'].values())
        result['risk_score'] = round(
            weighted_sum / max(total, 1), 2
        )

        # 2. Detect attack chains
        finding_names = set()
        for f in all_findings:
            v = (f.get('vulnerability', '') or 
                 f.get('finding', '') or '').lower()
            for keyword in f.get('keywords', []):
                finding_names.add(keyword.lower())
            finding_names.add(v)

        for kw1, kw2, chain_desc in self.CHAIN_RULES:
            if kw1.lower() in finding_names and kw2.lower() in finding_names:
                result['attack_chains'].append({
                    'type': f'{kw1} + {kw2}',
                    'description': chain_desc,
                    'risk_level': 'critical' if 'SQL Injection' in kw2 else 'high',
                })

        # 3. MITRE ATT&CK mapping
        seen_techniques = set()
        for finding in all_findings:
            finding_text = (finding.get('vulnerability', '') or 
                          finding.get('finding', '') or '').lower()
            for keyword, (tech_id, tech_name) in self.MITRE_MAP.items():
                if keyword.lower() in finding_text:
                    key = (tech_id, tech_name)
                    if key not in seen_techniques:
                        seen_techniques.add(key)
                        result['mitre_techniques'].append(dict(
                            technique_id=tech_id,
                            technique_name=tech_name,
                            keyword=keyword,
                            finding=finding.get('id', ''),
                        ))

        # 4. Kill chain mapping
        for finding in all_findings:
            finding_text = (finding.get('vulnerability', '') or 
                          finding.get('finding', '') or '').lower()
            for stage, keywords in self.KILL_CHAIN.items():
                for kw in keywords:
                    if kw.lower() in finding_text:
                        if stage not in result['kill_chain_mapping']:
                            result['kill_chain_mapping'][stage] = []
                        entry = {
                            'finding': finding.get('id', finding_text[:50]),
                            'severity': finding.get('severity', 'info'),
                            'matched': kw
                        }
                        if entry not in result['kill_chain_mapping'][stage]:
                            result['kill_chain_mapping'][stage].append(entry)

        # 5. Exploitability score
        exploitability_factors = {
            'authentication_required': {
                'none': 3.0,
                'low': 2.0,
                'high': 0.5,
            },
            'attack_complexity': {
                'low': 2.0,
                'high': 0.5,
            },
            'privileges_required': {
                'none': 3.0,
                'low': 1.5,
                'high': 0.25,
            },
        }
        overall_score = 0.0
        for finding in all_findings:
            sev = finding.get('severity', 'info').lower()
            base = severity_weights.get(sev, 0.5)
            
            # Adjust based on exploitability
            auth = finding.get('authentication_required', 'high')
            complexity = finding.get('attack_complexity', 'high')
            privs = finding.get('privileges_required', 'high')
            
            adj = (exploitability_factors['authentication_required'].get(auth, 1.0) *
                  exploitability_factors['attack_complexity'].get(complexity, 1.0) *
                  exploitability_factors['privileges_required'].get(privs, 1.0))
            
            overall_score += base * adj
        result['exploitability_score'] = round(
            overall_score / max(total, 1), 2
        )

        # 6. Target ranking (by number of critical findings + exploitability)
        targets = {}
        for finding in all_findings:
            target = finding.get('target', 'unknown')
            if target not in targets:
                targets[target] = {
                    'findings': [],
                    'critical': 0,
                    'high': 0,
                    'exploitability': 0.0,
                }
            targets[target]['findings'].append(finding)
            sev = finding.get('severity', 'info').lower()
            if sev == 'critical':
                targets[target]['critical'] += 1
            elif sev == 'high':
                targets[target]['high'] += 1
            if finding.get('exploit_available'):
                targets[target]['exploitability'] += 2.0
            if 'SQL Injection' in finding.get('vulnerability', ''):
                targets[target]['exploitability'] += 1.5
            if 'MS17-010' in finding.get('vulnerability', ''):
                targets[target]['exploitability'] += 2.0

        # Sort by exploitability, then critical count
        ranked = sorted(
            targets.items(),
            key=lambda x: (x[1]['exploitability'], x[1]['critical']),
            reverse=True
        )
        result['targets_ranked'] = [
            dict(
                target=t,
                critical=d['critical'],
                high=d['high'],
                finding_count=len(d['findings']),
                exploitability=round(d['exploitability'], 2)
            )
            for t, d in ranked
        ]

        # 7. Network topology (from recon data)
        recon = scan_data.get('recon', {})
        if isinstance(recon, dict):
            services = recon.get('services', [])
            subdomains = recon.get('subdomains', {}).get('subdomains', [])
            result['network_topology'] = {
                'subdomains': len(subdomains),
                'total_services': len(services),
                'by_protocol': {},
                'by_port': {},
            }
            for svc in services:
                proto = svc.get('protocol', 'unknown')
                port = svc.get('port', 0)
                result['network_topology']['by_protocol'][proto] = \
                    result['network_topology']['by_protocol'].setdefault(proto, 0) + 1
                result['network_topology']['by_port'][port] = \
                    result['network_topology']['by_port'].setdefault(port, 0) + 1

        # 8. Remediation prioritization
        for finding in all_findings:
            sev = finding.get('severity', 'info').lower()
            vuln = finding.get('vulnerability', finding.get('finding', ''))
            target = finding.get('target', 'unknown')
            
            entry = dict(
                vulnerability=vuln,
                target=target,
                severity=sev,
            )

            if sev in ('critical',):
                result['remediation']['immediate'].append(entry)
            elif sev in ('high',):
                result['remediation']['short_term'].append(entry)
            elif sev in ('medium', 'low', 'info'):
                result['remediation']['long_term'].append(entry)

        return result


# ─── CLI ─────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='ZETA ∞ Correlation Engine')
    parser.add_argument('--scans', nargs='+', help='JSON scan result files to correlate')
    args = parser.parse_args()
    
    if not args.scans:
        parser.print_help()
        sys.exit(1)
    
    # Load all scan files
    combined = {}
    for scan_file in args.scans:
        with open(scan_file) as f:
            data = json.load(f)
        # Merge into combined dict
        for key, value in data.items():
            if key in combined:
                if isinstance(combined[key], list):
                    combined[key].extend(value)
                else:
                    combined[key + '_' + os.path.basename(scan_file)] = value
            else:
                combined[key] = value
    
    correlator = Correlator()
    result = correlator.correlate(combined)
    print(json.dumps(result, indent=2))
