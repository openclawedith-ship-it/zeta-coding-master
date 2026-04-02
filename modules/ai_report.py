#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════
  AI REPORT — Natural Language Report Generation
═══════════════════════════════════════════════════════════
Uses the local Qwen2.5-0.5B model to generate human-readable
reports from scan results. If the model isn't available,
falls back to a template-based report generator.

This is the brain of ZETA ∞ — it turns raw scan data into
actionable intelligence.

Usage:
    Called automatically by zeta.py when --report is used.
    Can also be run standalone:
        python3 modules/ai_report.py --input report.json --output full_report.md
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


class AIReportGenerator:
    """Generate natural-language security reports using local AI or templates"""

    def __init__(self, model_path: str = None, server_url: str = None):
        self.model_path = model_path
        self.server_url = server_url
        self.llama_cli = self._find_llama_cli()
        self.llama_server = server_url or "http://127.0.0.1:8080"

    def _find_llama_cli(self) -> Optional[str]:
        """Find llama.cpp binary"""
        candidates = [
            str(Path(__file__).parent.parent /
                "zeta_local-ai" / "llama-cpp" / "llama-cli"),
            str(Path("/usr/local/bin/llama-cli")),
        ]
        for path in candidates:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        return None

    def generate_report(self, scan_results: Dict,
                        output_path: str = None,
                        format: str = "markdown") -> str:
        """
        Generate a professional security report.
        
        Tries: 1. llama.cpp local AI model
               2. Template-based report (guaranteed)
        """
        # Try AI-generated report first
        ai_report = None
        if self.llama_cli:
            try:
                ai_report = self._generate_with_ai(scan_results)
            except Exception as e:
                print(f"  ⚠  AI generation failed: {e}")
                print("  → Falling back to template report")

        # Always generate template fallback
        template_report = self._generate_template_report(scan_results)

        # Combine if AI was successful
        if ai_report:
            final_report = ai_report + "\n\n" + template_report
        else:
            final_report = template_report

        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(final_report)
            print(f"  📄 Report saved: {output_path}")

        return final_report

    def _generate_with_ai(self, scan_results: Dict) -> str:
        """Generate a report using the local Qwen2.5 model"""
        # Prepare prompt
        summary = self._extract_summary_text(scan_results)
        
        prompt = f"""You are a senior penetration tester writing a security assessment report.

Based on these scan results, write a professional security report in markdown format:

{summary}

Format the report with:
1. Executive Summary (1 paragraph)
2. Risk Assessment (High/Medium/Low findings)
3. Detailed Findings (each vulnerability with impact and remediation)
4. Attack Path Analysis (how an attacker could chain these)
5. Recommendations (prioritized list)

Be professional, clear, and actionable. Focus on business impact."""

        if not self.llama_cli:
            return None

        # Run llama-cli in single-shot mode
        cmd = [
            self.llama_cli,
            '-m', self.model_path or str(
                Path(__file__).parent.parent /
                "zeta_local-ai" / "models" /
                "Qwen2.5-0.5B-uncensored-Q4_K_M.gguf"),
            '-p', prompt,
            '-n', '2048',  # Max tokens
            '--temp', '0.7',
            '-ngl', '0',  # No GPU layers (CPU only)
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        
        return None

    def _extract_summary_text(self, results: Dict) -> str:
        """Extract a clean text summary from scan results"""
        lines = []
        
        # Target info
        lines.append(f"TARGET: {results.get('target', 'Unknown')}")
        
        # Recon findings
        recon = results.get('recon', {})
        subdomains = recon.get('subdomains', {}).get('subdomains', [])
        if subdomains:
            lines.append(f"SUBDOMAINS DISCOVERED ({len(subdomains)}):")
            for sub in subdomains[:20]:
                lines.append(f"  - {sub}")
        
        services = recon.get('services', [])
        if services:
            lines.append("OPEN SERVICES:")
            for svc in services:
                port = svc.get('port', '')
                service = svc.get('service', '')
                lines.append(f"  - Port {port}: {service}")
        
        # Webscan findings
        webscan = results.get('webscan', {})
        tech = webscan.get('technologies', [])
        if tech:
            lines.append("TECHNOLOGIES DETECTED:")
            for t in tech:
                lines.append(f"  - {t}")
        
        # Vulnerabilities
        vulns = []
        for module in ['webscan', 'recon', 'exploit']:
            findings = results.get(module, {}).get('findings', [])
            vulns.extend(findings)
        
        if vulns:
            lines.append(f"VULNERABILITIES ({len(vulns)}):")
            for v in sorted(vulns, key=lambda x: 
                          {'critical': 0, 'high': 1, 'medium': 2,
                           'low': 3, 'info': 4}.get(
                              x.get('severity', 'info').lower(), 4)):
                lines.append(f"  - [{v.get('severity', 'INFO').upper()}] "
                           f"{v.get('finding', 'Unknown')}")
        
        # Exploit results
        exploit = results.get('exploit', {})
        ms17 = exploit.get('ms17_010', {})
        if ms17.get('vulnerable'):
            lines.append("CRITICAL: MS17-010 EternalBlue vulnerable!")
        
        return "\n".join(lines)

    def _generate_template_report(self, results: Dict) -> str:
        """Generate a comprehensive template-based security report"""
        parts = []
        
        # Header
        parts.append("""# ZETA ∞ Security Assessment Report
""")
        
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        parts.append(f"**Generated:** {now}")
        parts.append(f"**Target:** {results.get('target', 'Unknown')}")
        parts.append(f"**Framework:** ZETA ∞ Automated Security Platform v1.0")
        parts.append("")
        
        # Executive summary
        parts.append("## Executive Summary")
        parts.append(self._executive_summary(results))
        parts.append("")
        
        # Target overview
        parts.append("## Target Overview")
        parts.append(self._target_overview(results))
        parts.append("")
        
        # Findings by severity
        parts.append("## Findings by Severity")
        parts.append(self._findings_table(results))
        parts.append("")
        
        # Detailed findings
        parts.append("## Detailed Findings")
        parts.append(self._detailed_findings(results))
        parts.append("")
        
        # Attack path analysis
        parts.append("## Attack Path Analysis")
        parts.append(self._attack_paths(results))
        parts.append("")
        
        # Network map
        parts.append("## Network Surface")
        parts.append(self._network_map(results))
        parts.append("")
        
        # Risk scoring
        parts.append("## Risk Scoring")
        parts.append(self._risk_scoring(results))
        parts.append("")
        
        # Recommendations
        parts.append("## Recommendations")
        parts.append(self._recommendations(results))
        parts.append("")
        
        # Methodology
        parts.append("## Methodology")
        parts.append("""This assessment was performed using the ZETA ∞ Automated Security
Platform, which chains together multiple tools and techniques:

1. **Reconnaissance** — Subdomain enumeration (subfinder), service discovery,
   OSINT gathering (emails), and web crawling
2. **Web Security Testing** — Technology detection, directory discovery
   (gobuster/ffuf), SQL injection testing (sqlmap), and SSL/TLS auditing
3. **Vulnerability Analysis** — Known vulnerability checks, WordPress
   security scanning (wpscan), and configuration review
4. **Exploitation Testing** — SMB enumeration, MS17-010 checks,
   credential extraction, and privilege escalation analysis

All analysis was performed locally on-device with zero cloud dependencies.""")
        parts.append("")
        
        # Appendices
        parts.append("## Appendices")
        parts.append("### A. Tools Used")
        parts.append(self._tools_used(results))
        parts.append("")
        
        return "\n".join(parts)

    def _executive_summary(self, results: Dict) -> str:
        """Generate executive summary text"""
        target = results.get('target', 'Unknown')
        
        # Count findings by severity
        all_findings = []
        for module_key in ['recon', 'webscan', 'exploit']:
            module = results.get(module_key, {})
            if isinstance(module, dict):
                findings = module.get('findings', [])
                all_findings.extend(findings)
        
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in all_findings:
            sev = f.get('severity', 'info').lower()
            if sev in counts:
                counts[sev] += 1
        
        total = sum(counts.values())
        
        # Subdomains
        recon = results.get('recon', {})
        subdomains_list = recon.get('subdomains', {}).get('subdomains', [])
        
        summary = f"This security assessment of **{target}** was conducted using"\
                  f" the ZETA ∞ platform. The scan identified **{total} findings**"\
                  f" including:"
        
        if counts['critical']:
            summary += f"\n- **{counts['critical']} Critical** vulnerabilities requiring immediate attention"
        if counts['high']:
            summary += f"\n- **{counts['high']} High** severity issues"
        if counts['medium']:
            summary += f"\n- **{counts['medium']} Medium** severity issues"
        if counts['low']:
            summary += f"\n- **{counts['low']} Low** severity informational findings"
        if counts['info']:
            summary += f"\n- **{counts['info']} Informational** findings"
        
        if subdomains_list:
            summary += f"\n\nThe target has **{len(subdomains_list)} discovered subdomains** "\
                      f"and active services that expand the attack surface."
        
        # Special callouts
        exploit = results.get('exploit', {})
        if exploit.get('ms17_010', {}).get('vulnerable'):
            summary += "\n\n⚠️  **CRITICAL:** The target is vulnerable to MS17-010 "\
                      "(EternalBlue), a remote code execution vulnerability patched by Microsoft in 2017."
        
        return summary

    def _target_overview(self, results: Dict) -> str:
        """Generate target overview section"""
        parts = []
        target = results.get('target', 'Unknown')
        
        parts.append(f"**Target:** {target}")
        
        # Recon data
        recon = results.get('recon', {})
        subdomains = recon.get('subdomains', {}).get('subdomains', [])
        parts.append(f"**Discovered Subdomains:** {len(subdomains)}")
        
        emails = recon.get('emails', {})
        if isinstance(emails, list):
            parts.append(f"**Emails Found:** {len(emails)}")
        
        # Services
        services = recon.get('services', [])
        if isinstance(services, list):
            parts.append(f"**Open Services:** {len(services)}")
            if services:
                parts.append("")
                parts.append("| Port | Protocol | Service | Version |")
                parts.append("|------|----------|---------|---------|")
                for svc in services[:20]:
                    parts.append(f"| {svc.get('port', '')} | "\
                                f"{svc.get('protocol', 'tcp')} | "\
                                f"{svc.get('service', '')} | "\
                                f"{svc.get('version', '')} |")
        
        # Technologies
        webscan = results.get('webscan', {})
        tech = webscan.get('technologies', [])
        if tech:
            parts.append("")
            parts.append("### Detected Technologies")
            for t in tech[:10]:
                parts.append(f"- {t.get('name', 'Unknown')}")
        
        return "\n".join(parts)

    def _findings_table(self, results: Dict) -> str:
        """Generate findings by severity table"""
        all_findings = []
        for module_key in ['recon', 'webscan', 'exploit']:
            module = results.get(module_key, {})
            if isinstance(module, dict):
                findings = module.get('findings', [])
                all_findings.extend(findings)
        
        parts = []
        parts.append("| Severity | Count | Description |")
        parts.append("|----------|-------|-------------|")
        
        severity_desc = {
            'critical': 'Immediate exploitation risk, data breach likely',
            'high': 'Significant risk, could lead to unauthorized access',
            'medium': 'Moderate risk, should be addressed in near term',
            'low': 'Low risk, best practice improvement',
            'info': 'Informational, no direct security impact',
        }
        
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in all_findings:
            sev = f.get('severity', 'info').lower()
            if sev in counts:
                counts[sev] += 1
        
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡',
                    'low': '🔵', 'info': 'ℹ️ '}.get(sev, '⚪')
            parts.append(f"| {emoji} {sev.upper()} | "\
                        f"{counts[sev]} | {severity_desc.get(sev, '')} |")
        
        return "\n".join(parts)

    def _detailed_findings(self, results: Dict) -> str:
        """Generate detailed findings section"""
        all_findings = []
        for module_key in ['recon', 'webscan', 'exploit']:
            module = results.get(module_key, {})
            if isinstance(module, dict):
                findings = module.get('findings', [])
                all_findings.extend(findings)
        
        # Sort by severity
        severity_order = {
            'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4
        }
        all_findings.sort(key=lambda x: 
                        severity_order.get(x.get('severity', 'info').lower(), 4))
        
        parts = []
        for i, finding in enumerate(all_findings, 1):
            sev = finding.get('severity', 'info').upper()
            tool = finding.get('tool', 'Unknown')
            vulnerability = finding.get('vulnerability', finding.get('finding', 'Unknown'))
            detail = finding.get('finding', '')
            target = finding.get('target', '')
            
            parts.append(f"\n### Finding #{i}: {vulnerability}")
            parts.append(f"- **Severity:** {sev}")
            parts.append(f"- **Tool:** {tool}")
            parts.append(f"- **Target:** {target}")
            parts.append(f"- **Details:** {detail}")
            
            # Add remediation suggestions for common finding types
            v_lower = vulnerability.lower()
            if 'sql injection' in v_lower:
                parts.append(f"\n**Remediation:** Use parameterized queries/prepared statements. "
                           f"Implement input validation and WAF rules.")
            elif 'missing header' in v_lower:
                parts.append(f"\n**Remediation:** Add the missing security headers to the web server "
                           f"configuration (nginx/apache) or application framework.")
            elif 'technology' in v_lower or 'detected' in v_lower:
                parts.append(f"- **No remediation needed** (informational)")
            elif 'smb' in v_lower or 'ms17-010' in v_lower:
                parts.append(f"\n**Remediation:** Apply MS17-010 patch (KB4013389). Disable SMBv1 "
                           f"if not needed. Restrict SMB access via firewall rules.")
            elif 'wordpress' in v_lower:
                parts.append(f"\n**Remediation:** Update WordPress core, themes, and plugins to latest "
                           f"versions. Remove unused plugins.")
            else:
                parts.append(f"\n**Remediation:** Review the finding and apply appropriate "
                           f"security controls or patches.")
        
        return "\n".join(parts) if parts else "*No specific findings to report.*"

    def _attack_paths(self, results: Dict) -> str:
        """Generate attack path analysis"""
        all_findings = []
        for module_key in ['recon', 'webscan', 'exploit']:
            module = results.get(module_key, {})
            if isinstance(module, dict):
                findings = module.get('findings', [])
                all_findings.extend(findings)
        
        parts = []
        parts.append("Based on the findings, here are the most likely attack paths:")
        
        # Check for specific combinations
        has_sqli = any('sql' in f.get('finding', '').lower() or 
                      'sql injection' in f.get('vulnerability', '').lower()
                      for f in all_findings)
        has_smb = any('smb' in f.get('finding', '').lower()
                     for f in all_findings)
        has_weak_auth = any('auth' in f.get('finding', '').lower() or
                           'login' in f.get('finding', '').lower()
                           for f in all_findings)
        has_outdated = any('outdated' in f.get('finding', '').lower() or
                          'version' in f.get('finding', '').lower()
                          for f in all_findings)
        has_exposed_files = any('exposed' in f.get('finding', '').lower() or
                               'found' in f.get('finding', '').lower()
                               for f in all_findings)
        exploit = results.get('exploit', {})
        ms17 = exploit.get('ms17_010', {})
        
        paths = []
        if ms17.get('vulnerable'):
            paths.append("1. **Remote Code Execution (MS17-010)**: Exploit the unpatched "
                        "SMB vulnerability to gain initial access. Use Metasploit's "
                        "exploit/windows/smb/ms17_010_eternalblue module.")
        
        if has_sqli:
            paths.append("2. **SQL Injection → Data Breach**: Extract credentials and "
                        "sensitive data through SQL injection. May lead to full database "
                        "compromise and administrative access.")
        
        if has_exposed_files and has_weak_auth:
            paths.append("3. **Exposed Files + Weak Authentication**: Access exposed "
                        "configuration files (.env, config.php) to obtain credentials, "
                        "then authenticate to admin interfaces.")
        
        if has_outdated and has_exposed_files:
            paths.append("4. **Outdated Software + Exposed Services**: Exploit known "
                        "vulnerabilities in outdated software versions, using exposed "
                        "services as entry points.")
        
        if has_weak_auth:
            paths.append("5. **Credential Stuffing/Brute Force**: Attempt credential "
                        "stuffing against identified login endpoints using harvested "
                        "email addresses.")
        
        if not paths:
            paths.append("No direct attack paths identified from current findings. "
                        "Continue monitoring and scanning for new vulnerabilities.")
        
        parts.extend(paths)
        return "\n".join(parts)

    def _network_map(self, results: Dict) -> str:
        """Generate network surface visualization"""
        recon = results.get('recon', {})
        subdomains = recon.get('subdomains', {}).get('subdomains', [])
        services = recon.get('services', [])
        
        parts = []
        target = results.get('target', 'Unknown')
        
        parts.append(f"```")
        parts.append(f"┌──────────────────────────────────────┐")
        parts.append(f"│  TARGET: {target:<27} │")
        parts.append(f"└──────────────┬───────────────────────┘")
        parts.append(f"               │")
        parts.append(f"               ▼")
        parts.append(f"┌──────────────────────────────────────┐")
        parts.append(f"│  Attack Surface                      │")
        parts.append(f"│                                      │")
        
        if subdomains:
            parts.append(f"│  Subdomains ({min(len(subdomains), 5)} shown):{' ' * (18 - len(str(min(len(subdomains), 5))))}   │")
            for sub in subdomains[:5]:
                display = sub[:30]
                parts.append(f"│    • {display:<30} │")
            if len(subdomains) > 5:
                parts.append(f"│    • ... and {len(subdomains) - 5} more")
        
        if services:
            parts.append(f"│                                      │")
            parts.append(f"│  Open Services:                      │")
            for svc in services[:10]:
                port = str(svc.get('port', ''))
                proto = svc.get('protocol', 'tcp')
                service = svc.get('service', '')
                parts.append(f"│    {port:>5}/{proto:<4} {service:<20} │")
            if len(services) > 10:
                parts.append(f"│    ... and {len(services) - 10} more")
        
        parts.append(f"│                                      │")
        parts.append(f"└──────────────────────────────────────┘")
        parts.append(f"```")
        
        return "\n".join(parts)

    def _risk_scoring(self, results: Dict) -> str:
        """Generate risk scoring section"""
        all_findings = []
        for module_key in ['recon', 'webscan', 'exploit']:
            module = results.get(module_key, {})
            if isinstance(module, dict):
                findings = module.get('findings', [])
                all_findings.extend(findings)
        
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in all_findings:
            sev = f.get('severity', 'info').lower()
            if sev in counts:
                counts[sev] += 1
        
        # Calculate CVSS-like score (0-10)
        weights = {'critical': 10.0, 'high': 7.5, 'medium': 4.0, 'low': 2.0, 'info': 0.5}
        total_weight = sum(counts[sev] * weights[sev] for sev in counts)
        total = sum(counts.values())
        risk_score = total_weight / max(total, 1)
        
        parts = []
        parts.append("### Overall Risk Score")
        parts.append("")
        
        if risk_score >= 8.0:
            level = "🔴 CRITICAL"
            desc = "Immediate action required. Active exploitation is likely or possible."
        elif risk_score >= 6.0:
            level = "🟠 HIGH"
            desc = "Significant risk. Attackers could gain unauthorized access."
        elif risk_score >= 4.0:
            level = "🟡 MEDIUM"
            desc = "Moderate risk. Vulnerabilities exist that should be addressed."
        elif risk_score >= 2.0:
            level = "🔵 LOW"
            desc = "Low risk. Best practice improvements needed."
        else:
            level = "✅ MINIMAL"
            desc = "Minimal risk. Target appears well-secured."
        
        parts.append(f"**Risk Score:** {risk_score:.1f} / 10.0 ({level})")
        parts.append(f"**Assessment:** {desc}")
        parts.append("")
        parts.append("### Scoring Breakdown")
        parts.append("| Severity | Count | Weight | Contribution |")
        parts.append("|----------|-------|--------|-------------|")
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            weight = weights[sev]
            contrib = counts[sev] * weight
            parts.append(f"| {sev.upper()} | {counts[sev]} | {weight} | {contrib:.1f} |")
        parts.append(f"| **Total** | **{total}** | | **{total_weight:.1f}** |")
        
        return "\n".join(parts)

    def _recommendations(self, results: Dict) -> str:
        """Generate prioritized recommendations"""
        all_findings = []
        for module_key in ['recon', 'webscan', 'exploit']:
            module = results.get(module_key, {})
            if isinstance(module, dict):
                findings = module.get('findings', [])
                all_findings.extend(findings)
        
        exploit = results.get('exploit', {})
        
        parts = []
        
        # Dynamic recommendations based on findings
        recs = []
        
        if exploit.get('ms17_010', {}).get('vulnerable'):
            recs.append(("CRITICAL", "Patch MS17-010 (EternalBlue)",
                        "Apply KB4013389 immediately. This vulnerability has "
                        "been actively exploited in the wild since 2017."))
        
        # Check for SQL injection
        has_sqli = any('sql' in f.get('finding', '').lower() or
                      'SQL Injection' in f.get('vulnerability', '')
                      for f in all_findings)
        if has_sqli:
            recs.append(("CRITICAL", "Remediate SQL Injection",
                        "Implement parameterized queries, input validation, "
                        "and deploy a Web Application Firewall (WAF)."))
        
        # Check for outdated software
        has_outdated = any('outdated' in f.get('finding', '').lower()
                          for f in all_findings)
        if has_outdated:
            recs.append(("HIGH", "Update All Software",
                        "Update web server, frameworks, CMS, and all plugins "
                        "to their latest versions."))
        
        # Check for exposed files
        has_exposed = any('exposed' in f.get('finding', '').lower() or
                         'found' in f.get('finding', '').lower()
                         for f in all_findings)
        if has_exposed:
            recs.append(("MEDIUM", "Restrict Access to Sensitive Files",
                        "Block access to .git, .env, config.php, and other "
                        "sensitive files via web server configuration."))
        
        # Missing headers
        has_missing_headers = any('missing header' in f.get('finding', '').lower()
                                 for f in all_findings)
        if has_missing_headers:
            recs.append(("LOW", "Add Security Headers",
                        "Add security headers: Strict-Transport-Security, "
                        "Content-Security-Policy, X-Frame-Options, etc."))
        
        # Always include these base recommendations
        recs.append(("INFO", "Regular Security Assessments",
                    "Schedule regular security assessments using ZETA ∞ "
                    "to continuously monitor the attack surface."))
        recs.append(("INFO", "Monitoring & Logging",
                    "Implement comprehensive logging and monitoring to detect "
                    "and respond to security incidents."))
        
        # Print recommendations
        parts.append("### Prioritized Recommendations")
        parts.append("")
        
        for priority, title, desc in recs:
            priority_emoji = {
                'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡',
                'LOW': '🔵', 'INFO': 'ℹ️ '
            }.get(priority, '⚪')
            parts.append(f"**{priority_emoji} {priority}: {title}**")
            parts.append(f"- {desc}")
            parts.append("")
        
        return "\n".join(parts)

    def _tools_used(self, results: Dict) -> str:
        """List tools used in the assessment"""
        tools_used = set()
        for module_key in ['recon', 'webscan', 'exploit']:
            module = results.get(module_key, {})
            if isinstance(module, dict):
                findings = module.get('findings', [])
                for f in findings:
                    tool = f.get('tool', '')
                    if tool:
                        tools_used.add(tool)
        
        tool_descriptions = {
            'subfinder': 'Subdomain enumeration tool',
            'dnsx': 'DNS query tool',
            'httpx': 'HTTP probing tool',
            'katana': 'Web crawler',
            'gobuster': 'Directory/file brute-forcing',
            'ffuf': 'Web fuzzer and directory scanner',
            'sqlmap': 'SQL injection testing',
            'wpscan': 'WordPress vulnerability scanner',
            'sslyze': 'SSL/TLS security analysis',
            'nmap': 'Network scanner (if available)',
            'theHarvester': 'Email and subdomain OSINT tool',
            'impacket': 'SMB/Active Directory exploitation suite',
            'pypykatz': 'Credential extraction from LSASS dumps',
        }
        
        parts = []
        for tool in sorted(tools_used):
            desc = tool_descriptions.get(tool, 'Custom tool')
            parts.append(f"- **{tool}**: {desc}")
        
        if not tools_used:
            parts.append("- No specific tools recorded in scan results")
        
        return "\n".join(parts)


def main():
    import argparse
    p = argparse.ArgumentParser(description="ZETA ∞ AI Report Generator")
    p.add_argument('--input', '-i', required=True,
                   help='Input scan results JSON file')
    p.add_argument('--output', '-o',
                   help='Output report file (default: stdout)')
    p.add_argument('--format', '-f', default='markdown',
                   choices=['markdown', 'html', 'json'],
                   help='Output format')
    args = p.parse_args()
    
    with open(args.input) as f:
        results = json.load(f)
    
    generator = AIReportGenerator()
    report = generator.generate_report(results, args.output)
    
    if not args.output:
        print(report)


if __name__ == '__main__':
    main()
