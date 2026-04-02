#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════
  ZETA ∞  —  Automated Security Assessment Platform
  Master Orchestrator CLI

Usage:
  python3 zeta.py full example.com           # Full pentest pipeline
  python3 zeta.py recon example.com          # Recon only  
  python3 zeta.py webscan https://example.com  # Web scan
  python3 zeta.py exploit 10.0.0.1           # Exploit chain
  python3 zeta.py analyze suspicious_file    # Deep file analysis
  python3 zeta.py memdump lsass.dmp          # Memory forensics
  python3 zeta.py pcap capture.pcap          # Network analysis
  python3 zeta.py payload --lhost IP --lport 4444  # Generate shells
"""

import sys
import os
import json
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# PLATFORM ROOT & PATHS
# ─────────────────────────────────────────────────────────────
PLATFORM = Path(__file__).resolve().parent
DB_DIR = PLATFORM / 'db'
REPORTS_DIR = PLATFORM / 'reports'
SCANS_DIR = PLATFORM / 'scans'
for d in [DB_DIR, REPORTS_DIR, SCANS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(PLATFORM))
sys.path.insert(0, str(PLATFORM.parent))

from knowledge import KnowledgeBase

# ─────────────────────────────────────────────────────────────
# MODULE IMPORTS
# ─────────────────────────────────────────────────────────────
def import_recon():
    from modules.recon import ReconModule
    return ReconModule()

def import_webscan():
    from modules.webscan import WebscanModule
    return WebscanModule()

def import_exploit():
    from modules.exploit import ExploitModule
    return ExploitModule()

def import_analysis():
    from modules.analysis import AnalysisModule
    return AnalysisModule()

def import_ai_report():
    try:
        from modules.ai_report import AIReportGenerator
        return AIReportGenerator()
    except ImportError:
        return None

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────
def save_results(data: dict, filename: str) -> str:
    """Save scan results to JSON in scans/ directory. Returns path."""
    out = SCANS_DIR / filename
    with open(out, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    return str(out)

def banner(title: str = "ZETA ∞"):
    print(f"\n{'═' * 60}")
    print(f"  ⚡ {title}")
    print(f"{'═' * 60}")

# ─────────────────────────────────────────────────────────────
# COMMANDS
# ─────────────────────────────────────────────────────────────

def cmd_status(args):
    """Show platform status — what's installed, what's missing"""
    banner("ZETA ∞ Platform Status")

    # System info
    import platform
    print(f"\n📱 Hardware:   {platform.machine()}")
    print(f"📦 OS:         {platform.system()} {platform.release()}")
    print(f"🐍 Python:    {sys.version.split()[0]}")
    print(f"📂 Platform:  {PLATFORM}")

    # Check binaries
    go_tools = ['subfinder', 'dnsx', 'httpx', 'katana', 
                'gobuster', 'ffuf', 'nmap']
    print(f"\n🔧 Go/System Tools:")
    for tool in go_tools:
        try:
            p = subprocess.run(['which', tool], capture_output=True, text=True)
            status = "✅" if p.returncode == 0 else "❌"
            print(f"   {status} {tool}")
        except:
            print(f"   ❌ {tool}")

    # Check Python packages
    py_pkgs = ['capstone', 'unicorn', 'lief', 'scapy', 
               'requests', 'bs4', 'paramiko', 'impacket',
               'volatility3', 'cryptography']
    print(f"\n🐍 Python Libraries:")
    for pkg in py_pkgs:
        try:
            __import__(pkg)
            print(f"   ✅ {pkg}")
        except ImportError:
            print(f"   ❌ {pkg}")

    # Check AI model — check multiple possible paths
    model_paths = [
        PLATFORM.parent / 'zeta_local-ai' / 'models',
        PLATFORM.parent / 'zeta-local-ai' / 'models',
    ]
    model_found = False
    for mp in model_paths:
        if mp.exists():
            models = list(mp.glob('*.gguf'))
            if models:
                print(f"\n🤖 Local AI:  {', '.join(m.name for m in models)}")
                for m in models:
                    size_mb = m.stat().st_size / 1024 / 1024
                    print(f"   📊 Model size: {size_mb:.0f} MB")
                model_found = True
                break
    if not model_found:
        print(f"\n🤖 Local AI:  No models found")

    # Knowledge base stats
    try:
        kb = KnowledgeBase()
        stats = kb.stats()
        print(f"\n🧠 Knowledge Base:")
        for k, v in stats.items():
            print(f"   {k}: {v}")
    except:
        print(f"\n🧠 Knowledge Base: Not initialized")

    print()

def cmd_recon(args):
    """Run reconnaissance module"""
    banner(f"ZETA ∞ Reconnaissance — {args.target}")

    recon = import_recon()
    kb = KnowledgeBase()

    full_data = recon.run_full_recon(args.target)

    # Populate knowledge base
    kb.add_target(args.target, target_type='network')

    # Subdomains
    for sub in full_data.get('subdomains', {}).get('subdomains', []):
        kb.add_subdomains(args.target, [{'subdomain': sub}])

    # Services
    for svc in full_data.get('services', {}):
        port = 0
        proto = 'tcp'
        service = ''
        version = ''
        banner_text = ''
        if isinstance(svc, dict):
            port = svc.get('port', 0)
            proto = svc.get('protocol', 'tcp')
            service = svc.get('service', '')
            version = svc.get('version', '')
        elif isinstance(svc, str):
            parts = svc.split('/')
            if len(parts) >= 2:
                proto_service = parts[0]
                if '/' in proto_service:
                    proto, service = proto_service.split('/', 1)
                else:
                    service = proto_service
                banner_text = svc
        kb.add_service(args.target, args.target, port, proto, 
                      service, version, banner_text)

    emails = full_data.get('emails', {}).get('emails', [])
    if emails:
        kb.add_emails(args.target, emails, source='recon')

    # Save
    path = save_results(full_data, f"recon_{args.target.replace('.', '_')}.json")
    print(f"\n💾 Results saved: {path}")

def cmd_webscan(args):
    """Run web vulnerability scanning"""
    banner(f"ZETA ∞ Web Scan — {args.target}")

    targets = [args.target]
    if not args.target.startswith(('http://', 'https://')):
        targets = [f'https://{args.target}']

    w = import_webscan()
    kb = KnowledgeBase()

    full_data = {}
    for url in targets:
        scan_data = w.scan(url)
        full_data[url] = scan_data

        kb.add_target(args.target, target_type='web')
        for finding in scan_data.get('findings', []):
            kb.add_vulnerability(
                args.target,
                finding.get('vulnerability', ''),
                finding.get('severity', 'info'),
                'webscan',
                finding.get('module', ''),
                finding.get('finding', ''))

    path = save_results(full_data, f"webscan_{args.target.replace('.', '_')}.json")
    print(f"\n💾 Results saved: {path}")

def cmd_exploit(args):
    """Run exploit module"""
    banner(f"ZETA ∞ Exploit — {args.target}")
    exp = import_exploit()
    kb = KnowledgeBase()
    kb.add_target(args.target, target_type='network')
    
    result = exp.run_exploit_chain(args.target)
    
    # Save findings to KB
    if 'exploit_findings' in result:
        for f in result['exploit_findings']:
            kb.add_vulnerability(
                args.target,
                f.get('vulnerability', ''),
                f.get('severity', 'info'),
                'exploit',
                f.get('tool', ''),
                f.get('finding', ''))

    path = save_results(result, f"exploit_{args.target.replace('.', '_')}.json")
    print(f"\n💾 Results saved: {path}")

def cmd_analyze(args):
    """Analyze a file"""
    banner(f"ZETA ∞ Analysis")
    ana = import_analysis()
    result = ana.analyze_file(args.file)
    print(json.dumps(result, indent=2, default=str))

def cmd_memdump(args):
    """Analyze a memory dump"""
    banner(f"ZETA ∞ Memory Analysis")
    ana = import_analysis()
    result = ana.analyze_memory_dump(args.file)
    print(json.dumps(result, indent=2, default=str))

def cmd_pcap(args):
    """Analyze a packet capture"""
    banner(f"ZETA ∞ PCAP Analysis")
    ana = import_analysis()
    result = ana.analyze_pcap(args.file)
    print(json.dumps(result, indent=2, default=str))

def cmd_payload(args):
    """Generate reverse shell payloads"""
    banner("ZETA ∞ Payload Generator")
    exp = import_exploit()
    result = exp.payload_generator(args.lhost, args.lport)
    print(result['payload'])

def cmd_db(args):
    """Query the knowledge base"""
    kb = KnowledgeBase()
    
    print("\n📚 Knowledge Base Contents:")
    print("=" * 60)
    
    stats = kb.stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")
    
    if args.list_targets:
        targets = kb.get_targets()
        print(f"\n🎯 Targets:")
        for t in targets:
            print(f"  {t.get('target', 'unknown')} ({t.get('type', 'unknown')})")
    
    if args.list_vulns:
        vulns = kb.get_vulnerabilities()
        print(f"\n🔴 Vulnerabilities:")
        for v in vulns:
            print(f"  [{v.get('severity', 'info').upper()}] {v.get('target', '')}: {v.get('finding', '')}")

def cmd_full(args):
    """
    Run full pentest pipeline: Recon → WebScan → Exploit → Analysis → AI Report
    
    This is the "B + C" — everything chained together, fully autonomous.
    """
    target = args.target
    print(f"\n{'═' * 60}")
    print(f"  ⚔️  ZETA ∞ — FULL AUTONOMOUS SECURITY ASSESSMENT")
    print(f"  🎯  Target: {target}")
    print(f"  📅  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═' * 60}\n")

    start_time = datetime.utcnow()
    kb = KnowledgeBase()

    # Register target
    kb.add_target(target)

    results = {
        'target': target,
        'timestamp': start_time.isoformat(),
    }

    # Phase 1: Reconnaissance
    print(f"\n{'─' * 60}")
    print(f"  PHASE 1: RECONNAISSANCE")
    print(f"{'─' * 60}")
    recon_results = cmd_recon(args)
    results['recon'] = recon_results

    # Phase 2: Web Scanning (if domain has HTTP)
    import requests
    has_http = False
    for proto in ['https', 'http']:
        try:
            r = requests.get(f"{proto}://{target.split(':')[0]}", timeout=5, verify=False)
            if r.status_code or str(500) in str(r.status_code).split('x')[:1]:
                has_http = True
                break
        except:
            pass

    if has_http:
        print(f"\n{'─' * 60}")
        print(f"  PHASE 2: WEB VULNERABILITY SCANNING")
        print(f"{'─' * 60}")
        webscan_results = cmd_webscan(type('DummyArgs', (), {'target': target, 
                                                              'quick': False})())
        results['webscan'] = webscan_results
    else:
        print(f"\n{'─' * 60}")
        print(f"  PHASE 2: SKIPPED — No HTTP service found")
        print(f"{'─' * 60}")

    # Phase 3: Exploitation
    print(f"\n{'─' * 60}")
    print(f"  PHASE 3: EXPLOIT CHAIN")
    print(f"{'─' * 60}")
    exploit_results = cmd_exploit(type('DummyArgs', (), {'target': target, 
                                                          'mode': 'auto'})())
    results['exploit'] = exploit_results

    # Phase 4: Analysis & Correlation
    print(f"\n{'─' * 60}")
    print(f"  PHASE 4: ANALYSIS & REPORT")
    print(f"{'─' * 60}")

    # Pull all findings from KB for correlation
    vulns = kb.get_vulnerabilities()
    
    from modules.correlation import Correlator
    corr = Correlator()
    correlation = corr.correlate({
        'recon': recon_results,
        'webscan': results.get('webscan', {}),
        'exploit': exploit_results,
        'vulnerabilities': vulns,
    })
    results['correlation'] = correlation

    # Phase 5: AI Report (if available)
    ai_gen = import_ai_report()
    if ai_gen:
        print(f"\n{'─' * 60}")
        print(f"  PHASE 5: AI-GENERATED REPORT")
        print(f"{'─' * 60}")
        report = ai_gen.generate_report(results)
        report_path = save_results(report, f"report_{target.replace('.', '_')}.json")
        print(f"  💾 Report: {report_path}")
        
        # Save markdown report
        md_path = REPORTS_DIR / f"{target.replace('.', '_')}_full_report.md"
        try:
            with open(md_path, 'w') as f:
                f.write(report)
            print(f"  💾 Markdown: {md_path}")
        except:
            pass

    # Save full scan data
    elapsed = (datetime.utcnow() - start_time).total_seconds()
    results['elapsed_seconds'] = round(elapsed, 1)
    full_path = save_results(results, f"full_scan_{target.replace('.', '_')}.json")

    print(f"\n{'═' * 60}")
    print(f"  ✅ COMPLETE — {round(elapsed)}s")
    print(f"  📊 Findings: {len(vulns)} vulnerabilities")
    print(f"  📋 Reports: {full_path}")
    print(f"{'═' * 60}\n")

    return results


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='zeta',
        description='ZETA ∞ — Autonomous Security Assessment Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    subparsers = parser.add_subparsers(dest='command')

    # Full assessment (B + C)
    full_p = subparsers.add_parser('full',
                                   help='Full autonomous pentest (recon + web + exploit + report)')
    full_p.add_argument('target', help='Target domain/IP/URL')
    full_p.set_defaults(func=cmd_full)

    # Individual modules
    recon_p = subparsers.add_parser('recon', help='Network reconnaissance')
    recon_p.add_argument('target', help='Target domain/IP')
    recon_p.set_defaults(func=cmd_recon)

    web_p = subparsers.add_parser('webscan', help='Web vulnerability scanning')
    web_p.add_argument('target', help='Target URL')
    web_p.add_argument('--quick', action='store_true', help='Quick scan only (tech + dirs)')
    web_p.set_defaults(func=cmd_webscan)

    exploit_p = subparsers.add_parser('exploit', help='Exploit chain execution')
    exploit_p.add_argument('target', help='Target IP')
    exploit_p.set_defaults(func=cmd_exploit)

    analyze_p = subparsers.add_parser('analyze', help='Analyze a file')
    analyze_p.add_argument('file', help='File path')
    analyze_p.set_defaults(func=cmd_analyze)

    memdump_p = subparsers.add_parser('memdump', help='Analyze memory dump')
    memdump_p.add_argument('file', help='Dump file path')
    memdump_p.set_defaults(func=cmd_memdump)

    pcap_p = subparsers.add_parser('pcap', help='Analyze packet capture')
    pcap_p.add_argument('file', help='PCAP file path')
    pcap_p.set_defaults(func=cmd_pcap)

    payload_p = subparsers.add_parser('payload', help='Generate exploit payload')
    payload_p.add_argument('--lhost', required=True, help='Your IP')
    payload_p.add_argument('--lport', type=int, default=4444, help='Port')
    payload_p.set_defaults(func=cmd_payload)

    db_p = subparsers.add_parser('db', help='Query knowledge base')
    db_p.add_argument('--list', action='store_true', help='List contents')
    db_p.add_argument('--list-targets', action='store_true')
    db_p.add_argument('--list-vulns', action='store_true')
    db_p.set_defaults(func=cmd_db)

    status_p = subparsers.add_parser('status', help='Platform status')
    status_p.set_defaults(func=cmd_status)

    # Parse
    args = parser.parse_args()
    if not args.command:
        banner()
        parser.print_help()
        sys.exit(1)

    banner()
    args.func(args)
    print()


if __name__ == '__main__':
    main()
