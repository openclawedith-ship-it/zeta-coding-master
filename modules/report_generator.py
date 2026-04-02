"""
ZETA ∞ — AI Report Generator
Generates professional markdown reports from scan results.
Uses local AI (Qwen2.5) to write the narrative sections.
"""

import os, sys, json, subprocess
from pathlib import Path
from datetime import datetime

class AIReportGenerator:
    """Generate reports using local AI + structured templates"""

    MODELS = [
        'Qwen2.5-0.5B-uncensored-Q4_K_M.gguf',
        'Qwen2.5-0.5B-Instruct-U4_K_M.gguf',
    ]

    def __init__(self, model_path: str = None):
        self.model_path = model_path or self._find_model()
        self.llama_cli = None

    def _find_model(self) -> str:
        """Find Qwen model in workspace"""
        models_dir = Path(__file__).parent.parent / 'zeta_local-ai' / 'models'
        for candidate in self.MODELS:
            path = models_dir / candidate
            if path.exists():
                return str(path)
        return ''

    def _ensure_llama_cli(self) -> bool:
        """Find and set up llama.cpp CLI"""
        if self.llama_cli:
            return True

        candidates = [
            Path('/usr/local/bin/llama-cli'),
            Path(__file__).parent.parent / 'zeta_local-ai' / 'llama-cpp' / 'llama-cli',
            Path('/usr/local/bin/llama.cpp/llama-server'),
        ]
        for path in candidates:
            if path.exists() and os.access(path, os.X_OK):
                self.llama_cli = str(path)
                return True
        return False

    def _llama_prompt(self, prompt: str, max_tokens: int = 2048) -> str:
        """Run a prompt through llama.cpp CLI"""
        if not self._ensure_llama_cli():
            return ''

        cmd = [
            self.llama_cli,
            '--model', self.model_path,
            '--prompt', prompt,
            '--n-predict', str(max_tokens),
            '--ctx-size', '2048',
            '--temp', '0.3',
            '--repeat-penalty', '1.1',
        ]
        try:
            p = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            return p.stdout.strip()
        except (subprocess.TimeoutExpired, Exception) as e:
            return f''

    def generate_report(self, scan_data: dict, output_path: str = None, fmt: str = 'markdown') -> str:
        """
        Generate full markdown report with AI-assisted writing.
        Sections: Executive summary, risk assessment, findings, attack chains.
        """
        report = self._assemble_report(scan_data)

        # AI-enhanced sections
        if self.model_path and os.path.exists(self.model_path):
            try:
                # Executive summary
                summary_prompt = (
                    f"You are a cybersecurity analyst. Based on this scan data, "
                    f"write a concise executive summary (2-3 paragraphs):\n"
                    f"Target: {scan_data.get('target', scan_data.get('recon', {}).get('target', 'unknown'))}\n"
                    f"Risk: {scan_data.get('risk_score', 'N/A')}/10\n"
                    f"Findings: {len(scan_data.get('findings', []))}\n"
                    f"Attack chains: {len(scan_data.get('chaains', []))}\n"
                    f"Write in professional markdown format. Be factual, not alarmist."
                )
                ai_summary = self._llama_prompt(summary_prompt, max_tokens=500)
                if ai_summary:
                    # Replace placeholder summary
                    report = report.replace('[AI_SUMMARY]', ai_summary)
                    # Save enhanced report
                    if output_path:
                        with open(output_path, 'w') as f:
                            f.write(report)
                    return report

            except Exception:
                pass

        # No AI enhancement — save template report
        if output_path:
            with open(output_path, 'w') as f:
                f.write(report)
        return report

    def _assemble_report(self, data: dict) -> str:
        """Assemble a structured markdown report from scan data"""
        # Use correlation data if available
        correlation = data.get('correlation', data)
        recon = data.get('recon', {})
        webscan = data.get('webscan', {})
        exploit = data.get('exploit', {})
        findings = data.get('findings', [])

        risk = correlation.get('risk_score', 0)
        targets = correlation.get('targets_ranked', [])
        severities = correlation.get('severity_counts', {})
        chains = correlation.get('attack_chains', [])

        lines = []
        lines.append('# ZETA ∞ Security Assessment Report')
        lines.append('')
        lines.append(f'**Generated:** {datetime.utcnow().strftime("%Y-%m-%d %H:%M")}')
        lines.append(f'**Target:** {data.get("target", recon.get("target", "unknown"))}')
        lines.append('')

        # Executive summary placeholder for AI
        lines.append('## Executive Summary')
        lines.append('')
        lines.append('[AI_SUMMARY]')
        lines.append('')

        # Risk Assessment
        lines.append(f'## Risk Assessment: {risk}/10')
        lines.append('')
        risk_label = '🔴 Critical' if risk >= 8 else '🟠 High' if risk >= 6 else '🟡 Medium' if risk >= 4 else '🔵 Low'

        lines.append(f'**Overall Risk: ** {risk_label}')
        lines.append('')
        lines.append('| Severity | Count |')
        lines.append('|----------|-------|')
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = severities.get(sev, 0)
            lines.append(f'| {sev.upper()} | {count} |')
        lines.append(f'| Total | {sum(severities.values())} |')
        lines.append('')

        # Target ranking
        if targets:
            liness.append('## Target Ranking')
            lines.append('')
            for i, t in enumerate(targets, 1):
                lines.append(f'{i}. **{t.get("target", "unknown")}** — Risk: {t.get("risk_score", 0)}/10')
            lines.append('')

        # Attack chains
        if chains:
            liness.append(f'## Attack Chains ({len(chains)})')
            lines.append('')
            for i, chain in enumerate(chains, 1):
                lines.append(f'{i}. {chain.get("chain", "Unknown")}')
            lines.append('')

        # Findings
        if findings:
            lines.append('## Findings')
            lines.append('')
            for i, f in enumerate(findings, 1):
                sev = f.get('severity', 'info').upper()
                lines.append(f'### {i}. {f.get("finding", "Unknown finding")}')
                lines.append(f'- **Severity:** {sev}')
                if f.get('target'):
                    lines.append(f'- **Target:** {f["target"]}')
                if f.get('tool'):
                    lines.append(f'- **Tool:** {f["tool"]}')
                if f.get('details'):
                    lines.append(f'- **Details:** {f["details"]}')
                lines.append('')

        # Recommendations
        lines.append('## Recommendations')
        lines.append('')
        lines.append('Based on the findings above, the following actions are recommended:')
        lines.append('')
        lines.append('1. Review and remediate Critical/High vulnerabilities immediately')
        lines.append('2. Implement network segmentation to limit lateral movement')
        lines.append('3. Apply all available security patches')
        lines.append('4. Review and enhance monitoring and alerting')
        lines.append('5. Conduct regular penetration tests')

        return '\n'.join(lines)


# ─── CLI ─────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description='ZETA ∞ Report Generator')
    p.add_argument('input', help='JSON scan results file')
    p.add_argument('-o', '--output', help='Output report file (.md)')
    args = p.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    gen = AIReportGenerator()
    report = gen.generate_report(data, args.output)

    if not args.output:
        print(report)
    else:
        print(f'Report saved: {args.output}')
