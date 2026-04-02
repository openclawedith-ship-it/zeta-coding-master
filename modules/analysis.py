"""
Module 4: ANALYSIS — Passive Intelligence & Evidence Analysis
Chains: volatility3 → python-native file analysis → hash computation

Handles:
- File analysis (hashes, magic, strings)
- Memory dumps (volatility3)
- PCAP/network dumps (scapy)
- Vulnerability correlation & risk scores
"""

import os, sys, json, re, hashlib, struct
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any


class AnalysisModule:
    """Passive intelligence — no network touches, pure local analysis"""

    FILE_SIGNATURES = {
        # Windows executables
        b'MZ': ('PE Executable', 'binary'),
        b'\x7fELF': ('ELF Executable', 'binary'),
        # Archives
        b'\x50\x4b\x03\x04': ('ZIP Archive', 'archive'),
        b'\x1f\x8b': ('GZIP Archive', 'archive'),
        b'\x28\xb5\x2f\xfd': ('ZSTD Archive', 'archive'),
        b'\xfd7zXZ\x00': ('XZ Archive', 'archive'),
        b'Rar!\x1a\x07': ('RAR Archive', 'archive'),
        # Images
        b'\xff\xd8\xff': ('JPEG Image', 'image'),
        b'\x89PNG\r\n': ('PNG Image', 'image'),
        b'GIF8': ('GIF Image', 'image'),
        b'BM': ('BMP Image', 'image'),
        b'\x00\x00\x01\x00': ('ICO Image', 'image'),
        b'RIFF': ('RIFF/WebP', 'image'),
        # Documents
        b'%PDF': ('PDF Document', 'document'),
        b'\xd0\xcf\x11\xe0': ('MS Office (OLE2)', 'document'),
        b'PK\x03\x04': ('Office OpenXML (ZIP)', 'document'),
        # Web
        b'<!DOCTYPE html': ('HTML Document', 'web'),
        b'<html': ('HTML Document', 'web'),
        b'<?xml': ('XML Document', 'web'),
        # Scripts
        b'#!/bin/bash': ('Bash Script', 'text'),
        b'#!/bin/sh': ('Shell Script', 'text'),
        b'#!/usr/bin/env python': ('Python Script', 'text'),
        b'#!/usr/bin/env node': ('Node.js Script', 'text'),
        b'#!/usr/bin/env perl': ('Perl Script', 'text'),
        b'#!/usr/bin/env ruby': ('Ruby Script', 'text'),
        # Disk
        b'PKSM': ('Unknown (PK)', 'unknown'),
        b'\x81\xf7': ('Linux Swap', 'disk'),
        # Database
        b'\x53\x51\x4c\x69\x74\x65': ('SQLite Database', 'database'),
        b'WDSL\x00\x00': ('Unknown', 'unknown'),
    }

    def __init__(self):
        pass

    # ─── File Analysis ─────────────────────────────────────

    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """Deep file analysis: magic, hashes, strings, entropy"""
        result = {
            'file': filepath, 'timestamp': datetime.utcnow().isoformat(),
            'error': None,
        }

        if not os.path.isfile(filepath):
            result['error'] = 'File not found'
            return result

        try:
            stat = os.stat(filepath)
            result['size'] = stat.st_size
            result['human_size'] = self._human_size(stat.st_size)
            result['modified'] = datetime.utcfromtimestamp(
                stat.st_mtime).isoformat()
            result['permissions'] = oct(stat.st_mode)[-3:]
        except Exception as e:
            result['error'] = str(e)
            return result

        # Hashes
        result['hashes'] = self._hash_file(filepath)

        # Magic bytes / file type
        try:
            with open(filepath, 'rb') as f:
                header = f.read(64)
            for sig, (ftype, category) in self.FILE_SIGNATURES.items():
                if header[:len(sig)] == sig:
                    result['detected_type'] = ftype
                    result['category'] = category
                    break
            else:
                result['detected_type'] = 'Unknown'
        except Exception:
            pass

        # Entropy
        try:
            with open(filepath, 'rb') as f:
                data = f.read(100000)  # First 100KB
            result['entropy'] = self._calculate_entropy(data)
            if result.get('entropy', 0) > 7.0:
                result['entropy_flag'] = 'HIGH — Possibly encrypted/compressed/packed'
            elif result.get('entropy', 0) > 5.0:
                result['entropy_flag'] = 'MODERATE — Binary data'
        except Exception:
            pass

        # Printable strings (extract interesting ones)
        result['strings'] = self._extract_strings(filepath, count=150)

        # Specific analysis by type
        dtype = result.get('detected_type', '')
        if not result.get('category'):
            result['category'] = 'unknown'

        cat = result.get('category')

        # PE file analysis with capstone
        if cat == 'binary' or 'executable' in (result.get('detected_type', '') or '').lower():
            result['arch'] = self._guess_arch(filepath)
            # Try capstone disassembly if it's an ELF
            if 'ELF' in result.get('detected_type', str(result)):
                try:
                    result['capstone'] = self._disasm_entry(filepath)
                except Exception:
                    pass
            # Check for UPX packing
            try:
                with open(filepath, 'rb') as f:
                    content = f.read(100000)
                if b'UPX0' in content or b'UPX1' in content:
                    result['packed'] = True
                    result['packer'] = 'UPX'
            except Exception:
                pass

        # Document analysis
        elif cat == 'document':
            result['doc_info'] = self._analyze_document(filepath)

        # Archive analysis
        elif cat == 'archive':
            result['archive_info'] = self._analyze_archive(filepath)

        return result

    @staticmethod
    def _hash_file(filepath: str) -> Dict[str, str]:
        """Calculate multiple hashes for a file"""
        hashes = {}
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            hashes['sha512'] = hashlib.sha512(data).hexdigest()
        except Exception as e:
            hashes['error'] = str(e)
        return hashes

    @staticmethod
    def _human_size(nbytes: int) -> str:
        """Convert bytes to human-readable format"""
        for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
            if nbytes < 1024:
                return f"{nbytes:.1f} {unit}"
            nbytes /= 1024
        return f"{nbytes:.1f} PB"

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence"""
        if not data:
            return 0.0
        import math
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count:
                p = count / data_len
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    @staticmethod
    def _extract_strings(filepath: str, count: int = 100) -> List[str]:
        """Extract printable ASCII strings (min length 4)"""
        strings = []
        try:
            with open(filepath, 'rb') as f:
                data = f.read(100000)  # First 100KB
            import re as _re
            pattern = _re.compile(b'[\x20-\x7e]{4,}')
            raw = pattern.findall(data)
            for match in raw[:count]:
                try:
                    s = match.decode('ascii').strip()
                    if s and not s.isspace():
                        strings.append(s)
                except UnicodeDecodeError:
                    pass
        except Exception:
            pass
        return strings

    @staticmethod
    def _guess_arch(filepath: str) -> str:
        """Guess architecture from file header"""
        try:
            with open(filepath, 'rb') as f:
                header = f.read(64)
            # ELF
            if header[:4] == b'\x7fELF':
                ei_class = header[4]
                ei_data = header[5]
                ei_machine = struct.unpack('<H', header[18:20])[0]
                arch = '64-bit' if ei_class == 2 else '32-bit'
                machine = {
                    0x3e: 'x86_64', 0x03: 'x86',
                    0xb7: 'AArch64', 0x28: 'ARM',
                    0x08: 'MIPS', 0x02: 'SPARC',
                    0xf3: 'RISC-V', 0x14: 'PowerPC'
                }.get(ei_machine, f'unknown({ei_machine})')
                endian = 'little-endian' if ei_data == 1 else 'big-endian'
                return f'{machine} {arch} {endian}'
            # MZ
            if header[:2] == b'MZ':
                return 'x86/x86_64 (PE)'
            # Universal
            return 'unknown'
        except Exception:
            return 'unknown'

    @staticmethod
    def _disasm_entry(filepath: str) -> str:
        """Try to disassemble a few instructions from the entry point"""
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            with open(filepath, 'rb') as f:
                data = f.read()
            # Simple ELF entry at offset specified in header
            e_entry = struct.unpack('<Q', data[24:32])[0]
            # Find the offset for that virtual address
            # For simplicity, try the entry point directly
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            start = data.find(b'\x7fELF')
            if start != -1:
                e_phoff = struct.unpack('<Q', data[start+32:start+40])[0]
                code_offset = e_phoff + 64
                code = data[code_offset:code_offset+64]
                return str(list(md.disasm(code, 0x400000))[:10])
            return 'could not disassemble'
        except Exception:
            return 'capstone disassembly failed'

    @staticmethod
    def _analyze_document(filepath: str) -> Dict:
        """Extract metadata from documents"""
        meta = {}
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            # Check for embedded URLs
            import re as _re
            urls = _re.findall(rb'(?:https?|ftp)://[^\s<>"\']{4,200}', data)
            meta['urls'] = [u.decode('ascii', errors='ignore')[:200]
                            for u in urls[:10]]

            # Check for email-like patterns
            emails = _re.findall(rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}', data)
            meta['emails'] = [e.decode('ascii', errors='ignore')[:200]
                              for e in emails[:10]]

            return meta
        except Exception as e:
            return {'error': str(e)}

    @staticmethod
    def _analyze_archive(filepath: str) -> Dict:
        """Analyze archive contents"""
        info = {}
        try:
            # Try ZIP first
            import zipfile
            info['type'] = 'ZIP'
            info['file_count'] = 0
            info['total_size'] = 0
            try:
                with zipfile.ZipFile(filepath, 'r') as zf:
                    infos = zf.infolist()
                    info['file_count'] = len(infos)
                    info['total_size'] = sum(zi.file_size for zi in infos)
                    info['filenames'] = [zi.filename for zi in infos[:50]]
            except zipfile.BadZipFile:
                pass
            return info
        except Exception as e:
            info['error'] = str(e)
            return info

    # ─── Memory Dump Analysis (volatility3) ─────────────

    def analyze_memory_dump(self, dump_path: str) -> Dict[str, Any]:
        """Analyze memory dump with volatility3"""
        result = {'dump': dump_path, 'timestamp': datetime.utcnow().isoformat()}

        if not os.path.isfile(dump_path):
            result['error'] = 'Dump file not found'
            return result

        if not self._has_volatility():
            result['error'] = 'volatility3 not installed'
            return result

        # List plugins
        try:
            import subprocess
            proc = subprocess.run(
                ['vol', '-f', dump_path, '--list'],
                capture_output=True, text=True, timeout=30)
            result['available_plugins'] = [
                line for line in proc.stdout.splitlines()
                if line.strip()][:20]

            # Run key plugins
            plugins = {
                'windows.pslist': 'processes',
                'windows.netscan': 'network',
                'windows.cmdline': 'cmdline',
                'windows.filescan': 'files',
                'windows.envars': 'environment',
                'windows.dlllist': 'dlls',
            }
            for plugin_name, report_key in plugins.items():
                try:
                    proc = subprocess.run(
                        ['vol', '-f', dump_path,
                         '-r', 'json',
                         plugin_name],
                        capture_output=True, text=True,
                        timeout=60)
                    if proc.stdout.strip():
                        # Parse JSON output
                        lines = proc.stdout.splitlines()
                        data = [json.loads(line) for line
                                in lines if line.strip()]
                        result[report_key] = data[:100]
                except Exception as e:
                    result[f'{report_key}_error'] = str(e)
            return result

        except Exception as e:
            result['error'] = str(e)
            return result

    @staticmethod
    def _has_volatility():
        import subprocess
        try:
            proc = subprocess.run(
                ['vol', '--version'],
                capture_output=True, text=True)
            return proc.returncode == 0
        except Exception:
            return False

    # ─── Network PCAP Analysis (scapy fallback) ─────────────

    def analyze_pcap(self, pcaps: str) -> Dict:
        """
        Analyze network packet capture for:
        - Top talkers (source IPs by packet count)
        - Protocol distribution
        - Suspicious ports
        - DNS queries (potential C2 / exfiltration)
        """
        result = {
            'file': pcaps,
            'timestamp': datetime.utcnow().isoformat(),
            'error': None,
            'total_packets': 0,
        }

        if not os.path.isfile(pcaps):
            result['error'] = 'PCAP file not found'
            return result

        try:
            from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, ARP
            packets = rdpcap(pcaps)
            result['total_packets'] = len(packets)

            src_counts = {}
            proto_counts = {}
            dst_ports = {}
            dns_queries = []
            total_bytes = 0

            for pkt in packets:
                if pkt.haslayer(IP):
                    src = pkt[IP].src
                    src_counts[src] = src_counts.get(src, 0) + 1
                    total_bytes += len(pkt)

                    proto = pkt[IP].proto
                    proto_counts[proto] = proto_counts.get(proto, 0) + 1

                    if pkt.haslayer(TCP):
                        dport = pkt[TCP].dport
                        dst_ports[dport] = dst_ports.get(dport, 0) + 1
                    elif pkt.haslayer(UDP):
                        dport = pkt[UDP].dport
                        dst_ports[dport] = dst_ports.get(dport, 0) + 1

                    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                        qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                        dns_queries.append(qname)

            result['total_bytes'] = total_bytes
            result['top_talkers'] = sorted(
                src_counts.items(), key=lambda x: x[1], reverse=True)[:20]
            result['protocol_distribution'] = proto_counts
            result['top_destination_ports'] = sorted(
                dst_ports.items(), key=lambda x: x[1], reverse=True)[:20]

            # Check for suspicious ports
            suspicious_ports = {
                4444: 'Metasploit default',
                4445: 'Metasploit secondary',
                1337: 'Default hacker port',
                31337: 'Back Orifice / Elite',
                12345: 'NetBus',
                5555: 'Default Android debug',
                8080: 'HTTP proxy (could be C2)',
                8443: 'HTTPS alt (could be C2)',
            }
            result['suspicious_ports'] = {
                str(port): desc for port, desc in suspicious_ports.items()
                if port in dst_ports
            }

            # Top DNS queries (potential C2 domains)
            from collections import Counter
            dns_counts = Counter(dns_queries)
            result['top_dns_queries'] = [{'domain': d, 'count': c} for d, c in dns_counts.most_common(30)]

        except Exception as e:
            result['error'] = f'Scapy error: {str(e)}'

        return result

    # ─── Vulnerability Correlation ─────────────────────────

    def correlate_vulnerabilities(self, findings: List[Dict]) -> Dict:
        """
        Given a list of vulnerability findings from other modules,
        compute:
        - Overall risk score (CVSS-like)
        - Chainable exploit paths
        - Attack surface summary
        - Remediation priority order
        """
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_findings': len(findings),
            'risk_score': 0,
            'chains': [],
            'remediation_order': [],
            'attack_surface': {},
        }

        if not findings:
            result['risk_score'] = 0
            return result

        severity_weights = {
            'critical': 10.0,
            'high': 7.0,
            'medium': 4.0,
            'low': 2.0,
            'info': 0.5,
        }

        # Calculate risk score (average weighted, normalized to 10)
        total_weight = 0
        count = 0
        for f in findings:
            sev = f.get('severity', '').lower()
            weight = severity_weights.get(sev, 0.5)
            total_weight += weight
            count += 1

        result['risk_score'] = round(
            (total_weight / count) if count > 0 else 0, 1)

        # Chainable exploits
        findings_by_target = {}
        for f in findings:
            target = f.get('target', 'unknown')
            if target not in findings_by_target:
                findings_by_target[target] = []
            findings_by_target[target].append(f)

        for target, vfs in findings_by_target.items():
            severities = [f.get('severity', 'info').lower() for f in vfs]
            # If multiple vulnerabilities exist on same target, they're potentially chainable
            if len(vfs) > 1 and any(s in ('critical', 'high') for s in severities):
                chain_desc = [f.get('finding', '')[:60] for f in vfs]
                result['chains'].append({
                    'target': target,
                    'chain_length': len(vfs),
                    'description': ' → '.join(chain_desc),
                    'risk': 'HIGH' if any(s == 'critical' for s in severities) else 'Medium',
                })

        # Remediation order (critical first, then by target)
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_weights.get(
                f.get('severity', 'info').lower(), 0.5),
            reverse=True)
        result['remediation_order'] = [
            {'severity': f.get('severity', 'info'),
             'finding': f.get('finding', ''),
             'target': f.get('target', '')}
            for f in sorted_findings[:20]  # Top 20
        ]

        # Attack surface summary
        vuln_types = {}
        tech_stack = set()
        for f in findings:
            vtype = f.get('vulnerability', 'Unknown')
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
            tech = f.get('technology', '')
            if tech:
                tech_stack.add(tech)
        result['attack_surface'] = {
            'vulnerability_types': vuln_types,
            'technology_stack': sorted(tech_stack),
        }

        return result
