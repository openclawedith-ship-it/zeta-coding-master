#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════
  KNOWLEDGE BASE — SQLite persistence layer for ZETA ∞
═══════════════════════════════════════════════════════════
Every scan result, vulnerability, host, credential, and
OSINT finding is stored here. The AI reads this database
to generate reports, find attack paths, and recommend
next steps.

Think of this as the platform's long-term memory.
"""

import sqlite3
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


class KnowledgeBase:
    """SQLite-backed knowledge base for all ZETA ∞ findings"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = str(Path(__file__).parent.parent / "db" / "zeta.db")
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT UNIQUE NOT NULL,
                target_type TEXT,
                first_seen TEXT DEFAULT (datetime('now')),
                last_seen TEXT,
                tags TEXT DEFAULT '[]',
                notes TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                ip TEXT,
                port INTEGER,
                is_live INTEGER DEFAULT 0,
                title TEXT,
                tech TEXT DEFAULT '[]',
                status_code INTEGER,
                first_seen TEXT DEFAULT (datetime('now')),
                UNIQUE(target, subdomain)
            );

            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                service TEXT,
                version TEXT,
                banner TEXT,
                extra TEXT,
                first_seen TEXT DEFAULT (datetime('now')),
                UNIQUE(host, port, protocol)
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                vulnerability TEXT,
                severity TEXT DEFAULT 'info',
                module TEXT,
                tool TEXT,
                finding TEXT,
                evidence TEXT,
                first_seen TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                username TEXT,
                password TEXT,
                hash TEXT,
                hash_type TEXT,
                source TEXT,
                cracked INTEGER DEFAULT 0,
                first_seen TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS osint_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                email TEXT NOT NULL,
                source TEXT,
                first_seen TEXT DEFAULT (datetime('now')),
                UNIQUE(target, email)
            );

            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT,
                modules_run TEXT DEFAULT '[]',
                start_time TEXT,
                end_time TEXT,
                findings_count INTEGER DEFAULT 0,
                report_path TEXT,
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                payload_type TEXT,
                payload TEXT,
                lhost TEXT,
                lport INTEGER,
                notes TEXT,
                created TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS file_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                md5 TEXT,
                sha1 TEXT,
                sha256 TEXT,
                file_type TEXT,
                category TEXT,
                entropy REAL,
                findings TEXT DEFAULT '[]',
                first_seen TEXT DEFAULT (datetime('now'))
            );
        """)
        self.conn.commit()

    # ─── Target Management ─────────────────────────────────

    def add_target(self, target: str, target_type: str = None,
                   tags: List[str] = None, notes: str = ""):
        tags = json.dumps(tags or [])
        self.conn.execute("""
            INSERT INTO targets (target, target_type, tags, notes, last_seen)
            VALUES (?, ?, ?, ?, datetime('now'))
            ON CONFLICT(target) DO UPDATE SET
                last_seen = datetime('now'),
                target_type = COALESCE(excluded.target_type, target_type),
                notes = CASE WHEN excluded.notes != '' THEN excluded.notes ELSE notes END
        """, (target, target_type, tags, notes))
        self.conn.commit()

    def get_targets(self) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM targets ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_target(self, target: str) -> Optional[Dict]:
        r = self.conn.execute(
            "SELECT * FROM targets WHERE target = ?",
            (target,)).fetchone()
        return dict(r) if r else None

    # ─── Subdomains ────────────────────────────────────────

    def add_subdomains(self, target: str, subdomains: List[Dict]):
        for sub in subdomains:
            if isinstance(sub, str):
                sub = {'subdomain': sub}
            self.conn.execute("""
                INSERT INTO subdomains
                    (target, subdomain, ip, is_live, title,
                     tech, status_code)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target, subdomain) DO UPDATE SET
                    ip = COALESCE(excluded.ip, ip),
                    is_live = COALESCE(excluded.is_live, is_live),
                    title = COALESCE(excluded.title, title),
                    tech = exclud.tech)
            """, (
                target,
                sub.get('subdmain', ''),
                sub.get('ip', ''),
                1 if sub.get('is_live') else 0,
                sub.get('title', ''),
                json.dumps(sub.get('tech', [])),
                sub.get('status_code', 0)
            ))
        self.conn.commit()

    def get_subdomains(self, target: str) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM subdomains WHERE target = ? ORDER BY subdomain",
            (target,)).fetchall()
        return [dict(r) for r in rows]

    # ─── Services ──────────────────────────────────────────

    def add_service(self, target: str, host: str, port: int,
                    protocol: str = "tcp", service: str = None,
                    version: str = None, banner: str = None,
                    extra: str = None):
        self.conn.execute("""
            INSERT INTO services
                (target, host, port, protocol, service, version, banner, extra)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host, port, protocol) DO UPDATE SET
                service = COALESCE(excluded.service, service),
                version = COALESCE(excluded.version, version),
                banner = COALESCE(excluded.banner, banner)
        """, (target, host, port, protocol, service, version, banner, extra))
        self.conn.commit()

    def get_services(self, target: str = None) -> List[Dict]:
        if target:
            rows = self.conn.execute(
                "SELECT * FROM services WHERE target = ? ORDER BY port",
                (target,)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM services ORDER BY target, port"
            ).fetchall()
        return [dict(r) for r in rows]

    # ─── Vulnerabilities ───────────────────────────────────

    def add_vulnerability(self, target: str, vulnerability: str,
                          severity: str, module: str, tool: str,
                          finding: str, evidence: str = None):
        self.conn.execute("""
            INSERT INTO vulnerabilities
                (target, vulnerability, severity, module, tool,
                 finding, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (target, vulnerability, severity, module, tool,
              finding, evidence))
        self.conn.commit()

    def get_vulnerabilities(self, target: str = None,
                            severity: str = None) -> List[Dict]:
        q = "SELECT * FROM vulnerabilities WHERE 1=1"
        args = []
        if target:
            q += " AND target = ?"
            args.append(target)
        if severity:
            q += " AND severity = ?"
            args.append(severity)
        q += (" ORDER BY CASE severity "
             "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
             "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 "
             "ELSE 4 END, first_seen DESC")
        rows = self.conn.execute(q, args).fetchall()
        return [dict(r) for r in rows]

    # ─── Credentials ───────────────────────────────────────

    def add_credential(self, target: str, username: str,
                       password: str = None, hash: str = None,
                       hash_type: str = None, source: str = None):
        cracked = 1 if password else 0
        self.conn.execute("""
            INSERT INTO credentials
                (target, username, password, hash, hash_type,
                 source, cracked)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (target, username, password, hash, hash_type,
              source, cracked))
        self.conn.commit()

    def get_credentials(self, target: str = None) -> List[Dict]:
        if target:
            rows = self.conn.execute(
                "SELECT * FROM credentials WHERE target = ?",
                (target,)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM credentials"
            ).fetchall()
        return [dict(r) for r in rows]

    # ─── OSINT Emails ─────────────────────────────────────

    def add_emails(self, target: str, emails: List[str],
                   source: str = None):
        for email in emails:
            self.conn.execute("""
                INSERT INTO osint_emails (target, email, source)
                VALUES (?, ?, ?)
                ON CONFLICT(target, email) DO NOTHING
            """, (target, email, source))
        self.conn.commit()

    def get_emails(self, target: str = None) -> List[Dict]:
        if target:
            rows = self.conn.execute(
                "SELECT * FROM osint_emails WHERE target = ?",
                (target,)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM osint_emails"
            ).fetchall()
        return [dict(r) for r in rows]

    # ─── Scan Runs ────────────────────────────────────────

    def start_scan(self, target: str, scan_type: str = "full",
                   modules: List[str] = None) -> int:
        cursor = self.conn.execute("""
            INSERT INTO scan_runs
                (target, scan_type, modules_run, start_time)
            VALUES (?, ?, ?, datetime('now'))
        """, (target, scan_type,
              json.dumps(modules or [])))
        self.conn.commit()
        return cursor.lastrowid

    def end_scan(self, scan_id: int, findings_count: int = 0,
                 report_path: str = None):
        self.conn.execute("""
            UPDATE scan_runs SET
                end_time = datetime('now'),
                findings_count = ?,
                report_path = ?
            WHERE id = ?
        """, (findings_count, report_path, scan_id))
        self.conn.commit()

    def get_scan_history(self) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM scan_runs ORDER BY start_time DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # ─── Stats & Reporting ─────────────────────────────────

    def stats(self) -> Dict[str, int]:
        tables = {
            'targets': 'targets',
            'subdomains': 'subdomains',
            'services': 'services',
            'vulnerabilities': 'vulnerabilities',
            'credentials': 'credentials',
            'emails': 'osint_emails',
            'scan_runs': 'scan_runs',
        }
        result = {}
        for key, table in tables.items():
            r = self.conn.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()
            result[key] = r[0]
        return result

    # ─── Close ─────────────────────────────────────────────

    def close(self):
        if self.conn:
            self.conn.close()
