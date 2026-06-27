#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OmniAdminFinder – Asynchronous Admin Page Discovery Engine
Repository: https://github.com/yourusername/OmniAdminFinder
License: MIT (Neutral Reference Implementation)
"""

import asyncio
import aiohttp
import aiofiles
import json
import re
import hashlib
import time
import urllib.parse
from urllib.parse import urljoin, urlparse
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from dataclasses import dataclass, field, asdict
import ssl
import socket
import random
import sys
import os
import logging

# Optional imports with graceful fallback
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    tqdm = lambda x, **kw: x

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_AVAILABLE = True
except ImportError:
    COLOR_AVAILABLE = False
    class Fore: RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; MAGENTA=''; WHITE=''; RESET=''; LIGHTRED_EX=''; LIGHTGREEN_EX=''; LIGHTCYAN_EX=''
    class Style: BRIGHT=''; RESET_ALL=''

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

# -----------------------------------------------------------------------------
# Configuration Constants
# -----------------------------------------------------------------------------

DEFAULT_WORDLIST = [
    "admin", "administrator", "administration", "adm", "adminpanel", "admin-panel",
    "admin_area", "admin_control", "admin_login", "admin-login", "admin.php",
    "admin.asp", "admin.aspx", "admin.do", "admin.action", "admin.jhtml",
    "cp", "cpanel", "controlpanel", "control-panel", "panel", "dashboard",
    "manage", "manager", "management", "operator", "staff", "staffarea",
    "backend", "backoffice", "back-office", "siteadmin", "webadmin",
    "sysadmin", "systemadmin", "system-administrator", "superadmin",
    "root", "superuser", "su", "sysop", "operator_panel",
    "wp-admin", "wp-login.php", "administrator/index.php", "administrator/login.php",
    "joomla/administrator", "drupal/admin", "magento/admin", "magento/index.php/admin",
    "shop/admin", "store/admin", "ecommerce/admin",
    "plesk", "whm", "cpanel", "webmail", "roundcube", "squirrelmail",
    "debug", "test", "testing", "dev", "development", "staging", "stage",
    "sandbox", "beta", "alpha", "demo", "example", "sample",
    "config", "configuration", "setup", "install", "installation",
    "upgrade", "update", "migration", "maintenance", "maintain",
    "laravel/admin", "laravel/login", "symfony/admin", "symfony/login",
    "rails/admin", "django/admin", "django-admin", "flask-admin",
    "spring/admin", "struts/admin", "jsf/admin", "asp.net/admin",
    "phpmyadmin", "mysqladmin", "sqladmin", "pgadmin", "adminer",
    "tomcat-manager", "manager/html", "host-manager",
    "jboss-web-console", "weblogic/console", "websphere/admin",
    "api/admin", "api/v1/admin", "api/v2/admin", "rest/admin",
    "graphql/admin", "graphiql", "playground", "voyager",
    "admin/api", "admin/rest", "admin/graphql",
    "secure", "private", "hidden", "secret", "classified", "internal",
    "only", "portal", "gateway", "entrance", "access", "auth",
    "login", "signin", "logon", "authenticate", "authorize",
    "session", "sso", "cas", "oauth", "openid",
]

EXTENDED_WORDLIST = [
    "admin1", "admin2", "admin123", "administrator1", "root1", "superuser1",
    "admin_backup", "admin_old", "admin_new", "admin_test", "admin_dev",
    "cpanel_webmail", "cpanel_login", "whm_login", "plesk_login",
    "webmin", "usermin", "virtualmin", "cloudmin",
    "zpanel", "sentora", "vesta", "ajenti", "froxlor",
    "ispconfig", "kloxo", "web-cp", "serveradmin",
    "directadmin", "directadmin/login", "da_admin",
    "interworx", "interworx/login", "iworx",
    "hsphere", "hsphere/login", "hsphere/control",
    "domainadmin", "domain-manager", "domains",
    "billing", "order", "invoice", "quotation", "estimate",
    "support", "helpdesk", "tickets", "service", "services",
    "monitor", "monitoring", "stats", "statistics", "analytics",
    "report", "reports", "logging", "logs", "audit",
    "backup", "backups", "restore", "recovery", "snapshot",
    "cron", "scheduled", "queue", "job", "worker",
    "cache", "clear-cache", "flush", "purge",
    "rebuild", "reindex", "optimize", "repair",
    "health", "ping", "status", "check", "diagnostic",
    "phpinfo", "info.php", "test.php", "php-test",
    "env", ".env", "environment", "config.php", "settings.php",
    "credentials", "secrets", "keys", "tokens", "passwords",
]

ADMIN_INDICATORS = {
    'title': re.compile(r'(admin|login|signin|logon|control|panel|dashboard|manage|staff|operator|superuser|system)', re.I),
    'header': re.compile(r'(set-cookie|session|token|auth|authorization|x-powered-by|server)', re.I),
    'body': re.compile(r'(password|username|userid|email|login|log in|sign in|authenticate|authorize|csrf|token|session|administrator|superuser)', re.I),
    'meta': re.compile(r'(robots|noindex,nofollow)', re.I),
    'form_action': re.compile(r'(login|auth|authenticate|signin|logon)', re.I),
}

# -----------------------------------------------------------------------------
# Data Structures
# -----------------------------------------------------------------------------

@dataclass
class ProbeResult:
    url: str
    path: str
    status_code: int
    response_time: float
    content_length: int
    content_hash: str
    title: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    redirected_to: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    is_admin_likely: bool = False
    confidence_score: int = 0
    raw_body_preview: str = ""
    detected_technologies: List[str] = field(default_factory=list)
    forms: List[Dict[str, str]] = field(default_factory=list)
    error_occurred: bool = False
    error_message: str = ""

@dataclass
class TargetConfig:
    base_url: str
    wordlist: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=lambda: ['', '.php', '.asp', '.aspx', '.jsp', '.do', '.action', '.html', '.htm'])
    methods: List[str] = field(default_factory=lambda: ['GET'])
    max_concurrent: int = 50
    timeout: float = 5.0
    max_redirects: int = 5
    follow_redirects: bool = True
    verify_ssl: bool = False
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    rate_limit: float = 0.0
    max_retries: int = 2
    retry_delay: float = 0.5
    respect_robots: bool = True
    detect_cms: bool = True
    fingerprint_tech: bool = True
    output_file: Optional[str] = None
    verbose: bool = False

# -----------------------------------------------------------------------------
# Core Engine
# -----------------------------------------------------------------------------

class AsyncAdminProber:
    def __init__(self, config: TargetConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.results: List[ProbeResult] = []
        self.path_queue: deque = deque()
        self.seen_paths: Set[str] = set()
        self.start_time: float = 0.0
        self.request_count: int = 0
        self.success_count: int = 0
        self.error_count: int = 0
        self.rate_limiter: Optional[asyncio.Task] = None
        self.last_request_time: float = 0.0
        self.lock = asyncio.Lock()

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=self.config.timeout * 3, connect=self.config.timeout)
        connector = aiohttp.TCPConnector(
            limit=self.config.max_concurrent * 2,
            limit_per_host=self.config.max_concurrent,
            ttl_dns_cache=300,
            ssl=False if not self.config.verify_ssl else True,
            enable_cleanup_closed=True,
            force_close=False,
        )
        headers = {
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        headers.update(self.config.headers)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            cookies=self.config.cookies,
        )
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def _rate_limit(self):
        if self.config.rate_limit <= 0:
            return
        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_request_time
            if elapsed < self.config.rate_limit:
                await asyncio.sleep(self.config.rate_limit - elapsed)
            self.last_request_time = time.monotonic()

    async def probe_path(self, path: str) -> Optional[ProbeResult]:
        await self._rate_limit()
        base = self.config.base_url.rstrip('/')
        path_clean = path.lstrip('/')
        url = f"{base}/{path_clean}" if path_clean else base
        result = ProbeResult(
            url=url,
            path=path_clean,
            status_code=0,
            response_time=0.0,
            content_length=0,
            content_hash="",
            title="",
            headers={}
        )
        for attempt in range(self.config.max_retries + 1):
            try:
                start = time.monotonic()
                async with self.semaphore:
                    method = 'GET'
                    async with self.session.request(
                        method=method,
                        url=url,
                        allow_redirects=self.config.follow_redirects,
                        max_redirects=self.config.max_redirects,
                        ssl=False if not self.config.verify_ssl else True,
                        proxy=self.config.proxy,
                    ) as response:
                        elapsed = time.monotonic() - start
                        result.response_time = elapsed
                        result.status_code = response.status
                        result.headers = dict(response.headers)
                        body = await response.content.read(50000)
                        body_str = body.decode('utf-8', errors='ignore')
                        result.content_length = len(body)
                        result.raw_body_preview = body_str[:500]
                        hash_obj = hashlib.sha256(body[:1024])
                        result.content_hash = hash_obj.hexdigest()
                        title_match = re.search(r'<title>(.*?)</title>', body_str, re.I | re.DOTALL)
                        if title_match:
                            result.title = title_match.group(1).strip()
                        form_matches = re.finditer(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>', body_str, re.I)
                        for fm in form_matches:
                            action = fm.group(1)
                            method_form = fm.group(2).upper()
                            inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', body_str, re.I)
                            result.forms.append({'action': action, 'method': method_form, 'inputs': inputs[:5]})
                        if response.history:
                            result.redirected_to = str(response.url)
                            result.redirect_chain = [str(h.url) for h in response.history]
                        self.request_count += 1
                        self.success_count += 1
                        self._classify_result(result, body_str)
                        return result
            except asyncio.TimeoutError:
                result.error_occurred = True
                result.error_message = f"Timeout (attempt {attempt+1})"
            except aiohttp.ClientError as e:
                result.error_occurred = True
                result.error_message = f"ClientError: {str(e)}"
            except Exception as e:
                result.error_occurred = True
                result.error_message = f"Unexpected: {str(e)}"
            if attempt < self.config.max_retries:
                await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
        self.error_count += 1
        return result

    def _classify_result(self, result: ProbeResult, body: str):
        score = 0
        tech_detected = []
        if result.status_code in (200, 302, 303, 307, 308):
            score += 20
        elif result.status_code == 401:
            score += 30
        elif result.status_code == 403:
            score += 25
        elif result.status_code == 404:
            score -= 50
        elif result.status_code in (500, 502, 503):
            score -= 20
        if result.title:
            if ADMIN_INDICATORS['title'].search(result.title):
                score += 25
                if 'login' in result.title.lower():
                    score += 10
                if 'dashboard' in result.title.lower():
                    score += 15
                if 'control' in result.title.lower():
                    score += 10
        header_text = ' '.join([f"{k}: {v}" for k, v in result.headers.items()])
        if ADMIN_INDICATORS['header'].search(header_text):
            score += 15
            if 'set-cookie' in header_text.lower():
                score += 5
                if 'session' in header_text.lower() or 'PHPSESSID' in header_text:
                    score += 5
        body_lower = body.lower()
        keyword_count = 0
        for pattern in ['admin', 'login', 'password', 'username', 'authenticate', 'authorize', 'session', 'csrf', 'token']:
            keyword_count += body_lower.count(pattern)
        if keyword_count > 5:
            score += min(keyword_count, 20)
        elif keyword_count > 0:
            score += keyword_count * 2
        if result.forms:
            score += 10
            for form in result.forms:
                if 'login' in form['action'].lower() or 'auth' in form['action'].lower():
                    score += 10
                if 'password' in ' '.join(form['inputs']):
                    score += 10
                if 'csrf' in ' '.join(form['inputs']):
                    score += 5
        if result.redirected_to:
            if 'login' in result.redirected_to.lower() or 'auth' in result.redirected_to.lower():
                score += 15
            if result.status_code in (302, 303, 307):
                score += 5
        if self.config.fingerprint_tech:
            server = result.headers.get('Server', '').lower()
            x_powered = result.headers.get('X-Powered-By', '').lower()
            if 'php' in server or 'php' in x_powered:
                tech_detected.append('PHP')
                if 'wp-admin' in result.path or 'wordpress' in body_lower:
                    tech_detected.append('WordPress')
                    score += 10
            if 'asp.net' in server or 'aspx' in result.path:
                tech_detected.append('ASP.NET')
            if 'django' in x_powered or 'django' in body_lower:
                tech_detected.append('Django')
                score += 10
            if 'rails' in server or 'ruby' in x_powered:
                tech_detected.append('Ruby on Rails')
            if 'laravel' in x_powered or 'laravel' in body_lower:
                tech_detected.append('Laravel')
                score += 10
            if 'spring' in server or 'java' in x_powered:
                tech_detected.append('Spring/Java')
            if 'magento' in body_lower:
                tech_detected.append('Magento')
                score += 10
            if 'joomla' in body_lower:
                tech_detected.append('Joomla')
                score += 10
            if 'drupal' in body_lower:
                tech_detected.append('Drupal')
                score += 10
            if 'phpmyadmin' in body_lower or 'adminer' in body_lower:
                tech_detected.append('DatabaseAdmin')
                score += 20
        result.detected_technologies = tech_detected
        if 'error' in body_lower and '404' in body_lower:
            score -= 30
        if 'page not found' in body_lower:
            score -= 25
        if 'under construction' in body_lower:
            score -= 20
        if 'coming soon' in body_lower:
            score -= 15
        if result.content_length < 100:
            score -= 10
        if result.content_length == 0 and result.status_code == 200:
            score -= 20
        result.confidence_score = max(0, min(100, score))
        result.is_admin_likely = result.confidence_score >= 40

    async def run_scan(self, wordlist: List[str]) -> List[ProbeResult]:
        self.start_time = time.monotonic()
        self.path_queue = deque(wordlist)
        self.seen_paths = set(wordlist)
        if self.config.extensions and len(self.config.extensions) > 1:
            extended_paths = []
            for path in wordlist:
                for ext in self.config.extensions:
                    if ext and not path.endswith(ext):
                        new_path = path + ext
                        if new_path not in self.seen_paths:
                            extended_paths.append(new_path)
                            self.seen_paths.add(new_path)
            self.path_queue.extend(extended_paths)
        total_paths = len(self.path_queue)
        if self.config.verbose:
            print(f"{Fore.CYAN}[*] Total paths to probe: {total_paths}")
        workers = []
        for _ in range(min(self.config.max_concurrent, total_paths)):
            workers.append(asyncio.create_task(self._worker()))
        if TQDM_AVAILABLE and not self.config.verbose:
            pbar = tqdm(total=total_paths, desc="Probing", unit="path", colour="green")
        else:
            pbar = None
        await asyncio.gather(*workers)
        if pbar:
            pbar.close()
        elapsed = time.monotonic() - self.start_time
        if self.config.verbose:
            print(f"{Fore.GREEN}[+] Scan completed in {elapsed:.2f}s")
            print(f"{Fore.YELLOW}[+] Requests: {self.request_count}, Success: {self.success_count}, Errors: {self.error_count}")
        self.results.sort(key=lambda r: r.confidence_score, reverse=True)
        return self.results

    async def _worker(self):
        while self.path_queue:
            path = self.path_queue.popleft()
            result = await self.probe_path(path)
            if result:
                self.results.append(result)
            await asyncio.sleep(0)

# -----------------------------------------------------------------------------
# Wordlist Generator
# -----------------------------------------------------------------------------

class WordlistGenerator:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.path = urlparse(base_url).path
        self.words = set()

    def generate(self, base_list: List[str] = None) -> List[str]:
        if base_list is None:
            base_list = DEFAULT_WORDLIST.copy()
        self.words.update(base_list)
        self.words.update(EXTENDED_WORDLIST)
        domain_parts = self.domain.split('.')
        if domain_parts:
            main_domain = domain_parts[0] if domain_parts else 'site'
            self.words.add(f"admin-{main_domain}")
            self.words.add(f"{main_domain}-admin")
            self.words.add(f"{main_domain}_admin")
            self.words.add(f"admin_{main_domain}")
            self.words.add(f"{main_domain}admin")
            self.words.add(f"admin{main_domain}")
            self.words.add(f"admin-{main_domain}-panel")
            self.words.add(f"{main_domain}-admin-panel")
        if self.path and self.path != '/':
            path_components = [p for p in self.path.split('/') if p]
            if path_components:
                last_component = path_components[-1]
                self.words.add(f"admin-{last_component}")
                self.words.add(f"{last_component}-admin")
                self.words.add(f"{last_component}_admin")
                self.words.add(f"{last_component}-panel")
                self.words.add(f"panel-{last_component}")
        for word in list(self.words):
            if len(word) > 3:
                self.words.add(f"{word}/index")
                self.words.add(f"{word}/login")
                self.words.add(f"{word}/dashboard")
                self.words.add(f"{word}/home")
                self.words.add(f"{word}/main")
                self.words.add(f"{word}/default")
                self.words.add(f"{word}/start")
                self.words.add(f"{word}/homepage")
                self.words.add(f"{word}/panel")
        current_year = datetime.now().year
        for year in range(current_year-5, current_year+1):
            self.words.add(f"admin{year}")
            self.words.add(f"{year}admin")
            self.words.add(f"admin-{year}")
            self.words.add(f"admin_{year}")
        typos = {
            "administrator": ["administrater", "adminstrator", "adminsitrator"],
            "dashboard": ["dashbord", "dashbaord", "dashbord"],
            "control": ["controll", "contro", "cntrol"],
            "panel": ["panal", "pannel", "pane"],
            "login": ["logon", "log-in", "signin", "singin"],
        }
        for base, variants in typos.items():
            for var in variants:
                self.words.add(var)
                self.words.add(f"admin-{var}")
                self.words.add(f"{var}-panel")
        final_list = sorted(self.words)
        final_list = [w for w in final_list if len(w) <= 50]
        return final_list

# -----------------------------------------------------------------------------
# Report Generator
# -----------------------------------------------------------------------------

class ReportGenerator:
    @staticmethod
    def generate_text_report(results: List[ProbeResult], base_url: str) -> str:
        lines = []
        lines.append(f"{'='*80}")
        lines.append(f"OMNIADMINFINDER – DISCOVERY REPORT")
        lines.append(f"Target: {base_url}")
        lines.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total paths probed: {len(results)}")
        found = [r for r in results if r.is_admin_likely]
        lines.append(f"Likely admin pages: {len(found)}")
        lines.append(f"{'='*80}\n")
        if not found:
            lines.append(f"{Fore.YELLOW}No admin pages found with confidence >= 40.{Fore.RESET}")
        else:
            for idx, r in enumerate(found[:50], 1):
                status_color = Fore.GREEN if r.status_code == 200 else (Fore.YELLOW if r.status_code in (302,401,403) else Fore.RED)
                score_color = Fore.GREEN if r.confidence_score >= 70 else (Fore.YELLOW if r.confidence_score >= 50 else Fore.RED)
                lines.append(f"{Fore.CYAN}{idx}. {r.url}{Fore.RESET}")
                lines.append(f"   Status: {status_color}{r.status_code}{Fore.RESET}  |  Score: {score_color}{r.confidence_score}%{Fore.RESET}")
                if r.title:
                    lines.append(f"   Title: {r.title}")
                if r.detected_technologies:
                    lines.append(f"   Tech: {', '.join(r.detected_technologies)}")
                if r.forms:
                    lines.append(f"   Forms: {len(r.forms)} detected")
                if r.redirected_to:
                    lines.append(f"   Redirects to: {r.redirected_to}")
                lines.append(f"   Response time: {r.response_time*1000:.1f}ms, Length: {r.content_length} bytes")
                lines.append(f"   Hash: {r.content_hash[:16]}...")
                if r.raw_body_preview:
                    preview = r.raw_body_preview[:200].replace('\n', ' ').replace('\r', ' ')
                    lines.append(f"   Preview: {preview}...")
                lines.append("")
        return '\n'.join(lines)

    @staticmethod
    def generate_json_report(results: List[ProbeResult], base_url: str) -> str:
        report = {
            "target": base_url,
            "timestamp": datetime.now().isoformat(),
            "total_probed": len(results),
            "likely_admin": [asdict(r) for r in results if r.is_admin_likely],
            "all_results": [asdict(r) for r in results[:100]],
            "statistics": {
                "status_codes": dict(defaultdict(int)),
                "avg_response_time": sum(r.response_time for r in results) / max(1, len(results)),
                "max_confidence": max([r.confidence_score for r in results]) if results else 0,
            }
        }
        # Fix: manually populate status_codes to avoid defaultdict serialization issue
        status_counts = {}
        for r in results:
            status_counts[r.status_code] = status_counts.get(r.status_code, 0) + 1
        report["statistics"]["status_codes"] = status_counts
        return json.dumps(report, indent=2, default=str)

    @staticmethod
    def generate_csv_report(results: List[ProbeResult], base_url: str) -> str:
        import csv
        from io import StringIO
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['URL', 'Path', 'Status', 'Score', 'Title', 'Tech', 'Redirect', 'Length', 'Time_ms', 'Hash'])
        for r in results[:200]:
            writer.writerow([
                r.url, r.path, r.status_code, r.confidence_score,
                r.title, ';'.join(r.detected_technologies),
                r.redirected_to or '', r.content_length,
                round(r.response_time*1000, 1), r.content_hash[:16]
            ])
        return output.getvalue()

# -----------------------------------------------------------------------------
# Main Orchestrator
# -----------------------------------------------------------------------------

class AdminFinder:
    def __init__(self, base_url: str, config: Optional[TargetConfig] = None):
        self.base_url = base_url.rstrip('/')
        self.config = config or TargetConfig(base_url=base_url)
        self.results: List[ProbeResult] = []
        self._reports = {}

    async def run(self) -> List[ProbeResult]:
        generator = WordlistGenerator(self.base_url)
        wordlist = generator.generate(self.config.wordlist or DEFAULT_WORDLIST)
        if self.config.verbose:
            print(f"{Fore.CYAN}[*] Generated {len(wordlist)} unique paths to probe")
        if self.config.respect_robots:
            additional = await self._fetch_robots_and_sitemap()
            wordlist.extend(additional)
            wordlist = list(set(wordlist))
            if self.config.verbose:
                print(f"{Fore.CYAN}[*] Added {len(additional)} paths from robots.txt/sitemap")
        async with AsyncAdminProber(self.config) as prober:
            self.results = await prober.run_scan(wordlist)
        self._reports = {
            'text': ReportGenerator.generate_text_report(self.results, self.base_url),
            'json': ReportGenerator.generate_json_report(self.results, self.base_url),
            'csv': ReportGenerator.generate_csv_report(self.results, self.base_url),
        }
        return self.results

    async def _fetch_robots_and_sitemap(self) -> List[str]:
        paths = []
        try:
            async with aiohttp.ClientSession() as session:
                robots_url = f"{self.base_url}/robots.txt"
                async with session.get(robots_url, timeout=5, ssl=False) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            line = line.strip()
                            if line.lower().startswith('disallow:'):
                                path = line.split(':', 1)[1].strip()
                                if path and path != '/':
                                    paths.append(path.lstrip('/'))
                            elif line.lower().startswith('allow:'):
                                path = line.split(':', 1)[1].strip()
                                if path and path != '/':
                                    paths.append(path.lstrip('/'))
                sitemap_candidates = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap/sitemap.xml']
                for candidate in sitemap_candidates:
                    try:
                        sitemap_full = f"{self.base_url}{candidate}"
                        async with session.get(sitemap_full, timeout=5, ssl=False) as resp2:
                            if resp2.status == 200:
                                xml = await resp2.text()
                                for match in re.finditer(r'<loc>(.*?)</loc>', xml, re.I):
                                    loc = match.group(1).strip()
                                    if loc.startswith(self.base_url):
                                        rel_path = loc[len(self.base_url):]
                                        if rel_path and rel_path != '/':
                                            paths.append(rel_path.lstrip('/'))
                    except:
                        pass
        except Exception as e:
            if self.config.verbose:
                print(f"{Fore.YELLOW}[!] Robots/sitemap fetch error: {e}")
        cleaned = []
        for p in paths:
            if '?' in p:
                p = p.split('?')[0]
            if '#' in p:
                p = p.split('#')[0]
            if p and len(p) < 100 and not p.startswith('http'):
                cleaned.append(p)
        return cleaned[:50]

    def get_text_report(self) -> str:
        return self._reports.get('text', '')

    def get_json_report(self) -> str:
        return self._reports.get('json', '{}')

    def get_csv_report(self) -> str:
        return self._reports.get('csv', '')

    async def save_results(self, filename_prefix: str = "admin_scan"):
        tasks = []
        if self._reports.get('text'):
            tasks.append(self._save_file(f"{filename_prefix}.txt", self._reports['text']))
        if self._reports.get('json'):
            tasks.append(self._save_file(f"{filename_prefix}.json", self._reports['json']))
        if self._reports.get('csv'):
            tasks.append(self._save_file(f"{filename_prefix}.csv", self._reports['csv']))
        await asyncio.gather(*tasks)

    async def _save_file(self, filename: str, content: str):
        async with aiofiles.open(filename, 'w', encoding='utf-8') as f:
            await f.write(content)
        if self.config.verbose:
            print(f"{Fore.GREEN}[+] Saved {filename}")

# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def print_banner():
    banner = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║    ██████╗ ███╗   ███╗███╗   ██╗██╗      █████╗ ██████╗ ███╗   ███╗██╗███╗   ██╗
║   ██╔═══██╗████╗ ████║████╗  ██║██║     ██╔══██╗██╔══██╗████╗ ████║██║████╗  ██║
║   ██║   ██║██╔████╔██║██╔██╗ ██║██║     ███████║██║  ██║██╔████╔██║██║██╔██╗ ██║
║   ██║   ██║██║╚██╔╝██║██║╚██╗██║██║     ██╔══██║██║  ██║██║╚██╔╝██║██║██║╚██╗██║
║   ╚██████╔╝██║ ╚═╝ ██║██║ ╚████║███████╗██║  ██║██████╔╝██║ ╚═╝ ██║██║██║ ╚████║
║    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝
║                                                                            ║
║          ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗                     ║
║          ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗                    ║
║          █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝                    ║
║          ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗                    ║
║          ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║                    ║
║          ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝                    ║
║                                                                            ║
║                    v4.2.1 – Distributed Admin Discovery                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description="OmniAdminFinder – Advanced Admin Page Discovery")
    parser.add_argument('url', help='Target base URL (e.g., https://example.com)')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist file (one path per line)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Max concurrent requests (default: 50)')
    parser.add_argument('-T', '--timeout', type=float, default=5.0, help='Request timeout in seconds (default: 5)')
    parser.add_argument('-r', '--rate-limit', type=float, default=0.0, help='Rate limit in seconds between requests (default: 0 = none)')
    parser.add_argument('-o', '--output', default='admin_scan', help='Output file prefix (default: admin_scan)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-ssl-verify', action='store_true', default=True, help='Disable SSL verification (default: True)')
    parser.add_argument('--extensions', help='Comma-separated extensions (e.g., .php,.asp)')
    parser.add_argument('--user-agent', default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--max-redirects', type=int, default=5)
    parser.add_argument('--no-follow-redirects', action='store_false', dest='follow_redirects')
    parser.add_argument('--no-banner', action='store_true', help='Suppress ASCII banner')
    return parser.parse_args()

async def main():
    args = parse_args()
    if not args.no_banner:
        print_banner()
    config = TargetConfig(
        base_url=args.url,
        max_concurrent=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        verify_ssl=not args.no_ssl_verify,
        user_agent=args.user_agent,
        proxy=args.proxy,
        max_redirects=args.max_redirects,
        follow_redirects=args.follow_redirects,
        verbose=args.verbose,
    )
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                custom_words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                config.wordlist = custom_words
                if args.verbose:
                    print(f"{Fore.CYAN}[*] Loaded {len(custom_words)} words from {args.wordlist}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to load wordlist: {e}")
    if args.extensions:
        ext_list = [e.strip() for e in args.extensions.split(',') if e.strip()]
        config.extensions = ext_list
    finder = AdminFinder(args.url, config)
    results = await finder.run()
    print(finder.get_text_report())
    await finder.save_results(args.output)
    if args.verbose:
        print(f"\n{Fore.CYAN}--- JSON Summary (first 3 results) ---{Fore.RESET}")
        json_data = json.loads(finder.get_json_report())
        for r in json_data.get('likely_admin', [])[:3]:
            print(f"{r['url']} (score: {r['confidence_score']})")

if __name__ == "__main__":
    asyncio.run(main())