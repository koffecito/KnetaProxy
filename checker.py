#!/usr/bin/env python3

import base64
import concurrent.futures
import ipaddress
import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

import requests


#---------
# КОНФИГУРАЦИЯ
#----------

SUBSCRIPTIONS_ENV = "SUBSCRIPTIONS"
TYPE_FILE = os.environ.get("TYPE_FILE", "type.txt")
CHEBURCHECK_URL = os.environ.get("CHEBURCHECK_URL", "https://cheburcheck.ru/api/v1/check")
CHEBURCHECK_TIMEOUT = float(os.environ.get("CHEBURCHECK_TIMEOUT", 5))
CHEBURCHECK_WORKERS = int(os.environ.get("CHEBURCHECK_WORKERS", 4))
CHEBURCHECK_RETRIES = int(os.environ.get("CHEBURCHECK_RETRIES", 2))
CHEBURCHECK_MIN_INTERVAL = float(os.environ.get("CHEBURCHECK_MIN_INTERVAL", 0.8))
XRAY_BIN = os.environ.get("XRAY_BIN", "xray")
XRAY_STARTUP_DELAY = float(os.environ.get("XRAY_STARTUP_DELAY", 1.2))
REQUEST_TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", 6))
EXIT_IP_API_URL = os.environ.get("EXIT_IP_API_URL", "https://api.ipify.org?format=json")
EXIT_IP_TIMEOUT = float(os.environ.get("EXIT_IP_TIMEOUT", 5))
EXIT_IP_RETRIES = int(os.environ.get("EXIT_IP_RETRIES", 1))
COUNTRY_API_URL = os.environ.get("COUNTRY_API_URL", "https://api.country.is")
COUNTRY_TIMEOUT = float(os.environ.get("COUNTRY_TIMEOUT", 5))
COUNTRY_RETRIES = int(os.environ.get("COUNTRY_RETRIES", 1))
COUNTRY_MIN_INTERVAL = float(os.environ.get("COUNTRY_MIN_INTERVAL", 0.2))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", 6))
MAX_PROXIES = int(os.environ.get("MAX_PROXIES", 100))
NAME_SUFFIX = os.environ.get("NAME_SUFFIX", "@KnetaEx")
INFO_FILE = os.environ.get("INFO_FILE", "info.txt")


def load_info_file(path: str = INFO_FILE) -> dict[str, str]:
    values = {
        "title_main": "KnetaProxy | Основная Подписка",
        "title_all": "KnetaProxy | Полная Подписка",
        "update_interval": "4",
        "support_url": "https://t.me/KnetaProxy",
        "announce": "Если не работает, то нажмите 🔄, а затем 🕒",
        "name_suffix": NAME_SUFFIX,
    }
    if not os.path.exists(path):
        return values
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                if key.strip() in values:
                    values[key.strip()] = value.strip()
    except OSError as e:
        print(f"[!] Не удалось прочитать {path}: {e}", file=sys.stderr)
    return values


INFO = load_info_file()
NAME_SUFFIX = INFO["name_suffix"]

OUTPUT_DIR = "proxies"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "working.txt")
ALL_FILE = os.path.join(OUTPUT_DIR, "all.txt")
REPORT_FILE = os.path.join(OUTPUT_DIR, "report.txt")
HISTORY_FILE = os.path.join(OUTPUT_DIR, "history.json")
TMP_DIR = "tmp_configs"
GENERATE_204_URLS = tuple(
    x.strip()
    for x in os.environ.get(
        "GENERATE_204_URLS",
        "https://www.gstatic.com/generate_204,https://clients3.google.com/generate_204,https://connectivitycheck.gstatic.com/generate_204"
    ).split(",")
    if x.strip()
)
TCP_TARGETS = [x.strip() for x in os.environ.get("TCP_TARGETS", "1.1.1.1:443").split(",") if x.strip()]

_chebur_lock = threading.Lock()
_chebur_last_call = 0.0
_chebur_next_allowed = 0.0
_chebur_cache: dict[str, tuple[bool, str]] = {}
_chebur_cache_lock = threading.Lock()
_country_lock = threading.Lock()
_country_last_call = 0.0
_country_cache: dict[str, tuple[str, str]] = {}

SITE_RETRIES = int(os.environ.get("SITE_RETRIES", 2))
SITE_RETRY_BACKOFF = float(os.environ.get("SITE_RETRY_BACKOFF", 0.8))
HTTP_TRANSIENT = {429, 500, 502, 503, 504}
SUPPORTED_SCHEMES = ("vless", "vmess", "trojan", "hysteria2", "hy2")


#---------
# СТРАНЫ
#----------

COUNTRY_NAMES_RU = {
    "RU": "Россия", "US": "США", "DE": "Германия", "NL": "Нидерланды",
    "FR": "Франция", "GB": "Великобритания", "FI": "Финляндия", "JP": "Япония",
    "SG": "Сингапур", "KR": "Южная Корея", "CA": "Канада", "TR": "Турция",
    "PL": "Польша", "UA": "Украина", "CH": "Швейцария", "SE": "Швеция",
    "ES": "Испания", "IT": "Италия", "HK": "Гонконг", "IN": "Индия",
    "AE": "ОАЭ", "KZ": "Казахстан", "AM": "Армения", "GE": "Грузия",
    "LT": "Литва", "LV": "Латвия", "EE": "Эстония", "CZ": "Чехия",
    "AT": "Австрия", "BE": "Бельгия", "PT": "Португалия", "GR": "Греция",
    "RO": "Румыния", "BG": "Болгария", "HU": "Венгрия", "IE": "Ирландия",
    "DK": "Дания", "NO": "Норвегия", "IS": "Исландия", "LU": "Люксембург",
    "MD": "Молдова", "AZ": "Азербайджан", "UZ": "Узбекистан", "KG": "Киргизия",
    "BR": "Бразилия", "AU": "Австралия", "NZ": "Новая Зеландия", "ZA": "ЮАР",
    "CN": "Китай", "TW": "Тайвань", "TH": "Таиланд", "VN": "Вьетнам",
    "ID": "Индонезия", "MY": "Малайзия", "PH": "Филиппины", "IL": "Израиль",
    "SA": "Саудовская Аравия", "EG": "Египет", "MX": "Мексика", "AR": "Аргентина",
    "CL": "Чили", "CY": "Кипр", "MT": "Мальта", "SK": "Словакия",
    "SI": "Словения", "HR": "Хорватия", "RS": "Сербия", "AL": "Албания",
    "BA": "Босния и Герцеговина", "MK": "Северная Македония", "ME": "Черногория",
}


def country_flag(iso: str) -> str:
    iso = (iso or "").upper()
    if len(iso) != 2 or not iso.isalpha():
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in iso)


def country_name(iso: str) -> str:
    iso = (iso or "").upper()
    return COUNTRY_NAMES_RU.get(iso, iso or "Неизвестно")


#---------
# ТИП ПРОВЕРКИ
#----------

@dataclass(frozen=True)
class CheckConfig:
    mode: str


def load_check_config(path: str = TYPE_FILE) -> CheckConfig:
    mode = "generate_204"
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip().lower()
        if raw in {"generate_204", "tcp", "no"}:
            mode = raw
        elif raw:
            print(f"[!] {path}: неизвестный режим '{raw}', использую generate_204", file=sys.stderr)
    return CheckConfig(mode=mode)


#---------
# МОДЕЛЬ КОНФИГА
#----------

@dataclass
class ProxyConfig:
    scheme: str
    host: str
    port: int
    user: str = ""
    password: str = ""
    name: str = ""
    params: dict[str, str] = field(default_factory=dict)
    extra: dict = field(default_factory=dict)

    def identity(self) -> tuple:
        return (
            self.scheme,
            self.host.lower(),
            self.port,
            self.user,
            self.password,
            tuple(sorted(self.params.items())),
            json.dumps(self.extra, sort_keys=True, ensure_ascii=False),
        )

    def transport(self) -> str:
        value = self.params.get("type", self.params.get("net", "tcp")).lower()
        return {
            "tcp": "raw",
            "raw": "raw",
            "ws": "websocket",
            "websocket": "websocket",
            "grpc": "grpc",
            "xhttp": "xhttp",
            "httpupgrade": "httpupgrade",
            "kcp": "mkcp",
            "mkcp": "mkcp",
        }.get(value, value)

    def to_link(self, name: str | None = None) -> str:
        title = name if name is not None else self.name
        if self.scheme == "vmess":
            data = dict(self.extra)
            data["ps"] = title
            raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
            return "vmess://" + base64.b64encode(raw).decode()
        if self.scheme == "vless":
            query = urlencode(self.params, doseq=False)
            link = f"vless://{quote(self.user, safe='')}@{self.host}:{self.port}"
            if query:
                link += "?" + query
            return link + ("#" + quote(title, safe="") if title else "")
        if self.scheme == "trojan":
            query = urlencode(self.params, doseq=False)
            link = f"trojan://{quote(self.password, safe='')}@{self.host}:{self.port}"
            if query:
                link += "?" + query
            return link + ("#" + quote(title, safe="") if title else "")
        if self.scheme == "hysteria2":
            query = urlencode(self.params, doseq=False)
            link = f"hysteria2://{quote(self.password, safe='')}@{self.host}:{self.port}"
            if query:
                link += "?" + query
            return link + ("#" + quote(title, safe="") if title else "")
        return ""


#---------
# ПАРСИНГ
#----------

def first_param(params: dict[str, list[str]], key: str, default: str = "") -> str:
    values = params.get(key)
    return values[0] if values else default


def parse_query(query: str) -> dict[str, str]:
    return {k: unquote(v[0]) if v else "" for k, v in parse_qs(query, keep_blank_values=True).items()}


def parse_vless(link: str) -> ProxyConfig | None:
    try:
        u = urlparse(link)
        if u.scheme.lower() != "vless" or not u.username or not u.hostname or not u.port:
            return None
        return ProxyConfig("vless", u.hostname, u.port, unquote(u.username), name=unquote(u.fragment), params=parse_query(u.query))
    except Exception:
        return None


def parse_trojan(link: str) -> ProxyConfig | None:
    try:
        u = urlparse(link)
        if u.scheme.lower() != "trojan" or not u.username or not u.hostname or not u.port:
            return None
        return ProxyConfig("trojan", u.hostname, u.port, password=unquote(u.username), name=unquote(u.fragment), params=parse_query(u.query))
    except Exception:
        return None


def parse_hysteria2(link: str) -> ProxyConfig | None:
    try:
        u = urlparse(link)
        if u.scheme.lower() not in {"hysteria2", "hy2"} or not u.hostname or not u.port:
            return None
        return ProxyConfig("hysteria2", u.hostname, u.port, password=unquote(u.username or ""), name=unquote(u.fragment), params=parse_query(u.query))
    except Exception:
        return None


def parse_vmess(link: str) -> ProxyConfig | None:
    try:
        payload = link.split("://", 1)[1]
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8", errors="strict")
        data = json.loads(raw)
        host = str(data.get("add", "")).strip()
        port = int(data.get("port", 0))
        user = str(data.get("id", "")).strip()
        if not host or not port or not user:
            return None
        params = {
            "type": str(data.get("net", data.get("type", "tcp")) or "tcp"),
            "security": str(data.get("tls", "") or "none"),
            "sni": str(data.get("sni", "") or ""),
            "host": str(data.get("host", "") or ""),
            "path": str(data.get("path", "") or "/"),
            "fp": str(data.get("fp", "") or ""),
            "pbk": str(data.get("pbk", "") or ""),
            "sid": str(data.get("sid", "") or ""),
            "alpn": str(data.get("alpn", "") or ""),
        }
        params = {k: v for k, v in params.items() if v}
        return ProxyConfig("vmess", host, port, user=user, name=str(data.get("ps", "") or ""), params=params, extra=data)
    except Exception:
        return None


def parse_link(link: str) -> ProxyConfig | None:
    scheme = link.split(":", 1)[0].lower() if ":" in link else ""
    if scheme == "vless":
        return parse_vless(link)
    if scheme == "vmess":
        return parse_vmess(link)
    if scheme == "trojan":
        return parse_trojan(link)
    if scheme in {"hysteria2", "hy2"}:
        return parse_hysteria2(link)
    return None


def supported_link(line: str) -> bool:
    return line.lower().startswith(("vless://", "vmess://", "trojan://", "hysteria2://", "hy2://"))


#---------
# ПОДПИСКИ
#----------

def decode_subscription_text(raw: str) -> list[str]:
    text = raw.strip()
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    direct = [x for x in lines if supported_link(x)]
    if direct:
        return direct
    try:
        decoded = base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", errors="ignore")
    except Exception:
        decoded = text
    return [x.strip() for x in decoded.splitlines() if supported_link(x.strip())]


def http_error_text(service: str, response: requests.Response) -> str:
    reason = (response.reason or "").strip()
    suffix = f" {reason}" if reason else ""
    return f"{service}: HTTP {response.status_code}{suffix}"


def exception_text(service: str, exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return f"{service}: timeout при подключении"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return f"{service}: timeout ожидания ответа"
    if isinstance(exc, requests.exceptions.Timeout):
        return f"{service}: timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return f"{service}: ошибка соединения"
    if isinstance(exc, requests.exceptions.InvalidURL):
        return f"{service}: некорректный URL"
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return f"{service}: слишком много перенаправлений"
    # Не включаем текст исключения: он может содержать секретный URL источника.
    return f"{service}: {type(exc).__name__}"


def fetch_subscription(url: str) -> tuple[list[str], str]:
    for attempt in range(SITE_RETRIES + 1):
        try:
            r = requests.get(url, timeout=15, allow_redirects=True)
            if r.status_code in HTTP_TRANSIENT and attempt < SITE_RETRIES:
                retry_after = r.headers.get("Retry-After")
                try:
                    delay = min(float(retry_after), 10.0) if retry_after else SITE_RETRY_BACKOFF * (2 ** attempt)
                except ValueError:
                    delay = SITE_RETRY_BACKOFF * (2 ** attempt)
                time.sleep(delay)
                continue
            if not r.ok:
                return [], http_error_text("подписка", r)
            links = decode_subscription_text(r.text)
            print(f"[+] Источник обработан: найдено {len(links)} поддерживаемых ссылок")
            return links, ""
        except requests.RequestException as e:
            if attempt < SITE_RETRIES:
                time.sleep(SITE_RETRY_BACKOFF * (2 ** attempt))
                continue
            return [], exception_text("подписка", e)
    return [], "подписка: неизвестная ошибка"


def load_subscription_sources() -> tuple[list[str], dict[str, int], list[str]]:
    stats = {"sources": 0, "sources_ok": 0, "sources_failed": 0, "unsupported_lines": 0}
    errors: list[str] = []
    raw_sources = os.environ.get(SUBSCRIPTIONS_ENV, "")
    if not raw_sources.strip():
        error = f"не задан GitHub Secret / переменная окружения {SUBSCRIPTIONS_ENV}"
        print(f"[!] {error}", file=sys.stderr)
        return [], stats, [error]

    result: list[str] = []
    source_number = 0
    for raw in raw_sources.splitlines():
        source = raw.strip()
        if not source or source.startswith("#"):
            continue
        if source.startswith(("http://", "https://")):
            source_number += 1
            stats["sources"] += 1
            links, error = fetch_subscription(source)
            if error:
                stats["sources_failed"] += 1
                errors.append(f"источник #{source_number}: {error}")
                print(f"[!] Источник #{source_number}: {error}", file=sys.stderr)
            else:
                stats["sources_ok"] += 1
                result.extend(links)
        elif supported_link(source):
            result.append(source)
        else:
            stats["unsupported_lines"] += 1
            # Не печатаем строку: она может содержать приватную конфигурацию.
            print("[!] Пропущена неизвестная строка в SUBSCRIPTIONS")
    return result, stats, errors


def collect_configs() -> tuple[list[ProxyConfig], dict[str, int], list[str]]:
    links, source_stats, source_errors = load_subscription_sources()
    stats = {
        "received": len(links),
        "invalid": 0,
        "duplicates": 0,
        "unique": 0,
        "unsupported_lines": source_stats["unsupported_lines"],
        "sources": source_stats["sources"],
        "sources_ok": source_stats["sources_ok"],
        "sources_failed": source_stats["sources_failed"],
    }
    for scheme in SUPPORTED_SCHEMES:
        stats[f"received_{scheme}"] = 0
        stats[f"unique_{scheme}"] = 0
    result: list[ProxyConfig] = []
    seen = set()
    for link in links:
        scheme = link.split(":", 1)[0].lower() if ":" in link else ""
        if scheme in SUPPORTED_SCHEMES:
            stats[f"received_{scheme}"] += 1
        proxy = parse_link(link)
        if proxy is None:
            stats["invalid"] += 1
            continue
        key = proxy.identity()
        if key in seen:
            stats["duplicates"] += 1
            continue
        seen.add(key)
        result.append(proxy)
        stats[f"unique_{proxy.scheme}"] += 1
    stats["unique"] = len(result)
    return result, stats, source_errors


#---------
# CHEBURCHECK
#----------

def host_ips(host: str) -> list[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    result = []
    for info in infos:
        ip = info[4][0]
        if ip not in result:
            result.append(ip)
    return result


def cheburcheck_ip(ip: str) -> tuple[bool, str]:
    global _chebur_last_call, _chebur_next_allowed
    with _chebur_cache_lock:
        cached = _chebur_cache.get(ip)
        if cached is not None:
            return cached

    last_error = ""
    for attempt in range(CHEBURCHECK_RETRIES + 1):
        with _chebur_lock:
            now = time.monotonic()
            wait = max(0.0, _chebur_next_allowed - now, CHEBURCHECK_MIN_INTERVAL - (now - _chebur_last_call))
            if wait > 0:
                time.sleep(wait)
            _chebur_last_call = time.monotonic()
            _chebur_next_allowed = _chebur_last_call + CHEBURCHECK_MIN_INTERVAL

        try:
            r = requests.get(CHEBURCHECK_URL, params={"target": ip}, timeout=CHEBURCHECK_TIMEOUT)
            if r.status_code == 429:
                last_error = http_error_text("Cheburcheck", r)
                if attempt < CHEBURCHECK_RETRIES:
                    retry_after = r.headers.get("Retry-After")
                    try:
                        delay = min(float(retry_after), 15.0) if retry_after else min(2 ** (attempt + 1), 8) + random.uniform(0.2, 0.8)
                    except ValueError:
                        delay = min(2 ** (attempt + 1), 8) + random.uniform(0.2, 0.8)
                    with _chebur_lock:
                        _chebur_next_allowed = max(_chebur_next_allowed, time.monotonic() + delay)
                    time.sleep(delay)
                    continue
                return False, last_error

            if r.status_code in {500, 502, 503, 504} and attempt < CHEBURCHECK_RETRIES:
                retry_after = r.headers.get("Retry-After")
                try:
                    delay = min(float(retry_after), 10.0) if retry_after else min(2 ** attempt, 4)
                except ValueError:
                    delay = min(2 ** attempt, 4)
                with _chebur_lock:
                    _chebur_next_allowed = max(_chebur_next_allowed, time.monotonic() + delay)
                time.sleep(delay)
                continue

            if not r.ok:
                result = (False, http_error_text("Cheburcheck", r))
                with _chebur_cache_lock:
                    _chebur_cache[ip] = result
                return result

            try:
                data = r.json()
            except ValueError:
                result = (False, "Cheburcheck: некорректный JSON")
                with _chebur_cache_lock:
                    _chebur_cache[ip] = result
                return result

            blocked = bool(data.get("blocked", False))
            subnets = data.get("blocked_subnets") or []
            result = ((not blocked and not subnets), "blocked" if blocked or subnets else "not_blocked")
            with _chebur_cache_lock:
                _chebur_cache[ip] = result
            return result
        except requests.RequestException as e:
            last_error = exception_text("Cheburcheck", e)
            if attempt < CHEBURCHECK_RETRIES:
                delay = min(2 ** attempt, 4) + random.uniform(0.1, 0.4)
                time.sleep(delay)
                continue
            result = (False, last_error)
            with _chebur_cache_lock:
                _chebur_cache[ip] = result
            return result
    return False, last_error or "Cheburcheck: неизвестная ошибка"


def gate_chebur(proxy: ProxyConfig) -> tuple[bool, str]:
    ips = host_ips(proxy.host)
    if not ips:
        return False, "не удалось определить IP"
    reasons = []
    for ip in ips:
        ok, reason = cheburcheck_ip(ip)
        if ok:
            return True, f"IP {ip} доступен в РФ"
        reasons.append(f"{ip}: {reason}")
    return False, "Cheburcheck: " + "; ".join(reasons[:3])


def gate_all(configs: list[ProxyConfig]) -> tuple[list[ProxyConfig], dict[str, int]]:
    passed_by_index: dict[int, ProxyConfig] = {}
    stats = {
        "passed": 0, "failed": 0, "blocked": 0,
        "http_errors": 0, "http_429": 0, "http_5xx": 0, "http_other": 0,
        "timeouts": 0, "connection_errors": 0,
        "dns_errors": 0, "other_errors": 0,
    }
    workers = max(1, CHEBURCHECK_WORKERS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(gate_chebur, p): i for i, p in enumerate(configs)}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            index = futures[future]
            proxy = configs[index]
            try:
                ok, reason = future.result()
            except Exception as e:
                ok, reason = False, exception_text("Cheburcheck", e)
            print(f"[gate {i}/{len(configs)}] {'PASS' if ok else 'FAIL':4} {proxy.name or proxy.host:30} {reason}")
            if ok:
                passed_by_index[index] = proxy
                stats["passed"] += 1
            else:
                stats["failed"] += 1
                low = reason.lower()
                if "blocked" in low:
                    stats["blocked"] += 1
                elif "http " in low:
                    stats["http_errors"] += 1
                    if "http 429" in low:
                        stats["http_429"] += 1
                    elif any(f"http {code}" in low for code in (500, 502, 503, 504)):
                        stats["http_5xx"] += 1
                    else:
                        stats["http_other"] += 1
                elif "timeout" in low:
                    stats["timeouts"] += 1
                elif "ошибка соединения" in low or "connection" in low:
                    stats["connection_errors"] += 1
                elif "ip" in low and "определ" in low:
                    stats["dns_errors"] += 1
                else:
                    stats["other_errors"] += 1
    passed = [passed_by_index[i] for i in range(len(configs)) if i in passed_by_index]
    return passed, stats


#---------
# XRAY
#----------

def find_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def add_stream_settings(params: dict[str, str], scheme: str) -> dict:
    transport = "hysteria" if scheme == "hysteria2" else ProxyConfig(scheme, "", 1, params=params).transport()
    security = params.get("security", "none").lower()
    if security in {"tls", "reality"}:
        security = "tls" if security == "tls" else "reality"
    elif params.get("tls", "").lower() in {"tls", "1", "true"}:
        security = "tls"
    stream = {"network": transport, "security": security}
    sni = params.get("sni") or params.get("servername") or params.get("serverName")
    fp = params.get("fp", "")
    if security == "tls":
        stream["tlsSettings"] = {"serverName": sni or "", "allowInsecure": params.get("insecure", "0").lower() in {"1", "true", "yes"}}
        if fp:
            stream["tlsSettings"]["fingerprint"] = fp
        alpn = params.get("alpn", "")
        if alpn:
            stream["tlsSettings"]["alpn"] = [x for x in alpn.split(",") if x]
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": sni or "",
            "fingerprint": fp or "chrome",
            "publicKey": params.get("pbk", ""),
            "shortId": params.get("sid", ""),
        }
    if transport == "websocket":
        stream["wsSettings"] = {
            "path": params.get("path", "/") or "/",
            "headers": {"Host": params.get("host", "") or sni or ""},
        }
    elif transport == "grpc":
        stream["grpcSettings"] = {"serviceName": params.get("serviceName", params.get("path", "")).lstrip("/")}
    elif transport == "xhttp":
        stream["xhttpSettings"] = {"path": params.get("path", "/") or "/"}
    elif transport == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": params.get("path", "/") or "/", "host": params.get("host", "") or sni or ""}
    return stream


def build_xray_config(proxy: ProxyConfig, local_port: int) -> dict:
    inbound = {
        "listen": "127.0.0.1",
        "port": local_port,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": False},
    }
    if proxy.scheme == "vless":
        user = {"id": proxy.user, "encryption": proxy.params.get("encryption", "none")}
        if proxy.params.get("flow"):
            user["flow"] = proxy.params["flow"]
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": proxy.host, "port": proxy.port, "users": [user]}]},
            "streamSettings": add_stream_settings(proxy.params, proxy.scheme),
        }
    elif proxy.scheme == "vmess":
        user = {"id": proxy.user, "alterId": int(proxy.extra.get("aid", 0) or 0), "security": proxy.extra.get("scy", "auto") or "auto"}
        outbound = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": proxy.host, "port": proxy.port, "users": [user]}]},
            "streamSettings": add_stream_settings(proxy.params, proxy.scheme),
        }
    elif proxy.scheme == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": proxy.host, "port": proxy.port, "password": proxy.password}]},
            "streamSettings": add_stream_settings(proxy.params, proxy.scheme),
        }
    elif proxy.scheme == "hysteria2":
        hparams = proxy.params
        stream = {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": {
                "serverName": hparams.get("sni", hparams.get("peer", proxy.host)),
                "allowInsecure": hparams.get("insecure", "0").lower() in {"1", "true", "yes"},
            },
            "hysteriaSettings": {
                "version": 2,
                "auth": proxy.password,
            },
        }
        obfs_type = hparams.get("obfs", "").lower()
        obfs_password = hparams.get("obfs-password", "")
        if obfs_type == "salamander" and obfs_password:
            stream["finalmask"] = {"type": "salamander", "settings": {"password": obfs_password}}
        outbound = {
            "protocol": "hysteria",
            "settings": {"version": 2, "address": proxy.host, "port": proxy.port},
            "streamSettings": stream,
        }
    else:
        raise ValueError(f"неподдерживаемый протокол: {proxy.scheme}")
    return {"log": {"loglevel": "none"}, "inbounds": [inbound], "outbounds": [outbound]}


#---------
# ПРОВЕРКА ЧЕРЕЗ VPN
#----------

@dataclass
class CheckResult:
    proxy: ProxyConfig
    ok: bool
    error: str = ""
    exit_ip: str = ""
    exit_iso: str = ""
    exit_country: str = ""
    check_reason: str = ""


def socks_proxies(port: int) -> dict[str, str]:
    return {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }


def check_generate_204(proxies: dict[str, str]) -> tuple[bool, str]:
    errors: list[str] = []

    for url in GENERATE_204_URLS:
        for attempt in range(SITE_RETRIES + 1):
            try:
                r = requests.get(
                    url,
                    proxies=proxies,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=False,
                    headers={"Connection": "close", "User-Agent": "KnetaProxy/1.0"},
                )
                if r.status_code == 204:
                    return True, "generate_204 OK"

                error = http_error_text("generate_204", r)
                if r.status_code in HTTP_TRANSIENT and attempt < SITE_RETRIES:
                    retry_after = r.headers.get("Retry-After", "")
                    try:
                        delay = max(0.0, float(retry_after)) if retry_after else SITE_RETRY_BACKOFF * (2 ** attempt)
                    except ValueError:
                        delay = SITE_RETRY_BACKOFF * (2 ** attempt)
                    time.sleep(min(delay, 5.0))
                    continue

                errors.append(f"{url}: {error}")
                break
            except requests.RequestException as e:
                error = exception_text("generate_204", e)
                if attempt < SITE_RETRIES:
                    time.sleep(SITE_RETRY_BACKOFF * (2 ** attempt))
                    continue
                errors.append(f"{url}: {error}")
                break

    if errors:
        return False, "generate_204: " + " | ".join(errors[:3])
    return False, "generate_204: нет доступных тестовых URL"


def socks5_connect(local_port: int, host: str, port: int) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", local_port), timeout=REQUEST_TIMEOUT)
    sock.settimeout(REQUEST_TIMEOUT)
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        sock.close()
        raise OSError("SOCKS5 handshake failed")
    try:
        ip = ipaddress.ip_address(host)
        atyp = b"\x01" if ip.version == 4 else b"\x04"
        addr = ip.packed
    except ValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            sock.close()
            raise OSError("hostname too long")
        atyp = b"\x03"
        addr = bytes([len(encoded)]) + encoded
    request = b"\x05\x01\x00" + atyp + addr + port.to_bytes(2, "big")
    sock.sendall(request)
    head = sock.recv(4)
    if len(head) != 4 or head[1] != 0:
        sock.close()
        raise OSError(f"SOCKS5 connect failed: {head[1] if len(head) > 1 else 'unknown'}")
    atyp = head[3]
    if atyp == 1:
        need = 4
    elif atyp == 4:
        need = 16
    elif atyp == 3:
        size = sock.recv(1)
        if not size:
            sock.close()
            raise OSError("SOCKS5 invalid response")
        need = size[0]
    else:
        sock.close()
        raise OSError("SOCKS5 invalid address type")
    remaining = need + 2
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            sock.close()
            raise OSError("SOCKS5 truncated response")
        remaining -= len(chunk)
    return sock


def check_tcp(local_port: int) -> tuple[bool, str]:
    for target in TCP_TARGETS:
        if target.startswith("[") and "]" in target:
            host, _, port_text = target[1:].partition("]:")
        else:
            host, _, port_text = target.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            return False, f"tcp: неверная цель {target}"
        try:
            sock = socks5_connect(local_port, host, port)
            sock.close()
        except Exception as e:
            return False, f"tcp: {str(e)[:100]}"
    return True, "tcp OK"


def get_exit_ip(proxies: dict[str, str]) -> tuple[str, str]:
    last_error = ""
    for attempt in range(EXIT_IP_RETRIES + 1):
        try:
            r = requests.get(EXIT_IP_API_URL, proxies=proxies, timeout=EXIT_IP_TIMEOUT)
            if r.status_code in HTTP_TRANSIENT and attempt < EXIT_IP_RETRIES:
                time.sleep(SITE_RETRY_BACKOFF * (2 ** attempt))
                continue
            if not r.ok:
                return "", http_error_text("exit-ip API", r)
            try:
                data = r.json()
            except ValueError:
                return "", "exit-ip API: некорректный JSON"
            ip = str(data.get("ip", "")).strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return "", "exit-ip API: вернул некорректный IP"
            return ip, ""
        except requests.RequestException as e:
            last_error = exception_text("exit-ip API", e)
            if attempt < EXIT_IP_RETRIES:
                time.sleep(SITE_RETRY_BACKOFF * (2 ** attempt))
    return "", last_error or "exit-ip API: неизвестная ошибка"


def lookup_country_direct(ip: str) -> tuple[str, str]:
    global _country_last_call
    with _country_lock:
        cached = _country_cache.get(ip)
        if cached:
            return cached
    last_error = ""
    for attempt in range(COUNTRY_RETRIES + 1):
        with _country_lock:
            wait = COUNTRY_MIN_INTERVAL - (time.monotonic() - _country_last_call)
            if wait > 0:
                time.sleep(wait)
            _country_last_call = time.monotonic()
        try:
            r = requests.get(f"{COUNTRY_API_URL}/{ip}", timeout=COUNTRY_TIMEOUT)
            if r.status_code in HTTP_TRANSIENT and attempt < COUNTRY_RETRIES:
                retry_after = r.headers.get("Retry-After")
                try:
                    delay = min(float(retry_after), 10.0) if retry_after else SITE_RETRY_BACKOFF * (2 ** attempt)
                except ValueError:
                    delay = SITE_RETRY_BACKOFF * (2 ** attempt)
                time.sleep(delay)
                continue
            if not r.ok:
                last_error = http_error_text("country API", r)
                continue
            try:
                data = r.json()
            except ValueError:
                last_error = "country API: некорректный JSON"
                continue
            iso = str(data.get("country", "")).strip().upper()
            if not iso:
                last_error = "country API: страна не указана"
                continue
            result = (iso, country_name(iso))
            with _country_lock:
                _country_cache[ip] = result
            return result
        except requests.RequestException as e:
            last_error = exception_text("country API", e)
            if attempt < COUNTRY_RETRIES:
                time.sleep(SITE_RETRY_BACKOFF * (2 ** attempt))
    return "", last_error or "country API: неизвестная ошибка"


def check_single_proxy(proxy: ProxyConfig, mode: str) -> CheckResult:
    local_port = find_free_port()
    cfg_path = ""
    proc = None
    try:
        config = build_xray_config(proxy, local_port)
        os.makedirs(TMP_DIR, exist_ok=True)
        fd, cfg_path = tempfile.mkstemp(prefix="cfg_", suffix=".json", dir=TMP_DIR)
        os.close(fd)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)
        proc = subprocess.Popen([XRAY_BIN, "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(XRAY_STARTUP_DELAY)
        if proc.poll() is not None:
            return CheckResult(proxy, False, "xray не запустился", check_reason="xray")
        proxies = socks_proxies(local_port)
        if mode == "generate_204":
            ok, reason = check_generate_204(proxies)
            if not ok:
                return CheckResult(proxy, False, reason, check_reason="alive")
        elif mode == "tcp":
            ok, reason = check_tcp(local_port)
            if not ok:
                return CheckResult(proxy, False, reason, check_reason="alive")
        exit_ip, exit_error = get_exit_ip(proxies)
        if not exit_ip:
            return CheckResult(proxy, False, exit_error, check_reason="exit_ip")
        exit_iso, exit_country = lookup_country_direct(exit_ip)
        if not exit_iso:
            return CheckResult(proxy, False, exit_country or "country API: не удалось определить страну", exit_ip=exit_ip, check_reason="country")
        return CheckResult(proxy, True, exit_ip=exit_ip, exit_iso=exit_iso, exit_country=exit_country, check_reason="ok")
    except Exception as e:
        return CheckResult(proxy, False, f"{type(e).__name__}: {str(e)[:110]}", check_reason="other")
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        if cfg_path:
            try:
                os.remove(cfg_path)
            except OSError:
                pass


def check_all(configs: list[ProxyConfig], mode: str) -> tuple[list[CheckResult], dict[str, int], dict[str, int]]:
    results_by_index: dict[int, CheckResult] = {}
    stats = {
        "ok": 0, "xray_fail": 0, "alive_fail": 0, "exit_ip_fail": 0,
        "country_fail": 0, "other_fail": 0,
        "generate_204_fail": 0, "tcp_fail": 0,
    }
    protocol_stats: dict[str, int] = {scheme: 0 for scheme in ("vless", "vmess", "trojan", "hysteria2")}
    workers = max(1, MAX_WORKERS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check_single_proxy, p, mode): i for i, p in enumerate(configs)}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            index = futures[future]
            try:
                result = future.result()
            except Exception as e:
                result = CheckResult(configs[index], False, f"worker: {type(e).__name__}: {str(e)[:100]}", check_reason="other")
            results_by_index[index] = result
            if result.ok:
                stats["ok"] += 1
                protocol_stats[result.proxy.scheme] = protocol_stats.get(result.proxy.scheme, 0) + 1
                info = f"exit={result.exit_ip} | {result.exit_iso}"
                status = "OK"
            else:
                key = result.check_reason
                if key == "xray":
                    stats["xray_fail"] += 1
                elif key == "alive":
                    stats["alive_fail"] += 1
                    if result.error.startswith("generate_204:"):
                        stats["generate_204_fail"] += 1
                    elif result.error.startswith("tcp:"):
                        stats["tcp_fail"] += 1
                elif key == "exit_ip":
                    stats["exit_ip_fail"] += 1
                elif key == "country":
                    stats["country_fail"] += 1
                else:
                    stats["other_fail"] += 1
                info = result.error
                status = "FAIL"
            print(f"[{i}/{len(configs)}] {status:4} {result.proxy.name or result.proxy.host:30} {info}")
    results = [results_by_index[i] for i in range(len(configs))]
    return results, stats, protocol_stats


#---------
# ИСТОРИЯ
#----------

def load_history() -> dict:
    if not os.path.exists(HISTORY_FILE):
        return {"version": 2, "entries": {}}
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("version") != 2 or not isinstance(data.get("entries"), dict):
            return {"version": 2, "entries": {}}
        return data
    except Exception:
        return {"version": 2, "entries": {}}


def save_history(history: dict) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    tmp = HISTORY_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, HISTORY_FILE)


def update_history(history: dict, results: list[CheckResult]) -> None:
    entries = history.setdefault("entries", {})
    for result in results:
        key = json.dumps(result.proxy.identity(), ensure_ascii=False, sort_keys=True)
        item = entries.get(key, {"streak": 0})
        item["streak"] = item.get("streak", 0) + 1 if result.ok else 0
        item["last_ok"] = result.ok
        item["exit_ip"] = result.exit_ip
        item["exit_iso"] = result.exit_iso
        entries[key] = item


#---------
# ВЫВОД
#----------

def named_link(result: CheckResult) -> str:
    name = f"{country_flag(result.exit_iso)} {country_name(result.exit_iso)} | {NAME_SUFFIX}"
    return result.proxy.to_link(name=name)


def write_subscription(path: str, results: list[CheckResult], title: str) -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    lines = [
        f"#profile-title: {title}",
        f"#profile-update-interval: {INFO['update_interval']}",
        f"#support-url: {INFO['support_url']}",
        f"#announce: {INFO['announce']}",
        "#subscription-userinfo: upload=0; download=0; total=0; expire=0",
    ]
    lines.extend(named_link(x) for x in results)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def save_results(
    results: list[CheckResult],
    collect_stats: dict[str, int],
    source_errors: list[str],
    gate_stats: dict[str, int],
    check_stats: dict[str, int],
    protocol_stats: dict[str, int],
    mode: str,
) -> None:
    good = [x for x in results if x.ok]
    if mode == "no":
        random.shuffle(good)
    main = good[:MAX_PROXIES]
    all_working = good
    write_subscription(OUTPUT_FILE, main, INFO["title_main"])
    write_subscription(ALL_FILE, all_working, INFO["title_all"])

    subscription_protocol_stats: dict[str, int] = {scheme: 0 for scheme in SUPPORTED_SCHEMES if scheme != "hy2"}
    for item in main:
        subscription_protocol_stats[item.proxy.scheme] = subscription_protocol_stats.get(item.proxy.scheme, 0) + 1

    country_counts: dict[str, int] = {}
    for item in main:
        country_counts[item.exit_iso] = country_counts.get(item.exit_iso, 0) + 1

    lines = [
        "=== СТАТИСТИКА ПРОВЕРКИ ===",
        f"Источников подписок: {collect_stats['sources']} (OK: {collect_stats['sources_ok']}, FAIL: {collect_stats['sources_failed']})",
        f"Получено ссылок: {collect_stats['received']}",
        f"  VLESS: {collect_stats['received_vless']}",
        f"  VMess: {collect_stats['received_vmess']}",
        f"  Trojan: {collect_stats['received_trojan']}",
        f"  Hysteria2/Hy2: {collect_stats['received_hysteria2'] + collect_stats['received_hy2']}",
        f"Некорректных конфигов: {collect_stats['invalid']}",
        f"Неизвестных строк: {collect_stats['unsupported_lines']}",
        f"Дубликатов удалено: {collect_stats['duplicates']}",
        f"Уникальных конфигов: {collect_stats['unique']}",
        f"После Cheburcheck: {gate_stats['passed']}",
        f"Cheburcheck FAIL: {gate_stats['failed']} (blocked: {gate_stats['blocked']}, HTTP: {gate_stats['http_errors']}, 429: {gate_stats['http_429']}, 5xx: {gate_stats['http_5xx']}, timeout: {gate_stats['timeouts']}, connection: {gate_stats['connection_errors']}, other: {gate_stats['other_errors']})",
        f"Режим проверки: {mode}",
        f"Xray OK: {check_stats['ok']}",
        f"Xray FAIL: {check_stats['xray_fail']}",
        f"Проверка доступности FAIL: {check_stats['alive_fail']} (generate_204: {check_stats['generate_204_fail']}, tcp: {check_stats['tcp_fail']})",
        f"Ошибка EXIT IP: {check_stats['exit_ip_fail']}",
        f"Ошибка страны: {check_stats['country_fail']}",
        f"Другие FAIL: {check_stats['other_fail']}",
        "",
        "ПРОТОКОЛЫ ОСНОВНОЙ ПОДПИСКИ:",
        f"  VLESS: {subscription_protocol_stats.get('vless', 0)}",
        f"  VMess: {subscription_protocol_stats.get('vmess', 0)}",
        f"  Trojan: {subscription_protocol_stats.get('trojan', 0)}",
        f"  Hysteria2/Hy2: {subscription_protocol_stats.get('hysteria2', 0)}",
        "",
        "РАБОЧИЕ ПО СТРАНАМ:",
    ]
    if country_counts:
        for iso, count in sorted(country_counts.items(), key=lambda x: (-x[1], x[0])):
            lines.append(f"  {country_flag(iso)} {country_name(iso)} ({iso}): {count}")
    else:
        lines.append("  —")
    lines += [
        "",
        f"ИТОГО рабочих: {len(good)}",
        f"Основная подписка: {len(main)} / {MAX_PROXIES}",
        f"Полная подписка: {len(all_working)}",
    ]
    if source_errors:
        lines += ["", "ОШИБКИ ОБРАЩЕНИЯ К САЙТАМ/ИСТОЧНИКАМ:"]
        lines.extend(f"  - {error}" for error in source_errors[:30])
        if len(source_errors) > 30:
            lines.append(f"  ... ещё {len(source_errors) - 30}")
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print()
    for line in lines:
        print(f"[+] {line}" if line else "")



#---------
# MAIN
#----------

def main() -> None:
    config = load_check_config()
    print(f"[+] Режим проверки: {config.mode}")
    configs, collect_stats, source_errors = collect_configs()
    print(f"[+] Найдено: {len(configs)} уникальных конфигов")
    if not configs:
        save_results([], collect_stats, source_errors, {"passed": 0, "failed": 0}, {"ok": 0, "xray_fail": 0, "alive_fail": 0, "exit_ip_fail": 0, "country_fail": 0, "other_fail": 0}, {"vless": 0, "vmess": 0, "trojan": 0, "hysteria2": 0}, config.mode)
        return
    gated, gate_stats = gate_all(configs)
    if not gated:
        save_results([], collect_stats, source_errors, gate_stats, {"ok": 0, "xray_fail": 0, "alive_fail": 0, "exit_ip_fail": 0, "country_fail": 0, "other_fail": 0}, {"vless": 0, "vmess": 0, "trojan": 0, "hysteria2": 0}, config.mode)
        return
    results, check_stats, protocol_stats = check_all(gated, config.mode)
    history = load_history()
    update_history(history, results)
    save_history(history)
    save_results(results, collect_stats, source_errors, gate_stats, check_stats, protocol_stats, config.mode)


if __name__ == "__main__":
    main()
