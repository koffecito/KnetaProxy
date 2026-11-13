#!/usr/bin/env python3

import base64
import hashlib
import hmac
import ipaddress
import itertools
import json
import os
import queue
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Iterator
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

import requests


#---------
# КОНФИГУРАЦИЯ
#---------

def env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


def env_float(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


SUBSCRIPTIONS_ENV = "SUBSCRIPTIONS"
CACHE_SALT_ENV = "CACHE_SALT"
TYPE_FILE = os.environ.get("TYPE_FILE", "other/type.txt")
INFO_FILE = os.environ.get("INFO_FILE", "other/info.txt")
VALID_MODES = ("generate_204", "tcp", "no")

CHEBURCHECK_URL = os.environ.get("CHEBURCHECK_URL", "https://cheburcheck.ru/api/v1/check")
CHEBURCHECK_TIMEOUT = env_float("CHEBURCHECK_TIMEOUT", 5)
CHEBURCHECK_WORKERS = env_int("CHEBURCHECK_WORKERS", 4)
CHEBURCHECK_RETRIES = env_int("CHEBURCHECK_RETRIES", 1)
CHEBURCHECK_MIN_INTERVAL = env_float("CHEBURCHECK_MIN_INTERVAL", 4.0)
CHEBURCHECK_MAX_INTERVAL = env_float("CHEBURCHECK_MAX_INTERVAL", 12)
CHEBURCHECK_CACHE_HOURS = env_float("CHEBURCHECK_CACHE_HOURS", 48)
CHEBURCHECK_BLOCKED_CACHE_HOURS = env_float("CHEBURCHECK_BLOCKED_CACHE_HOURS", 168)
CHEBURCHECK_RECHECK_DELAY = env_float("CHEBURCHECK_RECHECK_DELAY", 10)

XRAY_BIN = os.environ.get("XRAY_BIN", "xray")
XRAY_READY_TIMEOUT = env_float("XRAY_READY_TIMEOUT", 5)
REQUEST_TIMEOUT = env_float("REQUEST_TIMEOUT", 5)
TCP_PRECHECK_TIMEOUT = env_float("TCP_PRECHECK_TIMEOUT", 3)
TCP_PRECHECK_MAX_IPS = env_int("TCP_PRECHECK_MAX_IPS", 2)
GENERATE_204_STOP_ON_TIMEOUT = env_int("GENERATE_204_STOP_ON_TIMEOUT", 1)

EXIT_IP_API_URLS = tuple(
    x.strip()
    for x in os.environ.get(
        "EXIT_IP_API_URLS",
        os.environ.get("EXIT_IP_API_URL", "https://api.ipify.org?format=json,https://icanhazip.com,https://api.country.is"),
    ).split(",")
    if x.strip()
)
EXIT_IP_TIMEOUT = env_float("EXIT_IP_TIMEOUT", 4)
EXIT_IP_RETRIES = env_int("EXIT_IP_RETRIES", 0)

COUNTRY_API_URL = os.environ.get("COUNTRY_API_URL", "https://api.country.is")
COUNTRY_TIMEOUT = env_float("COUNTRY_TIMEOUT", 5)
COUNTRY_RETRIES = env_int("COUNTRY_RETRIES", 2)
COUNTRY_MIN_INTERVAL = env_float("COUNTRY_MIN_INTERVAL", 0.2)
COUNTRY_MAX_INTERVAL = env_float("COUNTRY_MAX_INTERVAL", 5)
COUNTRY_CACHE_DAYS = env_float("COUNTRY_CACHE_DAYS", 14)

MAX_WORKERS = env_int("MAX_WORKERS", 32)
MAX_PROXIES = env_int("MAX_PROXIES", 100)
HISTORY_KEEP_RUNS = env_int("HISTORY_KEEP_RUNS", 30)
MAX_RUNTIME_MINUTES = env_float("MAX_RUNTIME_MINUTES", 90)
START_TIME = time.monotonic()

SITE_RETRIES = env_int("SITE_RETRIES", 2)
SITE_RETRY_BACKOFF = env_float("SITE_RETRY_BACKOFF", 0.8)
HTTP_TRANSIENT = {429, 500, 502, 503, 504}

GENERATE_204_URLS = tuple(
    x.strip()
    for x in os.environ.get(
        "GENERATE_204_URLS",
        "https://www.gstatic.com/generate_204,https://cp.cloudflare.com/generate_204",
    ).split(",")
    if x.strip()
)


def parse_tcp_target(target: str) -> tuple[str, int] | None:
    host, _, port_text = target.strip().rpartition(":")
    host = host.strip("[]")
    try:
        port = int(port_text)
    except ValueError:
        return None
    return (host, port) if host and 0 < port < 65536 else None


TCP_TARGETS: list[tuple[str, int]] = []
for _target in os.environ.get("TCP_TARGETS", "1.1.1.1:443").split(","):
    if not _target.strip():
        continue
    _parsed = parse_tcp_target(_target)
    if _parsed is None:
        print(f"[!] TCP_TARGETS: пропущена неверная цель '{_target.strip()}'", file=sys.stderr)
    else:
        TCP_TARGETS.append(_parsed)

SUPPORTED_SCHEMES = ("vless", "vmess", "trojan", "hysteria2", "hy2")
OUTPUT_DIR = "sub"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "working.txt")
ALL_FILE = os.path.join(OUTPUT_DIR, "all.txt")
REPORT_FILE = os.path.join(OUTPUT_DIR, "report.txt")
HISTORY_FILE = os.path.join(OUTPUT_DIR, "history.json")
STATS_FILE = os.path.join(OUTPUT_DIR, "stats.json")


def load_info_file(path: str = INFO_FILE) -> dict[str, str]:
    values = {
        "title_main": "Kneta • Основная Подписка",
        "title_all": "Kneta • Полная Подписка",
        "update_interval": "4",
        "support_url": "https://t.me/KnetaProject",
        "announce": "тг: @KnetaProject | BlackList",
        "name_suffix": os.environ.get("NAME_SUFFIX", "[KP]"),
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

_log_lock = threading.Lock()


def log(message: str) -> None:
    with _log_lock:
        print(message, flush=True)


def write_text_atomic(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


#---------
# СТРАНЫ
#---------

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
    "BY": "Беларусь", "IR": "Иран", "IQ": "Ирак",
    "TJ": "Таджикистан", "TM": "Туркменистан", "MN": "Монголия",
    "PK": "Пакистан", "BD": "Бангладеш", "LK": "Шри-Ланка",
    "NP": "Непал", "AF": "Афганистан", "SY": "Сирия",
    "JO": "Иордания", "LB": "Ливан", "QA": "Катар",
    "KW": "Кувейт", "BH": "Бахрейн", "OM": "Оман",
    "YE": "Йемен", "MA": "Марокко", "DZ": "Алжир",
    "TN": "Тунис", "LY": "Ливия", "NG": "Нигерия",
    "KE": "Кения", "ET": "Эфиопия", "GH": "Гана",
    "CO": "Колумбия", "PE": "Перу", "VE": "Венесуэла",
    "EC": "Эквадор", "UY": "Уругвай", "PA": "Панама",
    "CR": "Коста-Рика", "DO": "Доминиканская Республика", "CU": "Куба",
    "KH": "Камбоджа", "LA": "Лаос", "MM": "Мьянма",
    "MO": "Макао", "LI": "Лихтенштейн", "MC": "Монако",
    "AD": "Андорра", "XK": "Косово",
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
# РЕЖИМ ПРОВЕРКИ
#---------

def load_mode(path: str = TYPE_FILE) -> str:
    if not os.path.exists(path):
        return "generate_204"
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read().strip().lower()
    if raw in VALID_MODES:
        return raw
    if raw:
        print(f"[!] {path}: неизвестный режим '{raw}', использую generate_204", file=sys.stderr)
    return "generate_204"


#---------
# HTTP
#---------

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
    return f"{service}: {type(exc).__name__}"


def parse_retry_after(response: requests.Response | None) -> float | None:
    value = response.headers.get("Retry-After") if response is not None else None
    if not value:
        return None
    try:
        return max(float(value), 0.0)
    except ValueError:
        return None


def retry_delay(response: requests.Response | None, attempt: int, max_delay: float) -> float:
    retry_after = parse_retry_after(response)
    if retry_after is not None:
        return min(retry_after, max_delay)
    return min(SITE_RETRY_BACKOFF * (2 ** attempt) + random.uniform(0, 0.3), max_delay)


def get_with_retry(
    url: str,
    *,
    timeout: float,
    retries: int = 0,
    retry_network: bool = False,
    max_delay: float = 10.0,
    before: Callable[[], None] | None = None,
    on_response: Callable[[requests.Response], None] | None = None,
    **kwargs,
) -> requests.Response:
    for attempt in range(retries + 1):
        is_last = attempt == retries
        if before:
            before()
        try:
            response = requests.get(url, timeout=timeout, **kwargs)
        except requests.RequestException:
            if is_last or not retry_network:
                raise
            delay = retry_delay(None, attempt, max_delay)
        else:
            if on_response:
                on_response(response)
            if response.status_code not in HTTP_TRANSIENT or is_last:
                return response
            delay = retry_delay(response, attempt, max_delay)
        time.sleep(delay)
    raise RuntimeError("unreachable")


class RateLimiter:

    SUCCESSES_TO_RELAX = 20

    GROWTH = 1.5

    RELAX = 0.9

    JITTER = 0.3

    def __init__(self, interval: float, max_interval: float | None = None, name: str = "rate") -> None:
        self.name = name
        self.base = interval
        self.interval = interval
        self.max_interval = max(interval, max_interval or interval)
        self.calls = 0
        self.throttled = 0
        self._next = 0.0
        self._blocked_until = 0.0
        self._last_adjust = 0.0
        self._ok_streak = 0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            self.calls += 1
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self.interval * random.uniform(1.0, 1.0 + self.JITTER)
        while True:
            with self._lock:
                start = max(start, self._blocked_until)
            now = time.monotonic()
            if start <= now:
                return
            time.sleep(start - now)

    def throttle(self, retry_after: float | None = None) -> None:
        with self._lock:
            before = self.interval
            now = time.monotonic()
            self.throttled += 1
            self._ok_streak = 0
            if now - self._last_adjust >= self.interval:
                self.interval = min(self.max_interval, max(self.interval * self.GROWTH, self.base))
                self._last_adjust = now
            pause = min(max(retry_after or 0.0, self.interval), 60.0)
            self._blocked_until = max(self._blocked_until, now + pause)
            self._next = max(self._next, self._blocked_until)
            after = self.interval
        if after != before:
            ra = f", Retry-After {retry_after:g} с" if retry_after else ""
            log(f"[{self.name}] 429: интервал {before:.1f} -> {after:.1f} с, пауза {pause:.1f} с{ra}")

    def success(self) -> None:
        with self._lock:
            self._ok_streak += 1
            if self._ok_streak >= self.SUCCESSES_TO_RELAX and self.interval > self.base:
                self.interval = max(self.base, self.interval * self.RELAX)
                self._ok_streak = 0

    def feedback(self, response: requests.Response) -> None:
        if response.status_code == 429:
            self.throttle(parse_retry_after(response))
        elif response.ok:
            self.success()


class TtlCache:

    def __init__(self, entries: dict, ttl_seconds: float) -> None:
        self.entries = entries
        self.ttl = ttl_seconds

    @staticmethod
    def key(ip: str) -> str:
        secret = (os.environ.get(CACHE_SALT_ENV) or os.environ.get(SUBSCRIPTIONS_ENV, "")).encode("utf-8")
        return hmac.new(secret, ip.encode("utf-8"), hashlib.sha256).hexdigest()[:20]

    def get(self, ip: str) -> dict | None:
        if self.ttl <= 0:
            return None
        item = self.entries.get(self.key(ip))
        if isinstance(item, dict) and item.get("exp", 0) > time.time():
            return item
        return None

    def put(self, ip: str, ttl_seconds: float | None = None, **fields) -> None:
        if self.ttl > 0:
            ttl = self.ttl if ttl_seconds is None else ttl_seconds
            self.entries[self.key(ip)] = {**fields, "exp": int(time.time() + ttl * random.uniform(0.25, 1.0))}

    def prune(self) -> None:
        now = time.time()
        for key in [k for k, v in self.entries.items() if not isinstance(v, dict) or v.get("exp", 0) <= now]:
            del self.entries[key]


#---------
# МОДЕЛЬ КОНФИГА
#---------

def transport_of(params: dict[str, str]) -> str:
    value = params.get("type", params.get("net", "tcp")).lower()
    return {
        "tcp": "raw",
        "raw": "raw",
        "ws": "websocket",
        "websocket": "websocket",
        "kcp": "mkcp",
        "mkcp": "mkcp",
    }.get(value, value)


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
        extra = {k: v for k, v in self.extra.items() if k != "ps"}
        return (
            self.scheme,
            self.host.lower(),
            self.port,
            self.user,
            self.password,
            tuple(sorted(self.params.items())),
            json.dumps(extra, sort_keys=True, ensure_ascii=False),
        )

    def key(self) -> str:
        return config_key(json.dumps(self.identity(), ensure_ascii=False, sort_keys=True))

    def to_link(self, name: str | None = None) -> str:
        title = name if name is not None else self.name
        if self.scheme == "vmess":
            data = dict(self.extra)
            data["ps"] = title
            raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
            return "vmess://" + base64.b64encode(raw).decode()
        if self.scheme not in {"vless", "trojan", "hysteria2"}:
            return ""
        secret = self.user if self.scheme == "vless" else self.password
        host = f"[{self.host}]" if ":" in self.host else self.host
        link = f"{self.scheme}://{quote(secret, safe=':' if self.scheme == 'hysteria2' else '')}@{host}:{self.port}"
        query = urlencode(self.params)
        if query:
            link += "?" + query
        return link + ("#" + quote(title, safe="") if title else "")


def config_key(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


#---------
# ПАРСИНГ
#---------

def parse_query(query: str) -> dict[str, str]:
    return {k: v[0] if v else "" for k, v in parse_qs(query, keep_blank_values=True).items()}


def parse_uri_link(link: str) -> ProxyConfig | None:
    try:
        u = urlparse(link)
        scheme = u.scheme.lower()
        if scheme == "hy2":
            scheme = "hysteria2"
        if scheme not in {"vless", "trojan", "hysteria2"} or not u.hostname or not u.port:
            return None
        secret = unquote(u.username or "")
        if scheme == "hysteria2" and u.password:
            secret += ":" + unquote(u.password)
        if not secret and scheme != "hysteria2":
            return None
        fields = {"user": secret} if scheme == "vless" else {"password": secret}
        return ProxyConfig(scheme, u.hostname, u.port, name=unquote(u.fragment), params=parse_query(u.query), **fields)
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
    scheme = link.split(":", 1)[0].lower()
    if scheme == "vmess":
        return parse_vmess(link)
    return parse_uri_link(link)


def supported_link(line: str) -> bool:
    return line.lower().startswith(tuple(f"{s}://" for s in SUPPORTED_SCHEMES))


#---------
# ПОДПИСКИ
#---------

def iter_source_lines(raw: str) -> Iterator[str]:
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def decode_subscription_text(raw: str) -> list[str]:
    text = raw.strip()
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    direct = [x for x in lines if supported_link(x)]
    if direct:
        return direct
    try:
        compact = "".join(text.split()).replace("-", "+").replace("_", "/")
        decoded = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", errors="ignore")
    except Exception:
        decoded = text
    return [x.strip() for x in decoded.splitlines() if supported_link(x.strip())]


def fetch_subscription(url: str) -> tuple[list[str], str]:
    try:
        r = get_with_retry(
            url,
            timeout=15,
            retries=SITE_RETRIES,
            retry_network=True,
            headers={"User-Agent": "KnetaProxy/1.0"},
        )
    except requests.RequestException as e:
        return [], exception_text("источник", e)
    if not r.ok:
        return [], http_error_text("источник", r)
    return decode_subscription_text(r.text), ""


@dataclass
class CollectStats:
    sources: int = 0
    sources_ok: int = 0
    sources_failed: int = 0
    unsupported_lines: int = 0
    received: int = 0
    invalid: int = 0
    duplicates: int = 0
    unique: int = 0
    by_scheme: Counter = field(default_factory=Counter)


def load_subscription_sources() -> tuple[list[str], CollectStats, list[str]]:
    stats = CollectStats()
    errors: list[str] = []
    raw = os.environ.get(SUBSCRIPTIONS_ENV, "")
    items = list(iter_source_lines(raw))
    urls = list(dict.fromkeys(x for x in items if x.lower().startswith(("http://", "https://"))))

    links: list[str] = []
    with ThreadPoolExecutor(max_workers=max(1, min(8, len(urls)))) as pool:
        pending = {url: pool.submit(fetch_subscription, url) for url in urls}
        seen_urls: set[str] = set()
        for item in items:
            if item in pending:
                if item in seen_urls:
                    continue
                seen_urls.add(item)
                stats.sources += 1
                found, error = pending[item].result()
                number = stats.sources
                if error:
                    stats.sources_failed += 1
                    errors.append(f"Источник #{number}: {error}")
                    print(f"[!] Источник #{number}: {error}", file=sys.stderr)
                else:
                    stats.sources_ok += 1
                    print(f"[+] Источник #{number}: {len(found)} ссылок")
                    links.extend(found)
            elif supported_link(item):
                links.append(item)
            else:
                stats.unsupported_lines += 1
                print("[!] Неизвестная строка в SUBSCRIPTIONS пропущена", file=sys.stderr)
    return links, stats, errors


def collect_configs() -> tuple[list[ProxyConfig], CollectStats, list[str]]:
    links, stats, errors = load_subscription_sources()
    stats.received = len(links)
    result: list[ProxyConfig] = []
    seen: set[str] = set()
    for link in links:
        stats.by_scheme[link.split(":", 1)[0].lower()] += 1
        proxy = parse_link(link)
        if proxy is None:
            stats.invalid += 1
            continue
        key = proxy.key()
        if key in seen:
            stats.duplicates += 1
            continue
        seen.add(key)
        result.append(proxy)
    stats.unique = len(result)
    return result, stats, errors


#---------
# CHEBURCHECK
#---------

TRANSIENT_KINDS = {"http_429", "http_5xx", "timeout", "connection"}
_chebur_limiter = RateLimiter(CHEBURCHECK_MIN_INTERVAL, CHEBURCHECK_MAX_INTERVAL, "gate")
_country_limiter = RateLimiter(COUNTRY_MIN_INTERVAL, COUNTRY_MAX_INTERVAL, "country")
_geo_cache = TtlCache({}, 0)


@dataclass(frozen=True)
class Verdict:
    ok: bool
    kind: str
    detail: str = ""

    @property
    def transient(self) -> bool:
        return self.kind in TRANSIENT_KINDS


def host_ips(host: str) -> list[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return list(dict.fromkeys(info[4][0] for info in infos))


def resolve_hosts(hosts: set[str]) -> dict[str, list[str]]:
    ordered = sorted(hosts)
    if not ordered:
        return {}
    with ThreadPoolExecutor(max_workers=min(32, len(ordered))) as pool:
        return dict(zip(ordered, pool.map(host_ips, ordered)))


def cheburcheck_ip(ip: str) -> Verdict:
    try:
        r = get_with_retry(
            CHEBURCHECK_URL,
            params={"target": ip},
            timeout=CHEBURCHECK_TIMEOUT,
            retries=CHEBURCHECK_RETRIES,
            retry_network=True,
            max_delay=15,
            before=_chebur_limiter.wait,
            on_response=_chebur_limiter.feedback,
        )
    except requests.RequestException as e:
        if isinstance(e, requests.Timeout):
            kind = "timeout"
        elif isinstance(e, requests.ConnectionError):
            kind = "connection"
        else:
            kind = "other"
        return Verdict(False, kind, exception_text("Cheburcheck", e))
    if not r.ok:
        if r.status_code == 429:
            kind = "http_429"
        elif r.status_code in HTTP_TRANSIENT:
            kind = "http_5xx"
        else:
            kind = "http_other"
        return Verdict(False, kind, http_error_text("Cheburcheck", r))
    try:
        data = r.json()
    except ValueError:
        return Verdict(False, "bad_json", "Cheburcheck: некорректный JSON")
    if not isinstance(data, dict):
        return Verdict(False, "bad_json", "Cheburcheck: неожиданный формат ответа")
    if data.get("blocked") or data.get("blocked_subnets"):
        return Verdict(False, "blocked", "заблокирован в РФ")
    return Verdict(True, "ok", "доступен в РФ")


def time_is_up() -> bool:
    return MAX_RUNTIME_MINUTES > 0 and time.monotonic() - START_TIME > MAX_RUNTIME_MINUTES * 60


def safe_cheburcheck(ip: str) -> Verdict:
    if time_is_up():
        return Verdict(False, "deferred", "отложено: лимит времени запуска")
    try:
        return cheburcheck_ip(ip)
    except Exception as e:
        return Verdict(False, "other", f"Cheburcheck: {type(e).__name__}")


#---------
# XRAY
#---------

def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def add_stream_settings(params: dict[str, str]) -> dict:
    transport = transport_of(params)
    security = params.get("security", "none").lower()
    if security not in {"tls", "reality"} and params.get("tls", "").lower() in {"tls", "1", "true"}:
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
            "streamSettings": add_stream_settings(proxy.params),
        }
    elif proxy.scheme == "vmess":
        try:
            alter_id = int(proxy.extra.get("aid", 0) or 0)
        except (TypeError, ValueError):
            alter_id = 0
        user = {"id": proxy.user, "alterId": alter_id, "security": proxy.extra.get("scy", "auto") or "auto"}
        outbound = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": proxy.host, "port": proxy.port, "users": [user]}]},
            "streamSettings": add_stream_settings(proxy.params),
        }
    elif proxy.scheme == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": proxy.host, "port": proxy.port, "password": proxy.password}]},
            "streamSettings": add_stream_settings(proxy.params),
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


def wait_port(proc: subprocess.Popen, port: int, timeout: float = XRAY_READY_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return proc.poll() is None
        except OSError:
            time.sleep(0.05)
    return False


def stop_xray(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def launch_xray(proxy: ProxyConfig, workdir: str) -> tuple[subprocess.Popen, int] | None:
    for _ in range(3):
        port = find_free_port()
        fd, cfg_path = tempfile.mkstemp(prefix="cfg_", suffix=".json", dir=workdir)
        proc = None
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(build_xray_config(proxy, port), f, ensure_ascii=False)
            proc = subprocess.Popen([XRAY_BIN, "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if wait_port(proc, port):
                return proc, port
            stop_xray(proc)
        except BaseException:
            stop_xray(proc)
            raise
        finally:
            try:
                os.remove(cfg_path)
            except OSError:
                pass
    return None


#---------
# ПРОВЕРКА ЧЕРЕЗ XRAY
#---------

@dataclass
class CheckResult:
    proxy: ProxyConfig
    ok: bool
    error: str = ""
    exit_ip: str = ""
    exit_iso: str = ""
    stage: str = ""


def socks_proxies(port: int) -> dict[str, str]:
    url = f"socks5h://127.0.0.1:{port}"
    return {"http": url, "https": url}


def check_generate_204(proxies: dict[str, str]) -> tuple[bool, str]:
    errors = []
    for url in GENERATE_204_URLS:
        try:
            r = requests.get(
                url,
                proxies=proxies,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                headers={"Connection": "close", "User-Agent": "KnetaProxy/1.0"},
            )
        except requests.Timeout as e:
            if GENERATE_204_STOP_ON_TIMEOUT:
                return False, exception_text("generate_204", e)
            errors.append(exception_text("generate_204", e))
            continue
        except requests.RequestException as e:
            errors.append(exception_text("generate_204", e))
            continue
        if r.status_code == 204:
            return True, "generate_204 OK"
        if r.status_code == 429:
            return True, "generate_204: 429 (узел отвечает)"
        errors.append(http_error_text("generate_204", r))
    return False, errors[-1] if errors else "generate_204: нет URL для проверки"


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("SOCKS5: соединение закрыто")
        data += chunk
    return data


def socks5_probe(local_port: int, host: str, port: int) -> None:
    with socket.create_connection(("127.0.0.1", local_port), timeout=REQUEST_TIMEOUT) as sock:
        sock.settimeout(REQUEST_TIMEOUT)
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS5 handshake failed")
        try:
            ip = ipaddress.ip_address(host)
            atyp = b"\x01" if ip.version == 4 else b"\x04"
            addr = ip.packed
        except ValueError:
            encoded = host.encode("idna")
            if len(encoded) > 255:
                raise OSError("hostname too long")
            atyp = b"\x03"
            addr = bytes([len(encoded)]) + encoded
        sock.sendall(b"\x05\x01\x00" + atyp + addr + port.to_bytes(2, "big"))
        head = recv_exact(sock, 4)
        if head[1] != 0:
            raise OSError(f"SOCKS5 connect failed: {head[1]}")
        if head[3] == 1:
            need = 4
        elif head[3] == 4:
            need = 16
        elif head[3] == 3:
            need = recv_exact(sock, 1)[0]
        else:
            raise OSError("SOCKS5 invalid address type")
        recv_exact(sock, need + 2)


def check_tcp(local_port: int) -> tuple[bool, str]:
    for host, port in TCP_TARGETS:
        try:
            socks5_probe(local_port, host, port)
        except Exception as e:
            return False, f"tcp: {str(e)[:100]}"
    return True, "tcp OK"


def parse_ip_response(response: requests.Response) -> str:
    try:
        data = response.json()
        text = str(data.get("ip", "")) if isinstance(data, dict) else ""
    except ValueError:
        text = response.text
    text = text.strip()
    ipaddress.ip_address(text)
    return text


def get_exit_ip(proxies: dict[str, str]) -> tuple[str, str]:
    last_error = "exit-ip API: нет URL для проверки"
    for url in EXIT_IP_API_URLS:
        try:
            r = get_with_retry(url, proxies=proxies, timeout=EXIT_IP_TIMEOUT, retries=EXIT_IP_RETRIES, retry_network=True)
        except requests.RequestException as e:
            last_error = exception_text("exit-ip API", e)
            continue
        if not r.ok:
            last_error = http_error_text("exit-ip API", r)
            continue
        try:
            return parse_ip_response(r), ""
        except ValueError:
            last_error = "exit-ip API: вернул некорректный IP"
    return "", last_error


_country_cache: dict[str, str] = {}


def lookup_country(ip: str) -> tuple[str, str]:
    cached = _country_cache.get(ip)
    if cached:
        return cached, ""
    saved = _geo_cache.get(ip)
    if saved and saved.get("iso"):
        _country_cache[ip] = saved["iso"]
        return saved["iso"], ""
    try:
        r = get_with_retry(
            f"{COUNTRY_API_URL}/{ip}",
            timeout=COUNTRY_TIMEOUT,
            retries=COUNTRY_RETRIES,
            retry_network=True,
            before=_country_limiter.wait,
            on_response=_country_limiter.feedback,
        )
    except requests.RequestException as e:
        return "", exception_text("country API", e)
    if not r.ok:
        return "", http_error_text("country API", r)
    try:
        iso = str(r.json().get("country", "")).strip().upper()
    except (ValueError, AttributeError):
        return "", "country API: некорректный JSON"
    if not iso:
        return "", "country API: страна не указана"
    _country_cache[ip] = iso
    _geo_cache.put(ip, iso=iso)
    return iso, ""


UDP_TRANSPORTS = {"kcp", "mkcp", "quic"}


def uses_tcp(proxy: ProxyConfig) -> bool:
    if proxy.scheme == "hysteria2":
        return False
    return str(proxy.params.get("type", "tcp")).lower() not in UDP_TRANSPORTS


_tcp_cache: dict[tuple[str, int], tuple[bool, str]] = {}


def tcp_probe(ip: str, port: int) -> tuple[bool, str]:
    cached = _tcp_cache.get((ip, port))
    if cached is not None:
        return cached
    try:
        with socket.create_connection((ip, port), timeout=TCP_PRECHECK_TIMEOUT):
            result = (True, "")
    except OSError as e:
        result = (False, exception_text("tcp", e))
    _tcp_cache[(ip, port)] = result
    return result


def tcp_reachable(ips: list[str], port: int) -> tuple[bool, str]:
    last_error = "tcp: нет IP для проверки"
    for ip in ips[: max(1, TCP_PRECHECK_MAX_IPS)]:
        ok, error = tcp_probe(ip, port)
        if ok:
            return True, ""
        last_error = error
    return False, last_error


def check_single_proxy(
    proxy: ProxyConfig, mode: str, workdir: str, ips: list[str] | None = None
) -> CheckResult:
    proc = None
    try:
        if mode == "generate_204" and TCP_PRECHECK_TIMEOUT > 0 and ips and uses_tcp(proxy):
            reachable, reason = tcp_reachable(ips, proxy.port)
            if not reachable:
                return CheckResult(proxy, False, reason, stage="tcp")
        launched = launch_xray(proxy, workdir)
        if launched is None:
            return CheckResult(proxy, False, "xray не запустился", stage="xray")
        proc, port = launched
        proxies = socks_proxies(port)
        if mode == "generate_204":
            ok, reason = check_generate_204(proxies)
        elif mode == "tcp":
            ok, reason = check_tcp(port)
        else:
            ok, reason = True, ""
        if not ok:
            return CheckResult(proxy, False, reason, stage=mode)
        exit_ip, error = get_exit_ip(proxies)
        if not exit_ip:
            if mode == "generate_204":
                return CheckResult(proxy, True, error, stage="unknown_ip")
            return CheckResult(proxy, False, error, stage="exit_ip")
        iso, error = lookup_country(exit_ip)
        if not iso:
            error = error or "country API: не удалось определить страну"
            if mode == "generate_204":
                return CheckResult(proxy, True, error, exit_ip=exit_ip, stage="unknown_country")
            return CheckResult(proxy, False, error, exit_ip=exit_ip, stage="country")
        return CheckResult(proxy, True, exit_ip=exit_ip, exit_iso=iso, stage="ok")
    except Exception as e:
        return CheckResult(proxy, False, f"{type(e).__name__}: {str(e)[:110]}", stage="other")
    finally:
        stop_xray(proc)


#---------
# КОНВЕЙЕР: Xray -> Cheburcheck
#---------

@dataclass
class GateStats:
    passed: int = 0
    failed: int = 0
    prefiltered: int = 0
    kinds: Counter = field(default_factory=Counter)
    cached: int = 0
    requests: int = 0
    throttled: int = 0
    dns: int = 0


def proxy_label(proxy: ProxyConfig) -> str:
    host = f"[{proxy.host}]" if ":" in proxy.host else proxy.host
    return f"{proxy.scheme}://{host}:{proxy.port}"


def run_pipeline(
    configs: list[ProxyConfig], mode: str, workdir: str, gate_cache: TtlCache
) -> tuple[list[CheckResult], GateStats, Counter]:
    host_map = resolve_hosts({p.host.lower() for p in configs})
    config_ips = [host_map.get(p.host.lower(), []) for p in configs]
    ip_users: dict[str, list[int]] = {}
    for idx, ips in enumerate(config_ips):
        for ip in ips:
            ip_users.setdefault(ip, []).append(idx)
    print(f"[+] Уникальных IP: {len(ip_users)}")

    gate = GateStats()
    xray_counter = itertools.count(1)
    tcp_counter = itertools.count(1)
    gate_counter = itertools.count(1)
    done_queue: queue.Queue = queue.Queue()
    outstanding = 0
    results: dict[int, CheckResult] = {}
    verdicts: dict[str, Verdict] = {}
    queued_ips: set[str] = set()
    waiting: set[int] = set()
    accepted: set[int] = set()
    rejected: dict[int, str] = {}

    def check_and_log(idx: int) -> CheckResult:
        proxy = configs[idx]
        result = check_single_proxy(proxy, mode, workdir, config_ips[idx])
        status = "OK  " if result.ok else "FAIL"
        if result.ok and result.exit_iso:
            extra = f"{result.exit_ip} | {result.exit_iso}"
        elif result.ok:
            extra = f"страна неизвестна ({result.error})"
        else:
            extra = result.error
        if mode == "generate_204" and result.stage == "tcp":
            log(f"[tcp {next(tcp_counter)}] FAIL {proxy_label(proxy)} {extra}")
        else:
            port_checked = (
                mode == "generate_204" and TCP_PRECHECK_TIMEOUT > 0 and bool(config_ips[idx]) and uses_tcp(proxy)
            )
            mark = " (tcp ок)" if port_checked else ""
            log(f"[xray {next(xray_counter)}] {status}{mark} {proxy_label(proxy)} {extra}")
        return result

    def submit(pool: ThreadPoolExecutor, fn: Callable, arg, tag: tuple) -> None:
        nonlocal outstanding
        future = pool.submit(fn, arg)
        outstanding += 1
        future.add_done_callback(lambda f, t=tag: done_queue.put((t, f)))

    def request_ip(ip: str) -> None:
        if ip in verdicts or ip in queued_ips:
            return
        saved = gate_cache.get(ip)
        if saved is not None:
            gate.cached += 1
            ok = bool(saved.get("ok"))
            verdicts[ip] = Verdict(ok, "ok" if ok else "blocked", "доступен в РФ (кэш)" if ok else "заблокирован в РФ (кэш)")
            return
        queued_ips.add(ip)
        submit(gate_pool, safe_cheburcheck, ip, ("gate", ip))

    def decide(idx: int) -> None:
        if idx not in waiting:
            return
        vs = [verdicts.get(ip) for ip in config_ips[idx]]
        if any(v is not None and v.ok for v in vs):
            waiting.discard(idx)
            accepted.add(idx)
            return
        if any(v is None or v.transient for v in vs):
            return
        waiting.discard(idx)
        rejected[idx] = next((v for v in vs if v.kind == "blocked"), vs[0]).kind

    with ThreadPoolExecutor(max_workers=max(1, MAX_WORKERS)) as check_pool, \
            ThreadPoolExecutor(max_workers=max(1, CHEBURCHECK_WORKERS)) as gate_pool:
        for idx, ips in enumerate(config_ips):
            if not ips:
                gate.dns += 1
                log(f"[dns] FAIL {proxy_label(configs[idx])} не удалось определить IP")
                continue
            if all((saved := gate_cache.get(ip)) is not None and not saved.get("ok") for ip in ips):
                gate.prefiltered += 1
                rejected[idx] = "blocked"
                continue
            submit(check_pool, check_and_log, idx, ("check", idx))

        retry_round = 0
        while True:
            while outstanding:
                tag, future = done_queue.get()
                outstanding -= 1
                if tag[0] == "check":
                    idx = tag[1]
                    try:
                        result = future.result()
                    except Exception as e:
                        result = CheckResult(configs[idx], False, f"{type(e).__name__}", stage="other")
                    results[idx] = result
                    if result.ok:
                        waiting.add(idx)
                        for ip in config_ips[idx]:
                            request_ip(ip)
                        decide(idx)
                    continue
                ip = tag[1]
                queued_ips.discard(ip)
                verdict = future.result()
                log(f"[gate {next(gate_counter)}] {'PASS' if verdict.ok else 'FAIL'} {ip} {verdict.detail}")
                if verdict.kind in {"ok", "blocked"}:
                    gate_cache.put(
                        ip,
                        ttl_seconds=None if verdict.ok else CHEBURCHECK_BLOCKED_CACHE_HOURS * 3600,
                        ok=int(verdict.ok),
                    )
                verdicts[ip] = verdict
                for idx in ip_users[ip]:
                    decide(idx)
            retry = [
                ip for ip, v in verdicts.items()
                if v.transient and any(idx in waiting for idx in ip_users[ip])
            ]
            if retry_round >= 1 or not retry or time_is_up():
                break
            retry_round += 1
            log(f"[gate] повторная проверка {len(retry)} IP после временных ошибок Cheburcheck")
            time.sleep(CHEBURCHECK_RECHECK_DELAY)
            for ip in retry:
                del verdicts[ip]
                request_ip(ip)

        for idx in sorted(waiting):
            vs = [verdicts[ip] for ip in config_ips[idx]]
            rejected[idx] = next((v for v in vs if v.kind == "blocked"), vs[0]).kind
        waiting.clear()

        gate.passed = len(accepted)
        gate.failed = len(rejected)
        for kind in rejected.values():
            gate.kinds[kind] += 1
        gate.requests = _chebur_limiter.calls
        gate.throttled = _chebur_limiter.throttled

    passed_xray = sum(1 for r in results.values() if r.ok)
    tcp_dropped = sum(1 for r in results.values() if mode == "generate_204" and r.stage == "tcp")
    print(f"[+] TCP-предпроверка: отсеяно {tcp_dropped}")
    print(f"[+] Xray: проверено {len(results) - tcp_dropped}, прошло {passed_xray}")
    print(f"[+] Cheburcheck: запросов {gate.requests}, из кэша {gate.cached}, отсеяно до Xray {gate.prefiltered}; прошло {gate.passed}, не прошло {gate.failed}")
    ordered = [results[i] for i in sorted(results) if i not in rejected]
    return ordered, gate, Counter(r.stage for r in results.values())

#---------
# ИСТОРИЯ
#---------

HISTORY_VERSION = 3


def empty_history() -> dict:
    return {"version": HISTORY_VERSION, "run": 0, "entries": {}, "gate": {}, "geo": {}}


def load_history() -> dict:
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return empty_history()
    if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
        return empty_history()
    if data.get("version") == HISTORY_VERSION:
        data["run"] = int(data.get("run", 0) or 0)
        for section in ("gate", "geo"):
            if not isinstance(data.get(section), dict):
                data[section] = {}
        return data
    if data.get("version") == 2:
        history = empty_history()
        for old_key, item in data["entries"].items():
            streak = item.get("streak", 0) if isinstance(item, dict) else 0
            if streak > 0:
                history["entries"][config_key(old_key)] = {"streak": streak, "seen": 0}
        return history
    return empty_history()


def update_history(history: dict, results: list[CheckResult]) -> None:
    history["run"] += 1
    run = history["run"]
    entries = history["entries"]
    for result in results:
        key = result.proxy.key()
        if result.ok:
            entries[key] = {"streak": entries.get(key, {}).get("streak", 0) + 1, "seen": run}
        else:
            entries.pop(key, None)
    for key in [k for k, v in entries.items() if run - v.get("seen", 0) > HISTORY_KEEP_RUNS]:
        del entries[key]


def save_history(history: dict) -> None:
    write_text_atomic(HISTORY_FILE, json.dumps(history, ensure_ascii=False, separators=(",", ":"), sort_keys=True))


#---------
# ВЫВОД
#---------

def named_link(result: CheckResult) -> str:
    name = f"{country_flag(result.exit_iso)} {country_name(result.exit_iso)} | {NAME_SUFFIX}"
    return result.proxy.to_link(name=name)


def write_subscription(path: str, results: list[CheckResult], title: str) -> None:
    lines = [
        f"#profile-title: {title}",
        f"#profile-update-interval: {INFO['update_interval']}",
        f"#support-url: {INFO['support_url']}",
        f"#announce: {INFO['announce']}",
        "#subscription-userinfo: upload=0; download=0; total=0; expire=0",
    ]
    lines.extend(named_link(x) for x in results)
    write_text_atomic(path, "\n".join(lines) + "\n")


def build_report(
    good: list[CheckResult],
    main_list: list[CheckResult],
    collect: CollectStats,
    source_errors: list[str],
    gate: GateStats,
    check: Counter,
    mode: str,
    kept_old: bool,
) -> list[str]:
    k = gate.kinds
    by = collect.by_scheme
    protocols = Counter(item.proxy.scheme for item in main_list)
    countries = Counter(item.exit_iso for item in main_list)
    unknown_ip = check["unknown_ip"]
    unknown_country = check["unknown_country"]
    unknown_total = unknown_ip + unknown_country
    lines = [
        "=== СТАТИСТИКА ПРОВЕРКИ ===",
        f"Источников подписок: {collect.sources} (OK: {collect.sources_ok}, FAIL: {collect.sources_failed})",
        f"Получено ссылок: {collect.received}",
        f"  VLESS: {by['vless']}",
        f"  VMess: {by['vmess']}",
        f"  Trojan: {by['trojan']}",
        f"  Hysteria2/Hy2: {by['hysteria2'] + by['hy2']}",
        f"Некорректных конфигов: {collect.invalid}",
        f"Неизвестных строк: {collect.unsupported_lines}",
        f"Дубликатов удалено: {collect.duplicates}",
        f"Уникальных конфигов: {collect.unique}",
        f"DNS FAIL: {gate.dns}",
        f"Режим проверки: {mode}",
        f"Проверено Xray: {sum(check.values())}",
        f"Xray FAIL: {check['xray']}",
        f"Проверка доступности FAIL: {check['generate_204'] + check['tcp']} (generate_204: {check['generate_204']}, tcp: {check['tcp']})",
        f"Ошибка EXIT IP: {check['exit_ip']}",
        f"Ошибка страны: {check['country']}",
        f"Страна не определена, принято как «Неизвестно»: {unknown_total} (exit IP: {unknown_ip}, страна: {unknown_country})",
        f"Другие FAIL: {check['other']}",
        f"Xray OK: {check['ok'] + unknown_total}",
        f"Cheburcheck запросов: {gate.requests} (из кэша IP: {gate.cached}, ответов 429: {gate.throttled})",
        f"Отсеяно по кэшу Cheburcheck до Xray: {gate.prefiltered}",
        (
            f"Cheburcheck FAIL: {gate.failed} (blocked: {k['blocked']}, "
            f"HTTP: {k['http_429'] + k['http_5xx'] + k['http_other']}, 429: {k['http_429']}, 5xx: {k['http_5xx']}, "
            f"timeout: {k['timeout']}, connection: {k['connection']}, other: {k['other'] + k['bad_json']}, "
            f"отложено по времени: {k['deferred']})"
        ),
        f"После Cheburcheck: {gate.passed}",
        "",
        "ПРОТОКОЛЫ ОСНОВНОЙ ПОДПИСКИ:",
        f"  VLESS: {protocols['vless']}",
        f"  VMess: {protocols['vmess']}",
        f"  Trojan: {protocols['trojan']}",
        f"  Hysteria2/Hy2: {protocols['hysteria2']}",
        "",
        "РАБОЧИЕ ПО СТРАНАМ:",
    ]
    if countries:
        for iso, count in sorted(countries.items(), key=lambda x: (-x[1], x[0])):
            code = iso or "XX"
            lines.append(f"  {country_flag(iso)} {country_name(iso)} ({code}): {count}")
    else:
        lines.append("  —")
    lines += [
        "",
        f"ИТОГО рабочих: {len(good)}",
        f"Основная подписка: {len(main_list)} / {MAX_PROXIES}",
        f"Полная подписка: {len(good)}",
    ]
    if kept_old:
        lines += ["", "ВНИМАНИЕ: рабочих конфигов нет, подписки НЕ перезаписаны (оставлены прошлые)."]
    if source_errors:
        lines += ["", "ОШИБКИ ОБРАЩЕНИЯ К САЙТАМ/ИСТОЧНИКАМ:"]
        lines.extend(f"  - {error}" for error in source_errors[:30])
        if len(source_errors) > 30:
            lines.append(f"  ... ещё {len(source_errors) - 30}")
    return lines


def build_stats(good: list[CheckResult], main_list: list[CheckResult]) -> dict:
    countries = Counter(item.exit_iso for item in main_list if item.exit_iso)
    return {
        "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": len(good),
        "main": len(main_list),
        "countries": len({item.exit_iso for item in good if item.exit_iso}),
        "unknown_country": sum(1 for item in good if not item.exit_iso),
        "protocols": dict(Counter(item.proxy.scheme for item in good)),
        "top_countries": [
            {"iso": iso, "name": country_name(iso), "count": count}
            for iso, count in countries.most_common(10)
        ],
    }


def save_results(
    results: list[CheckResult],
    history: dict,
    collect: CollectStats,
    source_errors: list[str],
    gate: GateStats,
    check: Counter,
    mode: str,
) -> None:
    streaks = history["entries"]
    good = [x for x in results if x.ok]
    good.sort(key=lambda x: (not x.exit_iso, -streaks.get(x.proxy.key(), {}).get("streak", 0)))
    main_list = [x for x in good if x.exit_iso][:MAX_PROXIES] or good[:MAX_PROXIES]

    kept_old = not good
    if good:
        write_subscription(OUTPUT_FILE, main_list, INFO["title_main"])
        write_subscription(ALL_FILE, good, INFO["title_all"])
        write_text_atomic(STATS_FILE, json.dumps(build_stats(good, main_list), ensure_ascii=False, indent=2) + "\n")

    lines = build_report(good, main_list, collect, source_errors, gate, check, mode, kept_old)
    write_text_atomic(REPORT_FILE, "\n".join(lines) + "\n")
    print()
    for line in lines:
        print(f"[+] {line}" if line else "")


#---------
# MAIN
#---------

def main() -> None:
    mode = load_mode()
    print(f"[+] Режим проверки: {mode}")
    configs, collect, source_errors = collect_configs()
    print(f"[+] Найдено: {len(configs)} уникальных конфигов")

    global _geo_cache
    history = load_history()
    gate_cache = TtlCache(history["gate"], CHEBURCHECK_CACHE_HOURS * 3600)
    _geo_cache = TtlCache(history["geo"], COUNTRY_CACHE_DAYS * 86400)
    results: list[CheckResult] = []
    gate = GateStats()
    check: Counter = Counter()
    if configs:
        with tempfile.TemporaryDirectory(prefix="knetaproxy_") as workdir:
            results, gate, check = run_pipeline(configs, mode, workdir, gate_cache)
        update_history(history, results)
        gate_cache.prune()
        _geo_cache.prune()
        save_history(history)
    save_results(results, history, collect, source_errors, gate, check, mode)


if __name__ == "__main__":
    main()
