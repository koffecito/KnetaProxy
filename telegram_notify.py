#!/usr/bin/env python3

#---------
# TELEGRAM УВЕДОМЛЕНИЕ
#----------

import html
import os
import re
import sys
from datetime import datetime, timezone

import requests

REPORT_FILE = "proxies/report.txt"
CHATS_FILE = "telegram_chats.txt"
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
REPORT_MAX_COUNTRIES = int(os.environ.get("REPORT_MAX_COUNTRIES", "10"))
TELEGRAM_TIMEOUT = float(os.environ.get("TELEGRAM_TIMEOUT", "15"))


def read_chats() -> list[str]:
    if not os.path.exists(CHATS_FILE):
        return []
    result = []
    with open(CHATS_FILE, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line not in result:
                result.append(line)
    return result


def get_int(text: str, pattern: str, default: int = 0) -> int:
    match = re.search(pattern, text, re.MULTILINE)
    return int(match.group(1)) if match else default


def get_mode(text: str) -> str:
    match = re.search(r"^Режим проверки:\s*(.+)$", text, re.MULTILINE)
    return match.group(1).strip() if match else "—"


def parse_protocols(text: str) -> list[tuple[str, int]]:
    names = {
        "VLESS": r"^  VLESS:\s*(\d+)$",
        "VMess": r"^  VMess:\s*(\d+)$",
        "Trojan": r"^  Trojan:\s*(\d+)$",
        "Hysteria2/Hy2": r"^  Hysteria2/Hy2:\s*(\d+)$",
    }
    return [(name, get_int(text, pattern)) for name, pattern in names.items()]


def parse_chebur_errors(text: str) -> list[str]:
    match = re.search(r"^Cheburcheck FAIL:\s*\d+ \(blocked:\s*(\d+), HTTP:\s*(\d+), 429:\s*(\d+), 5xx:\s*(\d+), timeout:\s*(\d+), connection:\s*(\d+), other:\s*(\d+)\)$", text, re.MULTILINE)
    if not match:
        return []
    blocked, http_total, http_429, http_5xx, timeout, connection, other = map(int, match.groups())
    result = []
    if blocked:
        result.append(f"🚫 Blocked — {blocked}")
    if http_429:
        result.append(f"⏱ HTTP 429 — {http_429}")
    if http_5xx:
        result.append(f"💥 HTTP 5xx — {http_5xx}")
    if timeout:
        result.append(f"⌛ Timeout — {timeout}")
    if connection:
        result.append(f"🔌 Connection — {connection}")
    if other:
        result.append(f"⚠️ Other — {other}")
    if http_total and not (http_429 or http_5xx):
        result.append(f"🌐 HTTP — {http_total}")
    return result


def parse_countries(text: str) -> list[tuple[str, int]]:
    section = text.split("РАБОЧИЕ ПО СТРАНАМ:", 1)
    if len(section) != 2:
        return []
    block = section[1].split("\n\n", 1)[0]
    result = []
    for line in block.splitlines():
        match = re.match(r"^\s+(\S+)\s+(.+?)\s+\(([A-Z]{2})\):\s*(\d+)$", line)
        if match:
            flag, name, _iso, count = match.groups()
            result.append((f"{flag} {name}", int(count)))
    return result


def parse_errors(text: str) -> list[str]:
    result = []
    section = text.split("ОШИБКИ ОБРАЩЕНИЯ К САЙТАМ/ИСТОЧНИКАМ:", 1)
    if len(section) != 2:
        return result
    for line in section[1].splitlines():
        line = line.strip()
        if line.startswith("-"):
            result.append(line.lstrip("- "))
    return result[:8]


def subscription_urls() -> tuple[str, str, str]:
    base = os.environ.get("SUBSCRIPTION_BASE_URL", "").strip().rstrip("/")
    if base:
        return f"{base}/working.txt", f"{base}/top10.txt", f"{base}/all.txt"

    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    branch = os.environ.get("GITHUB_REF_NAME", "main").strip() or "main"
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    if repository and server == "https://github.com":
        return (
            f"https://raw.githubusercontent.com/{repository}/{branch}/proxies/working.txt",
            f"https://raw.githubusercontent.com/{repository}/{branch}/proxies/top10.txt",
            f"https://raw.githubusercontent.com/{repository}/{branch}/proxies/all.txt",
        )
    return "URL не настроен", "URL не настроен", "URL не настроен"


def build_message(report: str) -> str:
    now = datetime.now(timezone.utc).astimezone()
    mode = html.escape(get_mode(report))

    received = get_int(report, r"^Получено ссылок:\s*(\d+)$")
    invalid = get_int(report, r"^Некорректных конфигов:\s*(\d+)$")
    duplicates = get_int(report, r"^Дубликатов удалено:\s*(\d+)$")
    unique = get_int(report, r"^Уникальных конфигов:\s*(\d+)$")
    chebur_ok = get_int(report, r"^После Cheburcheck:\s*(\d+)$")
    chebur_fail = get_int(report, r"^Cheburcheck FAIL:\s*(\d+)")
    total = get_int(report, r"^ИТОГО рабочих:\s*(\d+)$")

    protocols = parse_protocols(report)
    countries = parse_countries(report)
    errors = parse_errors(report)
    chebur_errors = parse_chebur_errors(report)
    main_url, top_url, all_url = subscription_urls()

    lines = [
        "📊 <b>KnetaProxy</b>",
        "<b>Результаты проверки</b>",
        "",
        f"⚙️ Режим: <code>{mode}</code>",
        f"🕐 Обновлено: <code>{now.strftime('%d.%m.%Y %H:%M')} UTC</code>",
        "",
        "━━━━━━━━━━━━━━━━━━",
        "",
        "📦 <b>Конфигурации</b>",
        f"├ 📥 Получено: <b>{received}</b>",
        f"├ 🧹 Уникальных: <b>{unique}</b>",
        f"├ ♻️ Дубликатов: <b>{duplicates}</b>",
        f"└ ⚠️ Некорректных: <b>{invalid}</b>",
        "",
        "🛡 <b>Cheburcheck</b>",
        f"├ ✅ Доступны: <b>{chebur_ok}</b>",
        f"└ ❌ Недоступны: <b>{chebur_fail}</b>",
        "",
        "🚀 <b>Результат</b>",
        f"└ ✅ Рабочих VPN: <b>{total}</b>",
        "",
        "━━━━━━━━━━━━━━━━━━",
        "",
        "🔌 <b>Протоколы в основной подписке</b>",
        "",
    ]
    for name, count in protocols:
        lines.append(f"• {html.escape(name)} — {count}")

    lines += ["", "━━━━━━━━━━━━━━━━━━", "", "🌍 <b>Страны</b>", ""]
    shown = countries[:REPORT_MAX_COUNTRIES]
    country_lines = "\n".join(f"{html.escape(name)} — {count}" for name, count in shown)
    if len(countries) > REPORT_MAX_COUNTRIES:
        country_lines += f"\n<i>Ещё {len(countries) - REPORT_MAX_COUNTRIES} стран...</i>"
    if not country_lines:
        country_lines = "—"
    lines.append(f"<blockquote expandable>{country_lines}</blockquote>")

    if chebur_errors:
        lines += ["", "━━━━━━━━━━━━━━━━━━", "", "❗ <b>Ошибки Cheburcheck</b>", ""]
        lines.extend(html.escape(error) for error in chebur_errors)

    if errors:
        lines += ["", "━━━━━━━━━━━━━━━━━━", "", "❗ <b>Ошибки источников</b>", ""]
        lines.extend(f"• {html.escape(error)}" for error in errors)

    lines += [
        "",
        "━━━━━━━━━━━━━━━━━━",
        "",
        "🔗 <b>Подписки</b>",
        "",
        "📥 <b>Основная Подписка</b>",
        f"<code>{html.escape(main_url)}</code>",
        "",
        "🏆 <b>TOP 10</b>",
        f"<code>{html.escape(top_url)}</code>",
        "",
        "📚 <b>Полная Подписка</b>",
        f"<code>{html.escape(all_url)}</code>",
    ]
    return "\n".join(lines)


def send_message(chat_id: str, message: str) -> None:
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    response = requests.post(
        url,
        json={"chat_id": chat_id, "text": message, "parse_mode": "HTML", "disable_web_page_preview": True},
        timeout=TELEGRAM_TIMEOUT,
    )
    if response.status_code != 200:
        raise RuntimeError(f"HTTP {response.status_code}: {response.text[:500]}")
    data = response.json()
    if not data.get("ok"):
        raise RuntimeError(data.get("description", "Telegram API error"))


def main() -> None:
    if not BOT_TOKEN:
        print("[!] TELEGRAM_BOT_TOKEN не задан — Telegram-уведомление пропущено")
        return
    if not os.path.exists(REPORT_FILE):
        print(f"[!] Не найден {REPORT_FILE}", file=sys.stderr)
        sys.exit(1)

    chats = read_chats()
    if not chats:
        print("[!] telegram_chats.txt не содержит chat ID — отправка пропущена")
        return

    report = open(REPORT_FILE, "r", encoding="utf-8").read()
    message = build_message(report)

    failed = 0
    for chat_id in chats:
        try:
            send_message(chat_id, message)
            print(f"[+] Telegram: отправлено в {chat_id}")
        except Exception as exc:
            failed += 1
            print(f"[!] Telegram: ошибка для {chat_id}: {exc}", file=sys.stderr)

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
