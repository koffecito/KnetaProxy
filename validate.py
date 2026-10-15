#!/usr/bin/env python3

#---------
# ПРОВЕРКА НАСТРОЕК
#---------

import os
import shutil
import sys
from urllib.parse import urlparse

from checker import SUBSCRIPTIONS_ENV, TYPE_FILE, VALID_MODES, XRAY_BIN, iter_source_lines, supported_link

REQUIRED_FILES = (
    "checker.py",
    TYPE_FILE,
    "info.txt",
    "telegram_notify.py",
    "telegram_chats.txt",
)


def fail(message: str) -> None:
    print(f"[!] {message}")
    sys.exit(1)


def main() -> None:
    print("[+] Проверка структуры проекта...")

    for path in REQUIRED_FILES:
        if not os.path.isfile(path):
            fail(f"Не найден обязательный файл: {path}")

    if shutil.which(XRAY_BIN) is None:
        fail(f"Xray не найден ({XRAY_BIN}): установите Xray-core или задайте XRAY_BIN")

    with open(TYPE_FILE, "r", encoding="utf-8") as f:
        mode = f.read().strip().lower()
    if mode not in VALID_MODES:
        fail(f"{TYPE_FILE} должен содержать одно из: {', '.join(VALID_MODES)}")
    print(f"[+] Режим: {mode}")

    raw_sources = os.environ.get(SUBSCRIPTIONS_ENV, "")
    if not raw_sources.strip():
        fail(f"Не задан GitHub Secret {SUBSCRIPTIONS_ENV} (по одному URL или конфигурации на строку)")

    sources = list(iter_source_lines(raw_sources))
    if not sources:
        fail(f"GitHub Secret {SUBSCRIPTIONS_ENV} не содержит источников или конфигураций")

    urls = []
    for line in sources:
        if line.lower().startswith(("http://", "https://")):
            if not urlparse(line).netloc:
                fail(f"Некорректный URL в GitHub Secret {SUBSCRIPTIONS_ENV}")
            urls.append(line)
        elif not supported_link(line):
            fail(f"В {SUBSCRIPTIONS_ENV} обнаружена неподдерживаемая строка")

    print(f"[+] Строк с источниками/конфигурациями: {len(sources)}")
    duplicates = len(urls) - len(set(urls))
    if duplicates:
        print(f"[!] Дубликатов URL-источников: {duplicates}")

    os.makedirs("proxies", exist_ok=True)
    print("[+] Проверка настроек завершена")


if __name__ == "__main__":
    main()
