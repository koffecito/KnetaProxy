#!/usr/bin/env python3

#---------
# ПРОВЕРКА НАСТРОЕК
#----------

import os
import sys
from urllib.parse import urlparse

REQUIRED_FILES = (
    "checker.py",
    "type.txt",
    "info.txt",
    "telegram_notify.py",
    "telegram_chats.txt",
)

VALID_MODES = {"generate_204", "tcp", "no"}


def fail(message: str) -> None:
    print(f"[!] {message}")
    sys.exit(1)


def main() -> None:
    print("[+] Проверка структуры проекта...")

    for path in REQUIRED_FILES:
        if not os.path.isfile(path):
            fail(f"Не найден обязательный файл: {path}")

    mode = open("type.txt", "r", encoding="utf-8").read().strip().lower()
    if mode not in VALID_MODES:
        fail("type.txt должен содержать generate_204, tcp или no")
    print(f"[+] Режим: {mode}")

    raw_sources = os.environ.get("SUBSCRIPTIONS", "")
    if not raw_sources.strip():
        fail("Не задан GitHub Secret SUBSCRIPTIONS (по одному URL или конфигурации на строку)")

    sources = []
    for raw in raw_sources.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("http://", "https://")):
            parsed = urlparse(line)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                fail("Некорректный URL в GitHub Secret SUBSCRIPTIONS")
            sources.append(line)
        else:
            # Поддерживаемые прямые конфигурации также разрешены.
            from checker import supported_link
            if not supported_link(line):
                fail("В SUBSCRIPTIONS обнаружена неподдерживаемая строка; содержимое не выводится из соображений безопасности")
            sources.append(line)

    if not sources:
        fail("GitHub Secret SUBSCRIPTIONS не содержит источников или конфигураций")

    urls = [item for item in sources if item.startswith(("http://", "https://"))]
    duplicates = len(urls) - len(set(urls))
    print(f"[+] Строк с источниками/конфигурациями: {len(sources)}")
    if duplicates:
        print(f"[!] Дубликатов URL-источников: {duplicates}")

    os.makedirs("proxies", exist_ok=True)
    print("[+] Каталог proxies: OK")
    print("[+] Проверка настроек завершена")


if __name__ == "__main__":
    main()
