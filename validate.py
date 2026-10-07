#!/usr/bin/env python3

#---------
# ПРОВЕРКА НАСТРОЕК
#----------

import os
import sys
from urllib.parse import urlparse

REQUIRED_FILES = (
    "checker.py",
    "subscriptions.txt",
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

    sources = []
    with open("subscriptions.txt", "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parsed = urlparse(line)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                fail(f"Некорректный URL в subscriptions.txt: {line}")
            sources.append(line)

    if not sources:
        fail("subscriptions.txt пуст")

    duplicates = len(sources) - len(set(sources))
    print(f"[+] Источников подписок: {len(sources)}")
    if duplicates:
        print(f"[!] Дубликатов источников: {duplicates}")

    os.makedirs("proxies", exist_ok=True)
    print("[+] Каталог proxies: OK")
    print("[+] Проверка настроек завершена")


if __name__ == "__main__":
    main()
