"""Интерфейс менеджера паролей в терминале"""

from __future__ import annotations

import argparse
import sys
from getpass import getpass
from pathlib import Path

from password_manager.generator import generate_password
from password_manager.manager import PasswordManager, VaultError

DEFAULT_PATH = Path.home() / ".password_manager" / "vault.json"
ATTEMPTS = 3
COMMAND_LIST = {"add", "list", "get", "delete"}


def create_parser() -> argparse.ArgumentParser:
    """Описывает аргументы для командной строки"""
    parser = argparse.ArgumentParser(prog="pm", description="Консольный менеджер паролей на Python")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--init", action="store_true", help="Инициализировать хранилище паролей")
    group.add_argument("--unlock", action="store_true", help="Войти в хранилище")
    group.add_argument("--generate", action="store_true", help="Сгенерировать безопасный пароль")

    parser.add_argument(
        "--length", "-l", type=int, default=10, help="Длина генерируемого пароля для --generate"
    )  # noqa: E501
    parser.add_argument(
        "--vault", type=Path, default=DEFAULT_PATH, help="Путь к файлу хранилища паролей"
    )  # noqa: E501
    return parser


def vault_init(manager: PasswordManager) -> None:
    """Инициализирует хранилище"""
    while True:
        password1 = getpass("Введите мастер-пароль к хранилищу:")
        password2 = getpass("Повторите матсер-пароль:")
        if password1 == password2:
            break
        else:
            print("Пароли не совпадают, повторите еще раз")
    manager.init_master(password1)
    print("Хранилище создано")


def vault_unlock(manager: PasswordManager) -> bool:
    """Открывает хранилище"""
    attempt = 0
    password = getpass("Введите мастер-пароль:")
    manager.unlock(password)
    if not manager.is_unlocked:
        while attempt < ATTEMPTS:
            if not manager.is_unlocked:
                attempt += 1
                password = getpass("Повторите попытку:")
                manager.unlock(password)
            if manager.is_unlocked:
                return True
        print("Превышено количество попыток")
        return False
    print("Хранилище открыто")
    return True


def generate_pass(length: int) -> None:
    """Печатает новый пароль"""
    print(generate_password(length))


def add(manager: PasswordManager) -> None:
    """Добавляет новую запись в хранилище"""
    name = input("Введите название сервиса: ")
    login = input("Введите логин от сервиса: ")
    password = getpass("Введите пароль от сервиса(Enter-генерация пароля): ")
    if len(password) == 0:
        password = generate_password()
    manager.add_entry(name, login, password)
    print(f"Данные для {name} успешно добавлены")


def entries(manager: PasswordManager) -> None:
    """Показывает список сервисов"""
    entries: list[str] = manager.list_entries()
    print("Список записей: \n")
    for note in entries:
        print(note, "\n")


def get(manager: PasswordManager) -> None:
    """Показывает логин и пароль от сервиса"""
    name = input("Введите название сервиса: ")
    if not manager.unlock(getpass("Подтвердите мастер-пароль: ")):
        print("Неверный пароль.")
        return
    login, password = manager.get_entry(name)
    print(f"Логин: {login}\nПароль: {password}")


def delete(manager: PasswordManager) -> None:
    """Удаляет запись из хранилища"""
    name = input("Введите имя записи: ")
    sure = input("Подтвердите удаление: y/n(default)")
    if sure == "y":
        manager.delete_entry(name)
        print("Запись удалена")


def run(manager: PasswordManager) -> None:
    """Читает команды до exit"""
    while True:
        command = input(">> ").strip().lower()
        if command == "exit":
            break
        if not command:
            continue
        if command not in COMMAND_LIST:
            print("Неизвестная команда. Доступно: add, list, get, delete, exit")
            continue
        try:
            if command == "add":
                add(manager)
            if command == "list":
                entries(manager)
            if command == "get":
                get(manager)
            if command == "delete":
                delete(manager)
        except (VaultError, ValueError) as e:
            print(f"ERROR. {e}")


def main(argv: list[str] | None = None) -> int:
    """Точка входа"""
    args = create_parser().parse_args(argv)
    try:
        if args.generate:
            generate_pass(args.length)
            return 0
        manager = PasswordManager(args.vault)
        if args.init:
            vault_init(manager)
        elif vault_unlock(manager):
            run(manager)
        else:
            return 1
    except (VaultError, ValueError) as e:
        print(f"ERROR. {e}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nВыход.")
        return 130
    return 0
