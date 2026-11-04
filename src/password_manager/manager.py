"""Менджер паролей: мастер-пароль, пароли к сервисам, сохранение в JSON"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from password_manager.crypto import (
    KdfParams,
    create_salt,
    decrypt,
    derive_key,
    encrypt,
    from_b64,
    to_b64,
    verify_password,
)


class VaultError(Exception):
    """Ошибка работы с хранилищем"""

class PasswordManager:
    """Менджер паролей, хранит записи в JSON"""

    def __init__(self, path: Path, params: KdfParams | None = None) -> None:
        self._path =  path
        self._params = params if params is not None else KdfParams()
        self._data: dict[str, Any] = {}
        self._key: bytes | None = None

    def _persist(self) -> None:
        """Записывает данные из self._data в json с правами 0o600"""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=4, ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._path)

    def _load(self) -> None:
        """Читает JSON в self._data"""
        if not self.is_initialised:
            raise VaultError("Хранилища не существует. Инициализируйте его командой pm --init")
        self._data = json.loads(self._path.read_text(encoding="utf-8"))

    @property
    def is_initialised(self) -> bool:
        """True если файл хранилища существует"""
        return self._path.exists()

    @property
    def is_unlocked(self) -> bool:
        """True если мастер пароль правильный"""
        return self._key is not None

    def init_master(self, password: str) -> None:
        """Создание нового хранилища, если есть бросает VaultError"""
        if self.is_initialised:
            raise VaultError("Хранилище уже создано")
        verify_salt = create_salt()
        key_salt = create_salt()
        verify_hash = derive_key(password, verify_salt, self._params)
        self._key = derive_key(password, key_salt, self._params)
        self._data = {
            "kdf" : asdict(self._params),
            "key_salt" : to_b64(key_salt),
            "verify_hash" : to_b64(verify_hash),
            "verify_salt" : to_b64(verify_salt),
            "entries" : {}
        }
        self._persist()

    def unlock(self, password: str) -> bool:
        """Проверяет мастер пароль"""
        self._load()
        params = KdfParams(**self._data["kdf"])
        salt = from_b64(self._data["verify_salt"])
        hash = from_b64(self._data["verify_hash"])
        if not verify_password(password, salt, hash, params):
            return False
        key_salt = from_b64(self._data["key_salt"])
        self._key=derive_key(password, key_salt, params)
        return True

    def _require_unlocked(self) -> bytes:
        """Возвращает ключ или кидает VaultError, если хранилище заперто"""
        if self._key is None:
            raise VaultError("Хранилище заперто")
        return self._key

    def add_entry(self, name: str, login: str, password: str) -> None:
        """Добавляет запись. Кидает VaultError если имя занято"""
        key = self._require_unlocked()
        self._load()
        for cur in self._data["entries"]:
            if cur == name:
                raise VaultError("Имя занято, попробуйте другое")
        self._data["entries"][name] = {"login" : encrypt(key, login),
                                       "password" : encrypt(key, password)}
        self._persist()

    def list_entries(self) -> list[str]:
        """Название записей"""
        self._require_unlocked()
        return sorted(self._data["entries"])

    def get_entry(self, name : str) -> tuple[str, str]:
        """Возвращает логин и пароль от сервиса, если такого нет кидает VaultError"""
        key = self._require_unlocked()
        self._load()
        node = self._data["entries"].get(name)
        if node is None:
            raise VaultError("Такого сервиса не существует")
        return (decrypt(key, node["login"]), decrypt(key, node["password"]))

    def delete_entry(self, name : str) -> None:
        """Удаляет запись о сервисе, если такого нет кидает VaultError"""
        self._require_unlocked()
        self._load()
        if self._data["entries"].get(name) is None:
            raise VaultError("Такого сервиса не существует")
        del self._data["entries"][name]
        self._persist()