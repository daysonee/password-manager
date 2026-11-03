"""функции шифрования и дешифрования Argon2id для мастер-пароля и Fernet для записей."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidKey
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

SALT_SIZE = 16
KEY_SIZE = 32


@dataclass(frozen=True)
class KdfParams:
    """Параметры для Argon2id по IRTF RFC 9106"""

    iterations: int = 3
    lanes: int = 4
    memory_cost: int = 2**16


def create_salt() -> bytes:
    """Возвращает соль для шифрования"""

    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes, params: KdfParams) -> bytes:
    """Создает ключ из пароля и подмешенной соли"""

    kdf = Argon2id(
        salt=salt,
        length=KEY_SIZE,
        iterations=params.iterations,
        lanes=params.lanes,
        memory_cost=params.memory_cost,
    )
    key = kdf.derive(password.encode("utf-8"))
    return key


def verify_password(password: str, salt: bytes, expected: bytes, params: KdfParams) -> bool:
    """Сравнивает пароль с реальным с подмешанной солью"""

    kdf = Argon2id(
        salt=salt,
        length=KEY_SIZE,
        iterations=params.iterations,
        lanes=params.lanes,
        memory_cost=params.memory_cost,
    )
    try:
        Argon2id.verify(kdf, password.encode("utf-8"), expected)
    except InvalidKey:
        return False
    return True


def encrypt(key: bytes, password: str) -> str:
    """Шифрует строку ключем размера KEY_SIZE и возвращает токен Fernet"""
    f = Fernet(base64.urlsafe_b64encode(key))
    return f.encrypt(password.encode("utf-8")).decode("utf-8")


def decrypt(key: bytes, token: str) -> str:
    """Расшифровывает Fernet токен. Плохой ключ или токен кидают ValueError"""
    f = Fernet(base64.urlsafe_b64encode(key))
    try:
        res = f.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as e:
        raise ValueError("Неверный ключ или данные") from e
    return res


def to_b64(data: bytes) -> str:
    """Байты в base64-строку для JSON"""
    return base64.urlsafe_b64encode(data).decode("utf-8")


def from_b64(text: str) -> bytes:
    """base64-строка из JSON в байты."""
    return base64.urlsafe_b64decode(text)
