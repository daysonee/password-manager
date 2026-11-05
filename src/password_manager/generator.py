"""Генератор надежных паролей"""

from __future__ import annotations

import secrets
import string

LETTERS = string.ascii_letters
DIGITS = string.digits
PUNCTUATIONS = string.punctuation

ALPHABET = string.ascii_letters + string.digits + string.punctuation
MIN_LEN = 8


def generate_password(len: int = 10) -> str:
    """Случайный пароль из букв цифр и символов содержащий символы из каждой группы"""
    if len < MIN_LEN:
        raise ValueError(f"Пароль должен быть не менее {MIN_LEN} символов")
    while True:
        password = "".join(secrets.choice(ALPHABET) for _ in range(len))
        if (
            any(char in LETTERS for char in password)
            and any(char in DIGITS for char in password)
            and any(char in PUNCTUATIONS for char in password)
        ):
            return password
