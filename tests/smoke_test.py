"""Тесты возможности запуска программы"""

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from password_manager import cli


def test_cli_main() -> None:
    assert callable(cli.main)


def test_argon2id_available() -> None:
    kdf = Argon2id(salt=b"0" * 16, length=32, iterations=1, lanes=4, memory_cost=2**21)
    assert len(kdf.derive(b"x")) == 32
