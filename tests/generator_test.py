"""Тесты генератора надежных паролей"""

import pytest

from password_manager import generator


def test_password_len() -> None:
    password = generator.generate_password(20)
    assert len(password) == 20


def test_all_symbols_from_alphaber() -> None:
    password = generator.generate_password()
    assert all(char in generator.ALPHABET for char in password)


def test_unsafe_password() -> None:
    with pytest.raises(ValueError):
        assert generator.generate_password(2)


def test_different_types_of_chars() -> None:
    password = generator.generate_password()
    assert (
        any(char in generator.LETTERS for char in password)
        and any(char in generator.DIGITS for char in password)
        and any(char in generator.PUNCTUATIONS for char in password)
    )
