"""Тесты шифрования"""

from password_manager.crypto import (
    KEY_SIZE,
    SALT_SIZE,
    KdfParams,
    create_salt,
    decrypt,
    derive_key,
    encrypt,
    from_b64,
    to_b64,
    verify_password,
)

FAST = KdfParams(memory_cost=8, iterations=1, lanes=1)  # минимальные параметры: тесты мгновенные


def test_derive_key() -> None:
    salt = create_salt()

    first = derive_key("key", salt, FAST)
    second = derive_key("key", salt, FAST)

    assert first == second


def test_verify_password_with_wrong_password() -> None:
    salt = create_salt()
    stored = derive_key("correct", salt, FAST)
    assert verify_password("wrong", salt, stored, FAST) is False


def test_verify_password_with_right_password() -> None:
    salt = create_salt()
    stored = derive_key("correct", salt, FAST)
    assert verify_password("correct", salt, stored, FAST) is True


def test_salt_change_token() -> None:
    salt1 = create_salt()
    salt2 = create_salt()
    pw1 = derive_key("pw", salt1, FAST)
    pw2 = derive_key("pw", salt2, FAST)
    assert pw1 != pw2


def test_key_and_salt() -> None:
    salt = create_salt()
    key = derive_key("key", salt, FAST)
    assert len(salt) == SALT_SIZE and len(key) == KEY_SIZE


def test_decrypt_and_encrypt() -> None:
    salt = create_salt()
    key = derive_key("key", salt, FAST)
    s = "test"
    assert s == decrypt(key, encrypt(key, s))


def test_from_and_to_b64() -> None:
    assert from_b64(to_b64(b"1")) == b"1"


def test_different_salts() -> None:
    assert create_salt() != create_salt()
