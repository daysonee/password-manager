"""Тесты менджера паролей"""

from pathlib import Path

import pytest

from password_manager.crypto import KdfParams
from password_manager.manager import PasswordManager, VaultError

FAST = KdfParams(memory_cost=8, iterations=1, lanes=1)
MASTER = "master"
LOGIN = "login123"
SECRET = "secret"


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    """Путь к файлу хранилища в папке теста"""
    return tmp_path / "vault.json"


@pytest.fixture
def pm(vault_path: Path) -> PasswordManager:
    """Созданное и отпертое хранилище"""
    manager = PasswordManager(vault_path, FAST)
    manager.init_master(MASTER)
    return manager


def test_init_manager(vault_path: Path) -> None:
    manager = PasswordManager(vault_path, FAST)
    assert not manager.is_initialised
    manager.init_master(MASTER)
    assert vault_path.exists()


def test_unlock_with_correct_password(pm: PasswordManager, vault_path: Path) -> None:
    manager = PasswordManager(vault_path, FAST)
    assert manager.unlock(MASTER) is True
    assert manager.is_unlocked


def test_unlock_with_wrong_password(pm: PasswordManager, vault_path: Path) -> None:
    manager = PasswordManager(vault_path, FAST)
    assert manager.unlock("wrong_password") is False
    assert not manager.is_unlocked


def test_reject_operations_without_unlock(pm: PasswordManager, vault_path: Path) -> None:
    manager = PasswordManager(vault_path, FAST)
    with pytest.raises(VaultError):
        manager.get_entry("github")


def test_second_init_dontt_overwrite(pm: PasswordManager, vault_path: Path) -> None:
    second = PasswordManager(vault_path, FAST)
    with pytest.raises(VaultError):
        second.init_master("second-password")
    assert second.unlock(MASTER) is True


def test_add_and_show_list(pm: PasswordManager) -> None:
    pm.add_entry("github", LOGIN, SECRET)
    assert pm.list_entries() == ["github"]


def test_get_login_and_password(pm: PasswordManager) -> None:
    pm.add_entry("github", LOGIN, SECRET)
    assert pm.get_entry("github") == (LOGIN, SECRET)


def test_deleter_entrie(pm: PasswordManager) -> None:
    pm.add_entry("github", LOGIN, SECRET)
    pm.delete_entry("github")
    assert len(pm.list_entries()) == 0


def test_save_data_after_restart(pm: PasswordManager, vault_path: Path) -> None:
    pm.add_entry("github", LOGIN, SECRET)
    manager = PasswordManager(vault_path, FAST)
    manager.unlock(MASTER)
    assert manager.get_entry("github") == (LOGIN, SECRET)


def test_vault_dont_have_raw_entries(pm: PasswordManager, vault_path: Path) -> None:
    pm.add_entry("github", LOGIN, SECRET)
    text = vault_path.read_text(encoding="utf-8")
    assert MASTER not in text
    assert LOGIN not in text
    assert SECRET not in text
