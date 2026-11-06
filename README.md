# password-manager

Консольный менеджер паролей на Python. Хранит логины и пароли к сервисам
в зашифрованном файле, доступ — по мастер-паролю.

Лабораторная работа №1, трек DevOps, тема Б1.

## Установка

```bash
git clone https://github.com/daysonee/password-manager.git
cd password-manager
uv sync
```

## Возможности

- создание хранилища с мастер-паролем (`--init`);
- вход по мастер-паролю, 3 попытки (`--unlock`);
- меню: `add`, `list`, `get`, `delete`, `exit`;
- `get` показывает пароль только после повторного ввода мастер-пароля;
- генератор надёжных паролей (`--generate`), в том числе при добавлении записи (Enter вместо пароля);
- логины и пароли записей хранятся зашифрованными.


## Запуск

```bash
uv run pm --init                  # создать хранилище
uv run pm --unlock                # войти и открыть меню
uv run pm --generate --length 16  # сгенерировать пароль
uv run pm --help                  # справка
```

По умолчанию хранилище лежит в `~/.password_manager/vault.json`.
Другой файл можно указать через `--vault`:

```bash
uv run pm --init --vault ./test.vault.json
```

Пример сессии:

```
$ uv run pm --unlock
Введите мастер-пароль:
Хранилище открыто. Команды: add, list, get, delete, exit
>> add
Введите название сервиса: github
...
```

## Тесты и проверки

```bash
uv run pytest                  # тесты
uv run ruff check .            # линтер
uv run ruff format --check .   # форматирование
uv run mypy                    # проверка типов (strict)
```

## Безопасность хранилища

- **Мастер-пароль не хранится.** В файле лежит только результат Argon2id
  от пароля с солью (`verify_hash`), по нему пароль можно проверить, но нельзя восстановить.
- **Ключ шифрования не хранится.** Он выводится из мастер-пароля при входе
  (Argon2id с другой солью) и живёт только в памяти.
- **Записи шифруются Fernet** (AES-128-CBC + HMAC-SHA256).
- **Ввод мастер-пароля скрыт** (`getpass`), пароль не передаётся аргументом командной строки,
  поэтому не попадает в историю терминала.
- **Пароли генерируются через `secrets`**, а не `random`.
- **Файл хранилища** создаётся с правами `0600` (только владелец) и записывается атомарно
  (временный файл + `os.replace`).

### Почему Argon2id, а не PBKDF2

Argon2id кроме времени требует много памяти (64 МиБ на попытку).
Реализация из библиотеки `cryptography`, поэтому отдельная зависимость не нужна.

## Структура

```
src/password_manager/
├── crypto.py      # Argon2id, Fernet, base64
├── manager.py     # класс PasswordManager: хранилище в JSON
├── generator.py   # генератор паролей
├── cli.py         # argparse, getpass, меню
└── __main__.py    # запуск через python -m password_manager
tests/             # pytest
```

## Источники##

- [OWASP: Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP: Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [cryptography: Fernet — using passwords](https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet)
- [cryptography: Key derivation functions](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/)
- [argparse — документация](https://docs.python.org/3/library/argparse.html)
- [json](https://docs.python.org/3/library/json.html)
