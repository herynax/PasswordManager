# passman

Локальный офлайн password manager для Linux: зашифрованный vault-файл,
CLI-интерфейс, без сети и бэкендов. Записей, ключей и паролей хостится на
вашей машине.

Криптография: XChaCha20-Poly1305 (AEAD), ключ выводится из мастер-пароля по
Argon2id. Ключ не хранится на диске — он живёт только на время выполнения
одной команды (stateless).

## Что стоит знать перед использованием

- **Мастер-пароль нигде не хранится.** Ключ шифрования выводится из него по
  Argon2id на время выполнения каждой команды и сразу уничтожается
  (stateless). Забыл пароль — данные невосстановимы, «секретного входа» нет.
  Единственный способ восстановления — **резервная копия vault-файла +
  старый пароль**.
- **Делай бэкапы** vault-файла (путь по умолчанию
  `$XDG_DATA_HOME/passman/vault.enc`, обычно
  `~/.local/share/passman/vault.enc`). Файл зашифрован, так что его безопасно
  копировать куда угодно.
- **Длина мастер-пароля — минимум 8 символов.** Чем длиннее — тем лучше (это
  единственный защитный рубеж).
- **`get` автоматически копирует пароль в буфер обмена и очищает его через
  ~15 секунд.** Команды, работающие с содержимым, запрашивают мастер-пароль
  из терминала (без эха).
- **Для буфера нужен `wl-copy` (Wayland) или `xclip` (X11)** — pacman:
  `pacman -S wl-clipboard` или `xclip`. Иначе команды с копированием завершатся
  ошибкой.
- **Защита файла:** шифрование XChaCha20-Poly1305 с привязкой к содержимому
  файла (любое изменение/порча → «authentication failed»), права 0600,
  атомарная запись.
- **Лимиты:** до 10 000 записей, до 32 тегов на запись.
- **Скрипты:** можно передать пароль через переменную окружения
  `PASSMAN_PASSPHRASE` (иначе команда ждёт ввода с tty). Пустая переменная —
  ошибка.
- **Требования:** rust >= 1.98, Wayland (wl-clipboard) или X11 (xclip).

## Установка и сборка

```
git clone <ваш-репозиторий> passman
cd passman
cargo build --release
sudo install -m 0755 target/release/passman /usr/local/bin/passman
```

## Справка по командам

```
passman [OPTIONS] <COMMAND>

Глобальные опции:
  -p, --path <FILE>   Путь к vault-файлу (по умолчанию $XDG_DATA_HOME/passman/vault.enc)
  -h, --help          Справка
  -V, --version       Версия
```

| Команда | Что делает | Пример |
|---|---|---|
| `init` | Создать новый (пустой) vault; дважды ввести мастер-пароль | `passman init` |
| `status` | Метаданные vault без расшифровки (путь, vault id, ключевые слоты) | `passman status` |
| `add` | Добавить запись; тип `login` (по умолч.) или `note`; недостающее спросит интерактивно | `passman add --title GitHub --username u --password s3cret --url https://github.com --tags dev,work` |
| `get` | Показать запись по id/названию; пароль копируется в буфер и автоочищается через 15 с | `passman get GitHub` |
| `list` | Все записи (id, тип, название, теги) | `passman list` |
| `search` | Поиск по названию или тегу (без учёта регистра) | `passman search work` |
| `update` | Изменить поля записи по id/названию | `passman update GitHub --url https://github.com/octocat` |
| `rm` | Удалить запись по id/названию | `passman rm GitHub` |
| `generate` | Сгенерировать случайный пароль (по умолч. 20 симв.) | `passman generate --length 24 --copy` |
| `pass` | Сменить мастер-пароль | `passman pass` |
| `backup` | Скопировать vault в файл/директорию (сначала проверит пароль); существующий файл перезаписывается | `passman backup /mnt/flash/` |

### Важные флаги

- `get`: `--reveal` — напечатать пароль в терминал (иначе скрыт и копируется),
  `--no-copy` — не копировать в буфер.
- `generate`: `--length N` (8..128, по умолч. 20), `--no-symbols` (только
  буквы/цифры), `--ambiguous` (включает 0O1lI|…), `--copy` (в буфер с
  автоочисткой).
- `add`/`update`: `--tags` — теги через запятую.
- `backup`: аргумент — путь. Заканчивается на `/` или указывает на существующую
  директорию → в неё пишется `passman-vault-backup.enc`; иначе аргумент считается
  именем файла (перезаписывается при повторном вызове). Перед копированием
  команда расшифровывает vault мастер-паролем (проверка ключа и целостности),
  затем проверяет записанные байты.

## Quick start

```
$ passman init
New master password: ********
Confirm master password: ********
vault created: /home/you/.local/share/passman/vault.enc

$ passman add --title GitHub --type login
Username: octocat
Password: ********
Confirm password: ********
URL (optional): https://github.com
saved login 'GitHub'

$ passman list
ID              TYPE   TITLE   TAGS
991ab207        login  GitHub  dev, work

$ passman get GitHub  → пароль скопирован в буфер, очистится через 15 с
```

Полная справка по любой команде: `passman <команда> --help`.

## Разработка

- `cargo test` — тесты (криптография, формат vault, CLI end-to-end).
- `cargo clippy --all-targets` и `cargo fmt --check` — статический анализ.
- `cargo audit` — проверка зависимостей на известные уязвимости.