# mediaserver

Сервер для автоматической синхронизации фото/видео с Android по локальной сети.
Принимает файлы по собственному TCP-протоколу, сжимает через FFmpeg и
раскладывает по структуре `YYYY/MM/DD/`.

## Зависимости

```bash
sudo pacman -S ffmpeg rust
```

## Сборка

```bash
# Клонируй или скопируй папку, затем:
cd mediaserver
cargo build --release
```

Бинарник: `target/release/mediaserver`

## Быстрый запуск (для теста)

```bash
# Отредактируй config.toml: укажи media_root и temp_dir
nano config.toml

# Запуск (логи в терминале)
RUST_LOG=info ./target/release/mediaserver config.toml
```

## Установка как systemd-сервис

```bash
# 1. Копируем бинарник
sudo cp target/release/mediaserver /usr/local/bin/

# 2. Создаём директорию конфига
sudo mkdir -p /etc/mediaserver
sudo cp config.toml /etc/mediaserver/

# 3. Редактируем конфиг (укажи свои пути)
sudo nano /etc/mediaserver/config.toml

# 4. Устанавливаем юнит
sudo cp mediaserver.service /etc/systemd/system/
# Замени YOUR_USER на своё имя:
sudo nano /etc/systemd/system/mediaserver.service

# 5. Включаем и запускаем
sudo systemctl daemon-reload
sudo systemctl enable --now mediaserver

# Смотрим логи
sudo journalctl -u mediaserver -f
```

## Структура хранилища

```
/mnt/media/
├── 2025/
│   ├── 05/
│   │   ├── 24/
│   │   │   ├── VID_20250524_120000_1748044800.mp4
│   │   │   └── IMG_20250524_120001_1748044801.jpg
│   │   └── 25/
│   └── 06/
└── .mediaserver.db     ← SQLite индекс
```

## Протокол

Подробное описание — в `src/protocol.rs`.
Клиентская часть (Android/Kotlin) — в директории `android/`.

## Отладка

```bash
# Подробные логи
RUST_LOG=debug ./target/release/mediaserver config.toml

# Запустить тесты
cargo test
```
