# JKS PEM Telegram Bot

## Requirements

- Python 3.10+
- OpenJDK (keytool)

On Ubuntu:

```
sudo apt-get update
sudo apt-get install -y openjdk-17-jre-headless
```

## Install

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```
export BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"
python main.py
```

## Usage

- Send a package name as text to generate a new JKS and PEM.
- If a key for this package already exists, bot asks:
  - `1` reuse existing key
  - `2` generate a new key
- Or send a JKS/keystore file with optional text:
  - line1: alias
  - line2: password (store + key)
  - defaults: alias=key0, password=1234567890

Generated keystore metadata uses realistic English data (name, company, city, state, country code)
via Faker.

## Storage

- Current files are saved to `generated/<package>/`:
  - `<package>.jks`
  - `<package>.pem` (certificate-only, Google Play compatible)
  - `info.txt`
  - `user.txt`
- On overwrite, previous package folder is moved to `generated_old/`:
  - first archive: `generated_old/<package>/`
  - next archives: `generated_old/<package>-1/`, `generated_old/<package>-2/`, ...

## Commands

- `/start` - Shows quick usage: how to generate from package name or convert uploaded JKS/keystore.
- `/help` - Shows detailed usage and required inputs (`alias`, `password`).
- `/status` - Health check endpoint, currently returns `OK` (bot is running).

## Logs

Logs are written to `logs/bot.log`.
