# JKS PEM Telegram Bot

## Requirements

- Python 3.10+
- OpenJDK (keytool)
- OpenSSL

On Ubuntu:

```
sudo apt-get update
sudo apt-get install -y openjdk-17-jre-headless openssl
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
- Or send a JKS/keystore file with optional text:
  - line1: alias
  - line2: password (store + key)
  - defaults: alias=key0, password=1234567890

Generated keystore metadata uses realistic English data (name, company, city, state, country code)
via Faker.

## Commands

- /help
- /status

## Logs

Logs are written to `logs/bot.log`.
