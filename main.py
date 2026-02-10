import asyncio
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional, Tuple

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import FSInputFile, InputMediaDocument, Message
from faker import Faker


DEFAULT_PASSWORD = "1234567890"
DEFAULT_ALIAS = "key0"
KEY_VALIDITY_DAYS = "36500"
LOG_PATH = os.path.join("logs", "bot.log")


class PendingFile(StatesGroup):
    waiting_alias = State()
    waiting_password = State()


@dataclass
class FileRequest:
    file_id: str
    filename: str
    alias: Optional[str] = None
    password: Optional[str] = None


router = Router()
faker = Faker("en_US")


def _sanitize_name(value: str) -> str:
    value = value.strip()
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return value or "keystore"


def _parse_alias_password(text: str) -> Tuple[Optional[str], Optional[str]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None, None
    alias = lines[0] if len(lines) >= 1 else None
    password = lines[1] if len(lines) >= 2 else None
    return alias, password


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _setup_logging() -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(LOG_PATH, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )


@dataclass
class DNameInfo:
    first_name: str
    last_name: str
    organization_unit: str
    organization: str
    city: str
    state: str
    country_code: str


def _random_dname_info() -> DNameInfo:
    profile = faker.simple_profile()
    first_name = profile["name"].split(" ")[0]
    last_name = profile["name"].split(" ")[-1]
    organization = faker.company()
    organization_unit = faker.job().split(",")[0]
    city = faker.city()
    state = faker.state()
    country_code = faker.country_code(representation="alpha-2")
    return DNameInfo(
        first_name=first_name,
        last_name=last_name,
        organization_unit=organization_unit,
        organization=organization,
        city=city,
        state=state,
        country_code=country_code,
    )


def _random_dname(dname_info: DNameInfo) -> str:
    def esc(value: str) -> str:
        return value.replace("\\", "\\\\").replace(",", "\\,")

    common_name = f"{dname_info.first_name} {dname_info.last_name}"
    company = dname_info.organization
    unit = dname_info.organization_unit
    city = dname_info.city
    state = dname_info.state
    country_code = dname_info.country_code
    return (
        f"CN={esc(common_name)}, OU={esc(unit)}, O={esc(company)}, "
        f"L={esc(city)}, S={esc(state)}, C={esc(country_code)}"
    )


def _generate_jks(
    target_path: str, package_name: str, alias: str, password: str, dname: str
) -> None:
    _run(
        [
            "keytool",
            "-genkeypair",
            "-alias",
            alias,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            KEY_VALIDITY_DAYS,
            "-keystore",
            target_path,
            "-storepass",
            password,
            "-keypass",
            password,
            "-dname",
            dname,
        ]
    )


def _jks_to_pem(jks_path: str, alias: str, password: str, pem_path: str) -> None:
    p12_path = os.path.splitext(jks_path)[0] + ".p12"
    _run(
        [
            "keytool",
            "-importkeystore",
            "-srckeystore",
            jks_path,
            "-srcstoretype",
            "JKS",
            "-srcstorepass",
            password,
            "-destkeystore",
            p12_path,
            "-deststoretype",
            "PKCS12",
            "-deststorepass",
            password,
            "-srcalias",
            alias,
            "-destalias",
            alias,
            "-srckeypass",
            password,
            "-destkeypass",
            password,
        ]
    )
    _run(
        [
            "openssl",
            "pkcs12",
            "-in",
            p12_path,
            "-nodes",
            "-passin",
            f"pass:{password}",
            "-out",
            pem_path,
        ]
    )


def _split_dn(owner: str) -> list[str]:
    parts = []
    current = []
    escaped = False
    for ch in owner:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == ",":
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _unescape_dn(value: str) -> str:
    return value.replace("\\,", ",").replace("\\\\", "\\").strip()


def _read_dname_from_jks(jks_path: str, alias: str, password: str) -> Optional[DNameInfo]:
    cmd = [
        "keytool",
        "-list",
        "-v",
        "-keystore",
        jks_path,
        "-storepass",
        password,
        "-alias",
        alias,
    ]
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    owner = None
    for line in result.stdout.decode("utf-8", errors="ignore").splitlines():
        if line.strip().startswith("Owner:"):
            owner = line.split("Owner:", 1)[1].strip()
            break
    if not owner:
        return None
    parts = {}
    for item in _split_dn(owner):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        parts[key.strip()] = _unescape_dn(value)
    if not parts:
        return None
    common_name = parts.get("CN", "")
    first_name = common_name.split(" ")[0] if common_name else ""
    last_name = common_name.split(" ")[-1] if common_name else ""
    state = parts.get("S") or parts.get("ST") or ""
    return DNameInfo(
        first_name=first_name,
        last_name=last_name,
        organization_unit=parts.get("OU", ""),
        organization=parts.get("O", ""),
        city=parts.get("L", ""),
        state=state,
        country_code=parts.get("C", ""),
    )


def _format_info(dname_info: Optional[DNameInfo], alias: str, password: str) -> str:
    if not dname_info:
        dname_info = DNameInfo(
            first_name="",
            last_name="",
            organization_unit="",
            organization="",
            city="",
            state="",
            country_code="",
        )
    def val(value: str) -> str:
        return value if value else "-"

    return (
        "Данные ключа:\n"
        f"First name: {val(dname_info.first_name)}\n"
        f"Last name: {val(dname_info.last_name)}\n"
        f"Organization unit: {val(dname_info.organization_unit)}\n"
        f"Organization: {val(dname_info.organization)}\n"
        f"City: {val(dname_info.city)}\n"
        f"State: {val(dname_info.state)}\n"
        f"Country code: {val(dname_info.country_code)}\n"
        f"\nAlias: {alias}\n"
        f"Password: {password}"
    )


async def _download_file(bot: Bot, file_id: str, target_path: str) -> None:
    file = await bot.get_file(file_id)
    await bot.download_file(file.file_path, target_path)


async def _process_request(
    bot: Bot,
    message: Message,
    *,
    package_name: Optional[str] = None,
    file_req: Optional[FileRequest] = None,
) -> None:
    if package_name is None and file_req is None:
        await message.answer("Нет входных данных.")
        return

    alias = DEFAULT_ALIAS
    password = DEFAULT_PASSWORD
    dname_info = None

    try:
        with tempfile.TemporaryDirectory(prefix="jksbot_") as temp_dir:
            if package_name:
                alias = DEFAULT_ALIAS
                password = DEFAULT_PASSWORD
                base_name = _sanitize_name(package_name)
                jks_path = os.path.join(temp_dir, f"{base_name}.jks")
                dname_info = _random_dname_info()
                dname = _random_dname(dname_info)
                _generate_jks(jks_path, package_name, alias, password, dname)
            else:
                alias = file_req.alias or DEFAULT_ALIAS
                password = file_req.password or DEFAULT_PASSWORD
                base_name = _sanitize_name(os.path.splitext(file_req.filename)[0])
                jks_path = os.path.join(temp_dir, f"{base_name}.jks")
                await _download_file(bot, file_req.file_id, jks_path)

            pem_path = os.path.join(temp_dir, f"{base_name}.pem")
            _jks_to_pem(jks_path, alias, password, pem_path)

            if not dname_info:
                dname_info = _read_dname_from_jks(jks_path, alias, password)

            info = _format_info(dname_info, alias, password)

            media = [
                InputMediaDocument(media=FSInputFile(jks_path), caption=info),
                InputMediaDocument(media=FSInputFile(pem_path)),
            ]
            await message.answer_media_group(media)
    except FileNotFoundError:
        logging.exception("Missing system dependency")
        await message.answer(
            "Системная ошибка: не найден keytool/openssl. Установите OpenJDK и OpenSSL."
        )
    except subprocess.CalledProcessError as exc:
        logging.exception("Command failed: %s", exc)
        await message.answer(
            "Не удалось обработать кейстор. "
            "Проверьте alias/password, тип файла или пароль кейстора."
        )
    except Exception:
        logging.exception("Unhandled error")
        await message.answer("Непредвиденная ошибка. Попробуйте позже.")


@router.message(CommandStart())
async def start_handler(message: Message) -> None:
    await message.answer(
        "Отправь имя пакета текстом — сгенерирую новый JKS и PEM.\n"
        "Или отправь JKS/keystore файл с подписью:\n"
        "строка 1: alias\n"
        "строка 2: пароль (store + key)\n"
        f"По умолчанию: alias={DEFAULT_ALIAS}, password={DEFAULT_PASSWORD}"
    )


@router.message(F.text == "/help")
async def help_handler(message: Message) -> None:
    await message.answer(
        "Как пользоваться:\n"
        "1) Отправь имя пакета текстом — сгенерирую новый JKS + PEM.\n"
        "2) Или отправь JKS/keystore файл с подписью:\n"
        "   строка 1: alias\n"
        "   строка 2: пароль (store + key)\n"
        f"По умолчанию: alias={DEFAULT_ALIAS}, password={DEFAULT_PASSWORD}"
    )


@router.message(F.text == "/status")
async def status_handler(message: Message) -> None:
    await message.answer("OK")


@router.message(F.document)
async def document_handler(message: Message, state: FSMContext, bot: Bot) -> None:
    caption = message.caption or ""
    alias, password = _parse_alias_password(caption)
    file_req = FileRequest(
        file_id=message.document.file_id,
        filename=message.document.file_name or "keystore.jks",
        alias=alias,
        password=password,
    )
    if not alias:
        await state.set_state(PendingFile.waiting_alias)
        await state.update_data(file_req=file_req)
        await message.answer("Отправь alias (строка 1).")
        return
    if not password:
        await state.set_state(PendingFile.waiting_password)
        await state.update_data(file_req=file_req)
        await message.answer("Отправь пароль (строка 2).")
        return
    await _process_request(bot, message, file_req=file_req)


@router.message(PendingFile.waiting_alias)
async def alias_handler(message: Message, state: FSMContext, bot: Bot) -> None:
    if not message.text or not message.text.strip():
        await message.answer("Нужен alias. Отправь alias (строка 1).")
        return
    data = await state.get_data()
    file_req: FileRequest = data["file_req"]
    file_req.alias = message.text.strip()
    await state.update_data(file_req=file_req)
    await state.set_state(PendingFile.waiting_password)
    await message.answer("Отправь пароль (строка 2).")


@router.message(PendingFile.waiting_password)
async def password_handler(message: Message, state: FSMContext, bot: Bot) -> None:
    if not message.text or not message.text.strip():
        await message.answer("Нужен пароль. Отправь пароль (строка 2).")
        return
    data = await state.get_data()
    file_req: FileRequest = data["file_req"]
    file_req.password = message.text.strip()
    await state.clear()
    await _process_request(bot, message, file_req=file_req)


@router.message(F.text)
async def text_handler(message: Message, bot: Bot) -> None:
    package_name = message.text.strip()
    if not package_name:
        await message.answer("Отправь непустое имя пакета.")
        return
    await _process_request(bot, message, package_name=package_name)


async def main() -> None:
    _setup_logging()
    token = os.getenv("BOT_TOKEN")
    if not token:
        raise RuntimeError("BOT_TOKEN env var is required.")

    bot = Bot(token=token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher()
    dp.include_router(router)

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
