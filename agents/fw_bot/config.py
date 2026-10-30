"""Config: paths, secrets from env, owner-id loading. Python 3.13, stdlib only."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

# Control API endpoint (loopback only, see docs/REFERENCE.md)
CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 5380
CONTROL_BASE = f"http://{CONTROL_HOST}:{CONTROL_PORT}"
HTTP_TIMEOUT = 5.0

# Alert grouping defaults
GROUP_WINDOW_MINUTES_DEFAULT = 10

# Telegram Bot API base; tests point this at a fake server.
TELEGRAM_API_DEFAULT = "https://api.telegram.org"

SEVERITY_ORDER = {"info": 0, "warn": 1, "high": 2, "critical": 3}
SEVERITIES = ("info", "warn", "high", "critical")


class ConfigError(Exception):
    """Missing or malformed configuration."""


def _secret_from_env(env: dict | None = None, name: str = "FW_BOT_CALLBACK_SECRET") -> bytes:
    env = os.environ if env is None else env
    val = env.get(name, "")
    if not val:
        raise ConfigError(
            f"missing callback signing secret; set {name} in the environment"
        )
    return val.encode("utf-8")


@dataclass
class Config:
    """Runtime configuration for fw_bot."""

    owner_chat_id: int | int
    owner_file: str = ""
    labels_path: str = "labels.jsonl"
    digest_path: str = "digest.jsonl"
    control_base: str = CONTROL_BASE
    telegram_api: str = TELEGRAM_API_DEFAULT
    telegram_token: str = ""
    group_window_minutes: int = GROUP_WINDOW_MINUTES_DEFAULT
    secret: bytes = b""
    extra: dict = field(default_factory=dict)

    @classmethod
    def load(
        cls,
        owner_path: str,
        *,
        env: dict | None = None,
        labels_path: str = "labels.jsonl",
        digest_path: str = "digest.jsonl",
        control_base: str = CONTROL_BASE,
        telegram_api: str | None = None,
        telegram_token: str | None = None,
        group_window_minutes: int | None = None,
    ) -> "Config":
        env = os.environ if env is None else env
        secret = _secret_from_env(env)
        token_env = env.get("FW_BOT_TELEGRAM_TOKEN", "")
        api_env = env.get("FW_BOT_TELEGRAM_API", "")
        window_env = env.get("FW_BOT_GROUP_WINDOW_MINUTES", "")
        try:
            window = (
                int(window_env)
                if window_env
                else (GROUP_WINDOW_MINUTES_DEFAULT if group_window_minutes is None else group_window_minutes)
            )
        except ValueError as exc:
            raise ConfigError("FW_BOT_GROUP_WINDOW_MINUTES must be an integer") from exc
        if window < 1:
            raise ConfigError("group window must be >= 1 minute")

        with open(owner_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # owner.json is {"chat_id": <int>, "user": <str>}; "owner_chat_id" is the fallback.
        if "chat_id" in data:
            owner = data["chat_id"]
        elif "owner_chat_id" in data:
            owner = data["owner_chat_id"]
        else:
            raise ConfigError(
                f"{owner_path}: missing owner id (need 'chat_id' or 'owner_chat_id')"
            )
        if isinstance(owner, bool) or not isinstance(owner, int):
            raise ConfigError(
                f"{owner_path}: owner id must be an integer (got {type(owner).__name__})"
            )
        cfg = cls(
            owner_chat_id=owner,
            owner_file=owner_path,
            labels_path=labels_path,
            digest_path=digest_path,
            control_base=control_base,
            telegram_api=telegram_api or api_env or TELEGRAM_API_DEFAULT,
            telegram_token=telegram_token if telegram_token is not None else token_env,
            group_window_minutes=window,
            secret=secret,
            extra={k: v for k, v in data.items() if k not in ("owner_chat_id", "chat_id")},
        )
        return cfg

    def is_owner(self, chat_id: int | None) -> bool:
        """Only the owner chat id may issue commands or press buttons."""
        if chat_id is None or isinstance(chat_id, bool):
            return False
        return chat_id == self.owner_chat_id
