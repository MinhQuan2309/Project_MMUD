import os
from pathlib import Path
from typing import Optional

import hvac


def _read_file_if_exists(path: str) -> Optional[str]:
    try:
        p = Path(path)
        if p.exists() and p.is_file():
            value = p.read_text(encoding="utf-8").strip()
            return value or None
    except Exception:
        return None
    return None


def get_secret_from_vault_or_file(secret_name: str) -> str:
    """
    Priority:
    1. Docker secret file: /run/secrets/<secret_name_lower>
    2. HashiCorp Vault KV v2: secret/project-mmud
    3. Env fallback only when ALLOW_ENV_SECRET_FALLBACK=true for local debug

    Không hardcode secret trong source code.
    Không log giá trị secret/token.
    """
    normalized_file_name = secret_name.lower()
    explicit_file = os.getenv(f"{secret_name}_FILE")
    candidate_files = [
        explicit_file,
        f"/run/secrets/{normalized_file_name}",
        f"/run/secrets/{secret_name}",
    ]

    for candidate in candidate_files:
        if candidate:
            value = _read_file_if_exists(candidate)
            if value:
                print(f"✅ Loaded {secret_name} from Docker secret file")
                return value

    vault_addr = os.getenv("VAULT_ADDR")
    vault_mount = os.getenv("VAULT_SECRET_MOUNT", "secret")
    vault_path = os.getenv("VAULT_SECRET_PATH", "project-mmud")
    vault_token = os.getenv("VAULT_TOKEN") or _read_file_if_exists("/run/secrets/vault_token")

    if vault_addr and vault_token:
        print(f"🔒 Loading {secret_name} from HashiCorp Vault path {vault_mount}/{vault_path}")
        try:
            client = hvac.Client(url=vault_addr, token=vault_token)

            if not client.is_authenticated():
                raise RuntimeError("Vault token is not authenticated")

            response = client.secrets.kv.v2.read_secret_version(
                mount_point=vault_mount,
                path=vault_path,
            )
            data = response["data"]["data"]
            value = data.get(secret_name)

            if not value:
                raise RuntimeError(f"{secret_name} not found in Vault")

            print(f"✅ Loaded {secret_name} from Vault")
            return value

        except Exception as exc:
            raise RuntimeError(f"Cannot load {secret_name} from Vault: {exc}") from exc

    allow_env = os.getenv("ALLOW_ENV_SECRET_FALLBACK", "false").lower() == "true"
    if allow_env:
        value = os.getenv(secret_name)
        if value:
            print(f"⚠️ Loaded {secret_name} from env fallback for local demo")
            return value

    raise RuntimeError(
        f"Missing required secret {secret_name}. "
        "Use Docker secret, Vault, or ALLOW_ENV_SECRET_FALLBACK=true for local demo."
    )
