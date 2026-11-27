from datetime import datetime, timezone
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BASE_DIR = Path(__file__).resolve().parent.parent
LAB_DIR = (BASE_DIR / "lab").resolve()
KEYS_DIR = (LAB_DIR / "keys").resolve()
LOGS_DIR = (BASE_DIR / "logs").resolve()

LOG_FILE = (LOGS_DIR / "lab_operations.log").resolve()
DEFAULT_KEY_FILE = (KEYS_DIR / "aes256_lab.key").resolve()


class KeyManagerError(Exception):
    """Exceção específica para falhas no gerenciamento de chaves do laboratório."""


def garantir_caminho_seguro(caminho: Path, raiz_permitida: Path) -> Path:
    """Garante que o caminho resolvido permanece dentro do diretório permitido."""
    caminho_resolvido = caminho.resolve()
    raiz_resolvida = raiz_permitida.resolve()
    if not caminho_resolvido.is_relative_to(raiz_resolvida):
        raise ValueError(f"Acesso bloqueado fora do diretório permitido: {caminho_resolvido}")
    return caminho_resolvido


def registrar_evento(modulo: str, acao: str, detalhes: dict | None = None) -> Path:
    """Registra um evento do laboratório em formato JSON Lines dentro de logs/."""
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    destino_log = garantir_caminho_seguro(LOG_FILE, LOGS_DIR)

    registro = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "modulo": modulo,
        "acao": acao,
        "detalhes": detalhes or {},
    }

    with destino_log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(registro, ensure_ascii=False) + "\n")

    return destino_log


def gerar_chave(caminho_chave: Path = DEFAULT_KEY_FILE, sobrescrever: bool = False) -> Path:
    """Gera uma chave AES-256 segura e a salva em lab/keys/."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    destino_seguro = garantir_caminho_seguro(caminho_chave, KEYS_DIR)

    if destino_seguro.exists() and not sobrescrever:
        registrar_evento(
            modulo="key_manager",
            acao="gerar_chave_ignorada",
            detalhes={"arquivo_chave": destino_seguro.name, "motivo": "chave_ja_existente"},
        )
        return destino_seguro

    try:
        chave = AESGCM.generate_key(bit_length=256)
        with destino_seguro.open("wb") as chave_file:
            chave_file.write(chave)
        os.chmod(destino_seguro, 0o600)

        registrar_evento(
            modulo="key_manager",
            acao="gerar_chave_sucesso",
            detalhes={"arquivo_chave": destino_seguro.name, "bits": 256},
        )
        return destino_seguro
    except OSError as exc:
        registrar_evento(
            modulo="key_manager",
            acao="gerar_chave_erro",
            detalhes={"arquivo_chave": destino_seguro.name, "erro": str(exc)},
        )
        raise KeyManagerError(f"Falha ao gravar a chave AES-256: {exc}") from exc


def carregar_chave(caminho_chave: Path = DEFAULT_KEY_FILE) -> bytes:
    """Carrega e valida a chave AES-256 (32 bytes) a partir de lab/keys/."""
    destino_seguro = garantir_caminho_seguro(caminho_chave, KEYS_DIR)

    if not destino_seguro.exists():
        registrar_evento(
            modulo="key_manager",
            acao="carregar_chave_erro",
            detalhes={"arquivo_chave": destino_seguro.name, "motivo": "arquivo_nao_encontrado"},
        )
        raise KeyManagerError(f"Chave não encontrada em: {destino_seguro}")

    try:
        chave = destino_seguro.read_bytes()
    except OSError as exc:
        registrar_evento(
            modulo="key_manager",
            acao="carregar_chave_erro",
            detalhes={"arquivo_chave": destino_seguro.name, "erro": str(exc)},
        )
        raise KeyManagerError(f"Falha ao ler a chave: {exc}") from exc

    if len(chave) != 32:
        registrar_evento(
            modulo="key_manager",
            acao="carregar_chave_erro",
            detalhes={"arquivo_chave": destino_seguro.name, "tamanho_bytes": len(chave)},
        )
        raise KeyManagerError(f"Tamanho de chave inválido para AES-256: {len(chave)} bytes (esperado 32)")

    registrar_evento(
        modulo="key_manager",
        acao="carregar_chave_sucesso",
        detalhes={"arquivo_chave": destino_seguro.name, "bits": 256},
    )
    return chave


if __name__ == "__main__":
    arquivo_gerado = gerar_chave()
    chave_carregada = carregar_chave(arquivo_gerado)
    print(f"Chave gerada/carregada em: {arquivo_gerado}")
    print(f"Tamanho da chave: {len(chave_carregada) * 8} bits")
    print(f"Log registrado em: {LOG_FILE}")