import json
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ransomware.encryptor import EXTENSAO_CIFRADO, TAMANHO_NONCE
from ransomware.file_generator import LAB_TARGET_DIR, LOGS_DIR, MANIFEST_PATH, calcular_sha256
from ransomware.key_manager import (
    DEFAULT_KEY_FILE,
    carregar_chave,
    garantir_caminho_seguro,
    registrar_evento,
)


class DecryptorError(Exception):
    """Exceção específica para falhas na rotina de descriptografia simulada."""


def listar_arquivos_cifrados(diretorio_alvo: Path = LAB_TARGET_DIR) -> list[Path]:
    """Lista arquivos .enc estritamente dentro de lab/test_files."""
    raiz_segura = garantir_caminho_seguro(diretorio_alvo, LAB_TARGET_DIR)
    if not raiz_segura.exists():
        raise DecryptorError(f"Diretório alvo não encontrado: {raiz_segura}")

    cifrados: list[Path] = []
    for item in raiz_segura.iterdir():
        caminho_seguro = garantir_caminho_seguro(item, raiz_segura)
        if caminho_seguro.is_file() and caminho_seguro.name.endswith(EXTENSAO_CIFRADO):
            cifrados.append(caminho_seguro)

    return sorted(cifrados)


def descriptografar_arquivo(
    arquivo_cifrado: Path,
    chave: bytes,
    raiz_permitida: Path = LAB_TARGET_DIR,
) -> Path:
    """Descriptografa um arquivo .enc usando AES-256-GCM e restaura o nome original."""
    caminho_cifrado = garantir_caminho_seguro(arquivo_cifrado, raiz_permitida)
    if not caminho_cifrado.name.endswith(EXTENSAO_CIFRADO):
        raise DecryptorError(f"Arquivo não possui extensão '{EXTENSAO_CIFRADO}': {caminho_cifrado.name}")

    nome_original = caminho_cifrado.name[: -len(EXTENSAO_CIFRADO)]
    destino_original = garantir_caminho_seguro(
        caminho_cifrado.with_name(nome_original),
        raiz_permitida,
    )

    if len(chave) != 32:
        raise DecryptorError("A chave fornecida deve ter exatamente 32 bytes (AES-256).")

    try:
        conteudo_cifrado_completo = caminho_cifrado.read_bytes()
        if len(conteudo_cifrado_completo) <= TAMANHO_NONCE:
            raise DecryptorError(f"Arquivo cifrado inválido ou truncado: {caminho_cifrado.name}")

        nonce = conteudo_cifrado_completo[:TAMANHO_NONCE]
        ciphertext = conteudo_cifrado_completo[TAMANHO_NONCE:]

        aesgcm = AESGCM(chave)
        dados_claros = aesgcm.decrypt(nonce, ciphertext, None)

        destino_original.write_bytes(dados_claros)
        caminho_cifrado.unlink()

        registrar_evento(
            modulo="decryptor",
            acao="descriptografar_arquivo_sucesso",
            detalhes={
                "arquivo_cifrado": caminho_cifrado.name,
                "arquivo_restaurado": destino_original.name,
                "bytes_restaurados": len(dados_claros),
            },
        )
        return destino_original
    except InvalidTag as exc:
        registrar_evento(
            modulo="decryptor",
            acao="descriptografar_arquivo_erro",
            detalhes={"arquivo": caminho_cifrado.name, "erro": "falha_autenticacao_gcm_ou_chave_invalida"},
        )
        raise DecryptorError(
            f"Falha de autenticação AES-GCM em '{caminho_cifrado.name}' (chave inválida ou dados alterados)."
        ) from exc
    except OSError as exc:
        registrar_evento(
            modulo="decryptor",
            acao="descriptografar_arquivo_erro",
            detalhes={"arquivo": caminho_cifrado.name, "erro": str(exc)},
        )
        raise DecryptorError(f"Falha de E/S ao descriptografar '{caminho_cifrado.name}': {exc}") from exc


def verificar_integridade(
    arquivos_restaurados: list[Path],
    manifesto_path: Path = MANIFEST_PATH,
    raiz_permitida: Path = LAB_TARGET_DIR,
) -> dict[str, bool]:
    """Compara o SHA-256 dos arquivos restaurados com o manifesto baseline_hashes.json."""
    caminho_manifesto = garantir_caminho_seguro(manifesto_path, LOGS_DIR)
    if not caminho_manifesto.exists():
        raise DecryptorError(f"Manifesto de hashes não encontrado: {caminho_manifesto}")

    hashes_esperados: dict[str, str] = json.loads(caminho_manifesto.read_text(encoding="utf-8"))
    resultados: dict[str, bool] = {}

    for arquivo in arquivos_restaurados:
        caminho_seguro = garantir_caminho_seguro(arquivo, raiz_permitida)
        hash_atual = calcular_sha256(caminho_seguro)
        hash_esperado = hashes_esperados.get(caminho_seguro.name)
        integro = hash_esperado is not None and hash_atual == hash_esperado
        resultados[caminho_seguro.name] = integro

        registrar_evento(
            modulo="decryptor",
            acao="verificacao_integridade",
            detalhes={
                "arquivo": caminho_seguro.name,
                "integro": integro,
                "sha256_atual": hash_atual,
                "sha256_esperado": hash_esperado,
            },
        )

    return resultados


def executar_descriptografia(
    diretorio_alvo: Path = LAB_TARGET_DIR,
    caminho_chave: Path = DEFAULT_KEY_FILE,
    manifesto_path: Path = MANIFEST_PATH,
) -> tuple[list[Path], dict[str, bool]]:
    """Executa o fluxo completo de descriptografia e validação de integridade."""
    chave = carregar_chave(caminho_chave)
    cifrados = listar_arquivos_cifrados(diretorio_alvo)

    restaurados: list[Path] = []
    for arquivo_enc in cifrados:
        restaurado = descriptografar_arquivo(arquivo_enc, chave, raiz_permitida=diretorio_alvo)
        restaurados.append(restaurado)

    integridade = verificar_integridade(
        restaurados,
        manifesto_path=manifesto_path,
        raiz_permitida=diretorio_alvo,
    )

    registrar_evento(
        modulo="decryptor",
        acao="execucao_descriptografia_concluida",
        detalhes={
            "total_restaurados": len(restaurados),
            "todos_integros": all(integridade.values()) if integridade else False,
        },
    )
    return restaurados, integridade


if __name__ == "__main__":
    arquivos_ok, status_integridade = executar_descriptografia()
    print(f"Arquivos restaurados ({len(arquivos_ok)}):")
    for arq in arquivos_ok:
        ok = status_integridade.get(arq.name, False)
        estado = "ÍNTEGRO (SHA-256 OK)" if ok else "DIVERGENTE"
        print(f" - {arq.name}: {estado}")