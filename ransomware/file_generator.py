from pathlib import Path
import hashlib
import json


BASE_DIR = Path(__file__).resolve().parent.parent
LAB_TARGET_DIR = (BASE_DIR / "lab" / "test_files").resolve()
LOGS_DIR = (BASE_DIR / "logs").resolve()
MANIFEST_PATH = (LOGS_DIR / "baseline_hashes.json").resolve()


def garantir_caminho_seguro(caminho: Path, raiz_permitida: Path) -> Path:
    """Garante que o caminho resolvido permanece dentro do diretório permitido."""
    caminho_resolvido = caminho.resolve()
    raiz_resolvida = raiz_permitida.resolve()
    if not caminho_resolvido.is_relative_to(raiz_resolvida):
        raise ValueError(f"Acesso bloqueado fora do escopo do laboratório: {caminho_resolvido}")
    return caminho_resolvido


def calcular_sha256(arquivo: Path) -> str:
    """Calcula o hash SHA-256 de um arquivo."""
    digest = hashlib.sha256()
    with arquivo.open("rb") as f:
        for bloco in iter(lambda: f.read(8192), b""):
            digest.update(bloco)
    return digest.hexdigest()


def gerar_arquivos_ficticios() -> dict[str, str]:
    """Cria arquivos fictícios de teste e retorna o mapa de hashes SHA-256."""
    LAB_TARGET_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    arquivos_ficticios = {
        "dados-confidenciais.txt": "Documento ficticio de laboratorio - registro #001\n",
        "senhas.txt": "Credencial ficticia de teste: user_lab / senha_ficticia_123\n",
        "relatorio_trimestral.txt": "Dados simulados para validacao de integridade.\n",
    }

    hashes: dict[str, str] = {}
    for nome, conteudo in arquivos_ficticios.items():
        destino = garantir_caminho_seguro(LAB_TARGET_DIR / nome, LAB_TARGET_DIR)
        destino.write_text(conteudo, encoding="utf-8")
        hashes[nome] = calcular_sha256(destino)

    manifesto_seguro = garantir_caminho_seguro(MANIFEST_PATH, LOGS_DIR)
    manifesto_seguro.write_text(json.dumps(hashes, indent=2), encoding="utf-8")
    return hashes


if __name__ == "__main__":
    resultado = gerar_arquivos_ficticios()
    print(f"Arquivos fictícios criados em: {LAB_TARGET_DIR}")
    for arquivo, sha in resultado.items():
        print(f" - {arquivo}: {sha[:16]}...")
