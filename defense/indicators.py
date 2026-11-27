from collections import Counter
import json
from pathlib import Path
from ransomware.encryptor import NOME_RESGATE
from ransomware.file_generator import LAB_TARGET_DIR, LOGS_DIR
from ransomware.key_manager import LOG_FILE, garantir_caminho_seguro

class IndicatorsError(Exception):
    """Exceção específica para falhas na extração de indicadores do laboratório."""


def ler_eventos_log(arquivo_log: Path = LOG_FILE) -> list[dict]:
    """Lê eventos JSON Lines de lab_operations.log de forma segura."""
    destino = garantir_caminho_seguro(arquivo_log, LOGS_DIR)
    if not destino.exists():
        return []

    eventos: list[dict] = []
    for linha in destino.read_text(encoding="utf-8").splitlines():
        texto = linha.strip()
        if not texto:
            continue
        try:
            item = json.loads(texto)
            if isinstance(item, dict):
                eventos.append(item)
        except json.JSONDecodeError:
            continue
    return eventos


def extrair_iocs_ficheiros(diretorio_alvo: Path = LAB_TARGET_DIR) -> dict:
    """Identifica artefactos observados no diretório de testes e em logs/."""
    raiz_lab = garantir_caminho_seguro(diretorio_alvo, LAB_TARGET_DIR.parent)
    raiz_logs = garantir_caminho_seguro(LOGS_DIR, LOGS_DIR)

    ficheiros_enc: list[str] = []
    nota_resgate_presente = False

    if raiz_lab.exists():
        for item in raiz_lab.rglob("*"):
            if not item.is_file():
                continue
            if item.suffix == ".enc":
                ficheiros_enc.append(item.name)
            if item.name == NOME_RESGATE:
                nota_resgate_presente = True

    artefactos_logs = {
        "lab_operations_log": (raiz_logs / "lab_operations.log").exists(),
        "keylogger_simulado_txt": (raiz_logs / "keylogger_simulado.txt").exists(),
        "sim_persistence_json": (raiz_logs / "sim_persistence.json").exists(),
        "baseline_hashes_json": (raiz_logs / "baseline_hashes.json").exists(),
    }

    return {
        "ficheiros_cifrados_enc": sorted(ficheiros_enc),
        "nota_resgate_presente": nota_resgate_presente,
        "artefactos_logs": artefactos_logs,
    }


def extrair_indicadores(
    arquivo_log: Path = LOG_FILE,
    diretorio_alvo: Path = LAB_TARGET_DIR,
) -> dict:
    """Consolida indicadores extraídos dos logs e dos diretórios do laboratório."""
    eventos = ler_eventos_log(arquivo_log)
    contagens_acao = Counter(ev.get("acao", "desconhecida") for ev in eventos)
    contagens_modulo = Counter(ev.get("modulo", "desconhecido") for ev in eventos)

    destinos_rede: list[str] = []
    total_teclas_sessoes = 0

    for ev in eventos:
        acao = ev.get("acao", "")
        detalhes = ev.get("detalhes") or {}
        if not isinstance(detalhes, dict):
            continue

        if acao in {"simular_transmissao_sucesso", "simular_transmissao_sem_receptor"}:
            destino = detalhes.get("destino")
            if destino and destino not in destinos_rede:
                destinos_rede.append(str(destino))

        if acao == "sessao_captura_encerrada":
            qtd = detalhes.get("total_teclas", 0)
            if isinstance(qtd, int):
                total_teclas_sessoes += qtd

    iocs_ficheiros = extrair_iocs_ficheiros(diretorio_alvo)

    return {
        "total_eventos_log": len(eventos),
        "por_modulo": dict(contagens_modulo),
        "por_acao": dict(contagens_acao),
        "destinos_rede_simulados": destinos_rede,
        "total_teclas_registadas_em_sessoes": total_teclas_sessoes,
        "artefactos": iocs_ficheiros,
    }


if __name__ == "__main__":
    relatorio = extrair_indicadores()
    print(json.dumps(relatorio, indent=2, ensure_ascii=False))