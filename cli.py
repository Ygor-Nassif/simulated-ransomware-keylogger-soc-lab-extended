import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from defense.analysis import gerar_relatorio_defensivo
from defense.detection import avaliar_comportamentos
from defense.indicators import extrair_indicadores
from ransomware.decrypto import executar_descriptografia
from ransomware.encryptor import executar_cifragem
from ransomware.file_generator import LAB_TARGET_DIR, LOGS_DIR, gerar_arquivos_ficticios
from ransomware.key_manager import LOG_FILE, carregar_chave, garantir_caminho_seguro, gerar_chave


PROJECT_ROOT = Path(__file__).resolve().parent
KEYS_DIR = (PROJECT_ROOT / "lab" / "keys").resolve()


def _executar_modulo(modulo: str) -> int:
    """Executa um submódulo Python usando o mesmo interpretador ativo."""
    resultado = subprocess.run(
        [sys.executable, "-m", modulo],
        cwd=PROJECT_ROOT,
        check=False,
    )
    return resultado.returncode


def _limpar_diretorio_seguro(alvo: Path, raiz_permitida: Path, manter_dir: bool = True) -> None:
    """Remove o conteúdo de um diretório dentro da raiz permitida sem sair do escopo."""
    seguro = garantir_caminho_seguro(alvo, raiz_permitida)
    if seguro.exists():
        for item in seguro.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
    elif manter_dir:
        seguro.mkdir(parents=True, exist_ok=True)


def cmd_ransomware(args: argparse.Namespace) -> int:
    if args.acao == "gerar":
        gerar_arquivos_ficticios()
        return 0
    if args.acao == "chave":
        try:
            carregar_chave()
            print("Chave AES-256 carregada com sucesso em lab/keys/.")
        except FileNotFoundError:
            gerar_chave()
            print("Chave AES-256 gerada com sucesso em lab/keys/.")
        return 0
    if args.acao == "decifrar":
        executar_descriptografia()
        return 0
    if args.acao == "cifrar":
        try:
            carregar_chave()
        except Exception:
            gerar_chave()
        executar_cifragem()
        return 0
    return 1


def cmd_keylogger(args: argparse.Namespace) -> int:
    if args.acao == "logger":
        return _executar_modulo("keylogger.logger")
    if args.acao == "captura":
        return _executar_modulo("keylogger.capture")
    if args.acao == "simular":
        return _executar_modulo("keylogger.simulator")
    return 1


def cmd_defesa(args: argparse.Namespace) -> int:
    if args.acao == "indicadores":
        dados = extrair_indicadores(arquivo_log=LOG_FILE, diretorio_alvo=LAB_TARGET_DIR)
        print(json.dumps(dados, indent=2, ensure_ascii=False))
        return 0
    if args.acao == "detectar":
        dados = avaliar_comportamentos(arquivo_log=LOG_FILE, diretorio_alvo=LAB_TARGET_DIR)
        print(json.dumps(dados, indent=2, ensure_ascii=False))
        return 0
    if args.acao == "analisar":
        relatorio = gerar_relatorio_defensivo()
        print(f"Nível de risco geral: {relatorio['nivel_risco_geral']}")
        print(f"Total de alertas: {relatorio['resumo_executivo']['total_alertas']}")
        print("Técnicas MITRE ATT&CK observadas:")
        for tec in relatorio["resumo_executivo"]["tecnicas_mitre_observadas"]:
            print(f" - [{tec['tecnica_id']}] {tec['tecnica']} ({tec['tatica']} / {tec['tatica_id']})")
        return 0
    return 1


def cmd_reset(args: argparse.Namespace) -> int:
    """Restaura um estado limpo do laboratório (arquivos de teste, chaves e/ou logs)."""
    if args.arquivos:
        _limpar_diretorio_seguro(LAB_TARGET_DIR, PROJECT_ROOT / "lab")
        gerar_arquivos_ficticios()
        print("Arquivos de teste recriados em lab/test_files/.")

    if args.chaves:
        _limpar_diretorio_seguro(KEYS_DIR, PROJECT_ROOT / "lab")
        print("Chaves de laboratório removidas de lab/keys/.")

    if args.logs:
        _limpar_diretorio_seguro(LOGS_DIR, PROJECT_ROOT)
        print("Artefatos de log/relatório removidos de logs/.")

    if not (args.arquivos or args.chaves or args.logs):
        print("Use --arquivos, --chaves, --logs ou --tudo para resetar o laboratório.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lab-cli",
        description="CLI unificada para o laboratório controlado de simulação ofensiva e análise defensiva.",
    )
    subparsers = parser.add_subparsers(dest="comando", required=True)

    p_ransom = subparsers.add_parser("ransomware", help="Etapas de simulação de ransomware")
    p_ransom.add_argument(
        "acao",
        choices=["gerar", "chave", "cifrar", "decifrar"],
        help="Ação do módulo de ransomware",
    )
    p_ransom.set_defaults(func=cmd_ransomware)

    p_keylog = subparsers.add_parser("keylogger", help="Etapas de simulação de keylogger")
    p_keylog.add_argument(
        "acao",
        choices=["logger", "captura", "simular"],
        help="Ação do módulo de keylogger",
    )
    p_keylog.set_defaults(func=cmd_keylogger)

    p_defesa = subparsers.add_parser("defesa", help="Etapas de indicadores, detecção e relatório")
    p_defesa.add_argument(
        "acao",
        choices=["indicadores", "detectar", "analisar"],
        help="Ação do módulo de defesa",
    )
    p_defesa.set_defaults(func=cmd_defesa)

    p_reset = subparsers.add_parser("reset", help="Limpa/redefine artefatos gerados no laboratório")
    p_reset.add_argument("--arquivos", action="store_true", help="Recria os arquivos fictícios em lab/test_files/")
    p_reset.add_argument("--chaves", action="store_true", help="Remove chaves em lab/keys/")
    p_reset.add_argument("--logs", action="store_true", help="Remove logs e relatórios em logs/")
    p_reset.add_argument(
        "--tudo",
        action="store_true",
        help="Aplica reset completo (arquivos, chaves e logs)",
    )
    p_reset.set_defaults(func=cmd_reset)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.comando == "reset" and getattr(args, "tudo", False):
        args.arquivos = True
        args.chaves = True
        args.logs = True
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())