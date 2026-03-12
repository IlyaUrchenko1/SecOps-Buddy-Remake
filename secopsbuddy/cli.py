from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secopsbuddy",
        description="SecOps Buddy: легковесный CLI для детектирования MITRE ATT&CK техник.",
    )

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--list", action="store_true", help="Показать список детекторов")
    action_group.add_argument("--info", metavar="DETECTOR_ID", help="Показать информацию о детекторе")
    action_group.add_argument("--run", metavar="DETECTOR_ID", help="Запустить детектор")

    parser.add_argument(
        "--mode",
        choices=["monitor", "block"],
        default="monitor",
        help="Режим запуска: monitor или block",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Непрерывный мониторинг в цикле",
    )
    parser.add_argument(
        "--monitor-interval-seconds",
        type=float,
        default=None,
        help="Пауза между циклами мониторинга",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=None,
        help="Ограничение числа циклов для continuous режима",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="Путь к YAML-конфигу",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Вывод результата в JSON",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Принудительный dry-run для firewall действий",
    )

    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)
