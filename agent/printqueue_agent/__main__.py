"""Entry point: ``python -m printqueue_agent [--config PATH]``."""

from __future__ import annotations

import argparse
import logging
import sys

from .agent import Agent
from .config import AgentConfig
from .serial_printer import list_serial_ports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print-queue printer agent (LK5 Pro / Marlin)")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--list-ports", action="store_true", help="List serial ports and exit")
    parser.add_argument("--doctor", action="store_true",
                        help="Run connection diagnostics (pinpoints why the printer isn't talking) and exit")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    if args.list_ports:
        ports = list_serial_ports()
        if ports:
            print("Available serial ports:")
            for p in ports:
                print(f"  {p}")
        else:
            print("No serial ports found.")
        return 0

    try:
        cfg = AgentConfig.load(args.config)
    except Exception as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2

    if args.doctor:
        from .diagnostics import run as run_doctor
        print(run_doctor(cfg))
        return 0

    Agent(cfg, config_path=args.config).run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
