"""
AASM Enterprise Logging
Structured logging with Rich integration.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

AASM_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "debug": "dim white",
    "highlight": "bold magenta",
    "finding": "bold yellow",
    "critical_finding": "bold red",
})

console = Console(theme=AASM_THEME, stderr=False)
err_console = Console(theme=AASM_THEME, stderr=True)


def setup_logging(level: str = "INFO", log_file: str | None = None) -> None:
    handlers: list[logging.Handler] = [
        RichHandler(
            console=err_console,
            show_time=False,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
    ]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"aasm.{name}")
