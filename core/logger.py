import logging
import sys
from datetime import datetime
from pathlib import Path
from rich.logging import RichHandler
from rich.console import Console

console = Console()


def setup_logger(name: str = "redscope", level: str = "INFO", log_file: bool = False) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if logger.handlers:
        return logger

    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
    )
    rich_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(rich_handler)

    if log_file:
        log_dir = Path("output/logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_handler = logging.FileHandler(log_dir / f"redscope_{ts}.log")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        logger.addHandler(file_handler)

    return logger


log = setup_logger()
