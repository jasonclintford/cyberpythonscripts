from rich.console import Console

from .theme import build_theme

console = Console(theme=build_theme())
