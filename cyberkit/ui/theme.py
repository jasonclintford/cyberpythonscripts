from rich.theme import Theme


def build_theme() -> Theme:
    return Theme(
        {
            "accent": "bold cyan",
            "warning": "bold yellow",
            "danger": "bold red",
            "ok": "bold green",
            "muted": "grey70",
            "title": "bold bright_white",
        }
    )
