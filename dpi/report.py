"""ASCII report formatting helpers."""

from __future__ import annotations

WIDTH = 62


def banner(title: str) -> None:
    line = "+" + "-" * WIDTH + "+"
    print()
    print(line)
    print(f"| {title:<{WIDTH - 2}} |")
    print(line)
    print()


def section(title: str) -> None:
    line = "+" + "-" * WIDTH + "+"
    print(line)
    print(f"| {title:<{WIDTH - 2}} |")
    print(line)


def row(label: str, value: str | int) -> None:
    content = f"{label}{value}"
    print(f"| {content:<{WIDTH - 2}} |")


def footer() -> None:
    print("+" + "-" * WIDTH + "+")
