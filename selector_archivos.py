#!/usr/bin/env python3
"""Selector nativo aislado para la interfaz local del auditor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from tkinter import Tk, filedialog


FOLDER_KINDS = {"repository", "output"}
FILE_KINDS = {"config", "comparison"}


def select_path(kind: str, initial: str) -> str:
    initial_dir = Path(initial).expanduser()
    if not initial_dir.is_dir():
        initial_dir = Path(__file__).resolve().parent

    root = Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    root.update_idletasks()
    root.lift()
    try:
        if kind in FOLDER_KINDS:
            title = (
                "Seleccione la copia local autorizada"
                if kind == "repository"
                else "Seleccione la carpeta de resultados"
            )
            selected = filedialog.askdirectory(
                parent=root,
                title=title,
                initialdir=str(initial_dir),
                mustexist=True,
            )
        elif kind in FILE_KINDS:
            title = (
                "Seleccione la política JSON"
                if kind == "config"
                else "Seleccione la evidencia JSON"
            )
            selected = filedialog.askopenfilename(
                parent=root,
                title=title,
                initialdir=str(initial_dir),
                filetypes=(("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")),
            )
        else:
            raise ValueError("Tipo de selector no permitido")
        return str(selected or "")
    finally:
        root.destroy()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Selector de archivos del auditor")
    parser.add_argument("--kind", choices=sorted(FOLDER_KINDS | FILE_KINDS), required=True)
    parser.add_argument("--initial", default=str(Path(__file__).resolve().parent))
    args = parser.parse_args(argv)
    try:
        print(select_path(args.kind, args.initial), flush=True)
    except Exception as exc:  # pragma: no cover - depende del escritorio de Windows
        print(f"No se pudo abrir el explorador de archivos: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
