"""Construye dist/Sarezain.exe (Windows) con PyInstaller.

Uso (con el entorno virtual activo y `pip install pyinstaller pillow`):
    python packaging/build_exe.py
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import PyInstaller.__main__
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "packaging"
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT))
from sarezain import __version__  # noqa: E402

BG, ACCENT = (14, 17, 19, 255), (61, 220, 151, 255)


def make_icon(path: Path) -> None:
    """Escudo verde con tres nodos sobre fondo oscuro (mismo diseño que el favicon)."""
    s = 256
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, s - 1, s - 1), radius=56, fill=BG)
    shield = [(128, 34), (206, 62), (206, 118), (196, 162), (170, 198), (128, 224),
              (86, 198), (60, 162), (50, 118), (50, 62)]
    d.line(shield + [shield[0]], fill=ACCENT, width=16, joint="curve")
    for cx, cy, r in ((128, 104, 15), (96, 140, 12), (160, 140, 12)):
        d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=ACCENT)
    d.line([(128, 104), (96, 140)], fill=ACCENT, width=6)
    d.line([(128, 104), (160, 140)], fill=ACCENT, width=6)
    img.save(path, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


def make_version_file(path: Path) -> None:
    nums = tuple(int(x) for x in (__version__.split(".") + ["0", "0", "0"])[:4])
    path.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={nums}, prodvers={nums}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('0C0A04B0', [
      StringStruct('CompanyName', 'Mikel Zalacain González'),
      StringStruct('FileDescription', 'Sarezain - Escáner visual de vulnerabilidades de red'),
      StringStruct('FileVersion', '{__version__}'),
      StringStruct('InternalName', 'Sarezain'),
      StringStruct('LegalCopyright', '© 2026 Mikel Zalacain González · Licencia MIT'),
      StringStruct('OriginalFilename', 'Sarezain.exe'),
      StringStruct('ProductName', 'Sarezain'),
      StringStruct('ProductVersion', '{__version__}'),
      StringStruct('Comments', 'https://github.com/mikelzalacain/sarezain')])]),
    VarFileInfo([VarStruct('Translation', [0x0C0A, 1200])])
  ]
)
""", encoding="utf-8")


def main() -> None:
    BUILD.mkdir(exist_ok=True)
    icon, version = BUILD / "sarezain.ico", BUILD / "version.txt"
    make_icon(icon)
    make_version_file(version)
    sep = ";"  # separador de --add-data en Windows
    PyInstaller.__main__.run([
        str(PKG / "entry.py"),
        "--name", "Sarezain",
        "--onefile",
        "--console",  # la ventana muestra la URL y permite cerrar el programa
        "--noconfirm", "--clean",
        "--icon", str(icon),
        "--version-file", str(version),
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(BUILD / "pyinstaller"),
        "--specpath", str(BUILD),
        "--add-data", f"{ROOT / 'sarezain' / 'web'}{sep}sarezain/web",
        "--add-data", f"{ROOT / 'sarezain' / 'data'}{sep}sarezain/data",
        "--exclude-module", "tkinter",
        "--exclude-module", "PIL",
        "--exclude-module", "PyInstaller",
    ])
    exe = ROOT / "dist" / "Sarezain.exe"
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    (ROOT / "dist" / "Sarezain.exe.sha256").write_text(f"{digest}  Sarezain.exe\n", encoding="ascii")
    print(f"\n{exe}  {exe.stat().st_size / 1e6:.1f} MB\nSHA-256: {digest}")


if __name__ == "__main__":
    main()
