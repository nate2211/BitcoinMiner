# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_dynamic_libs

block_cipher = None

# IMPORTANT:
# Run: pyinstaller --clean bitcoinminer.spec
# from the BitcoinMiner project folder.
ROOT = Path.cwd()

datas = []
binaries = []
hiddenimports = []

kernel_path = ROOT / "btc_sha256d_scan.cl"
if kernel_path.exists():
    datas.append((str(kernel_path), "."))

for dll_name in ("BitcoinProject.dll", "OpenCL.dll"):
    dll_path = ROOT / dll_name
    if dll_path.exists():
        binaries.append((str(dll_path), "."))

hiddenimports += collect_submodules("pyopencl")
hiddenimports += collect_submodules("numpy")
hiddenimports += collect_submodules("PyQt5")

binaries += collect_dynamic_libs("pyopencl")
binaries += collect_dynamic_libs("numpy")

a = Analysis(
    ["gui.py"],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="BitcoinMiner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)