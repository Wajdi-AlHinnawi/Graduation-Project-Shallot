# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Shallot — Privacy-Preserving Onion-Network client.

Build with:
    pyinstaller --noconfirm Shallot.spec

Output:
    dist/Shallot/Shallot.exe       (the executable, no console window)
    dist/Shallot/_internal/        (bundled Python, libs, Tcl/Tk)
    dist/Shallot/extension/        (browser extension files; copied by build.ps1)
    dist/Shallot/directory_config.json (pinned URL + signing key; copied by build.ps1)

Distribute the entire ``dist/Shallot/`` folder to end users. They run
``Shallot.exe`` from inside that folder.

The launcher uses Tkinter for the status window, so we re-include
tkinter / _tkinter (PyInstaller normally bundles them automatically;
we list them in hidden_imports as a safety belt).
"""
import os

hidden_imports = [
    'shared.protocol',
    'shared.crypto_utils',
    'shared.config',
    'shared.security',
    'shared.key_exchange',
    'shared.relay_registration',
    'shared.logging_utils',
    'shared.runtime_paths',
    'client.directory',
    'client.client_state',
    'client.circuit_builder',
    'client.proxy_client',
    'client.contributor_relay',
    'client.control_api',
    # Tkinter parts — usually auto-detected, listed for safety.
    'tkinter',
    '_tkinter',
    'tkinter.ttk',
    'tkinter.scrolledtext',
    # cryptography backends; PyInstaller's static analysis sometimes
    # misses the ones loaded via dynamic dispatch.
    'cryptography.hazmat.backends.openssl',
    'cryptography.hazmat.backends.openssl.backend',
    'cryptography.hazmat.bindings._rust',
    'cryptography.hazmat.primitives.ciphers.aead',
    'cryptography.hazmat.primitives.asymmetric.x25519',
    'cryptography.hazmat.primitives.asymmetric.ed25519',
    'cryptography.hazmat.primitives.kdf.hkdf',
    'cryptography.hazmat.primitives.serialization',
]

# Bundle the icon as a read-only resource. ``bundle_resource_root()``
# in shared/runtime_paths.py picks it up at runtime via sys._MEIPASS.
# If the icon file does not exist on disk the build still succeeds —
# the GUI just falls back to the default Windows app icon.
datas = []
if os.path.exists('Shallot.ico'):
    datas.append(('Shallot.ico', '.'))

a = Analysis(
    ['launcher.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Things we don't need that PyInstaller pulls in by default.
        # NB: do NOT exclude tkinter — we use it for the GUI.
        'pytest',
        'pip',
        'setuptools',
        'distutils',
        'IPython',
        'jupyter',
        'matplotlib',
        'numpy',
        'PIL',
        'pandas',
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)

# Resolve the icon path for the EXE() call. We pass it only if the
# file is present so missing-icon doesn't fail the build.
exe_icon = 'Shallot.ico' if os.path.exists('Shallot.ico') else None

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Shallot',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,            # UPX often triggers AV false positives
    console=False,        # Windowed app — no black console box
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=exe_icon,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='Shallot',
)
