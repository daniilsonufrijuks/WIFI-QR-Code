from cx_Freeze import setup, Executable
import sys

build_options = {
    'packages': ['tkinter', 'qrcode', 'PIL'],
    'excludes': [],
    'include_files': []
}

base = 'Win32GUI' if sys.platform == 'win32' else None

executables = [
    Executable('main.py', 
               base=base,
               target_name='WiFi_QR_Generator',
               icon=None)
]

setup(
    name='WiFi QR Generator',
    version='1.0',
    description='Generate WiFi QR codes',
    options={'build_exe': build_options},
    executables=executables
)