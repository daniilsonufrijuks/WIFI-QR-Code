from cx_Freeze import setup, Executable
import sys

# Define build options
build_options = {
    'packages': ['tkinter', 'qrcode', 'PIL', 'io'],
    'excludes': ['tkinter.test'],
    'include_files': []
}

# Use Win32GUI to hide console window on Windows
base = 'Win32GUI' if sys.platform == 'win32' else None

executables = [
    Executable('main.py', 
               base=base,
               target_name='QR_Generator',
               icon=None)
]

setup(
    name='QR Generator',
    version='1.0',
    description='Generate WiFi, Password, and Link QR codes',
    options={'build_exe': build_options},
    executables=executables
)