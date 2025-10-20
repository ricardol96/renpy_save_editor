@echo off
echo Building Ren'Py Save Editor executable...
echo.

REM Install PyInstaller if not already installed
pip install pyinstaller

REM Build the executable (one file, windowed mode)
REM Output to 'executable' directory instead of 'dist'
pyinstaller --onefile --windowed --name "RenpySaveEditor" --distpath executable --icon=NONE renpy_save_editor.py

echo.
echo Done! Executable is in the 'executable' folder
echo.
echo Cleaning up build artifacts...
if exist build rmdir /s /q build
if exist RenpySaveEditor.spec del RenpySaveEditor.spec

echo.
echo Build complete! Run executable\RenpySaveEditor.exe
pause

