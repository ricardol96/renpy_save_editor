@echo off
echo Setting up Git repository...
echo.

REM Initialize git repository
git init

REM Add all files
git add .

REM Create initial commit
git commit -m "Initial commit: Ren'Py Save Editor"

echo.
echo Git repository initialized!
echo.
echo Now create a repository on GitHub, then run these commands:
echo.
echo   git remote add origin https://github.com/differentfun/renpy-save-editor
echo   git branch -M main
echo   git push -u origin main
echo.
pause

