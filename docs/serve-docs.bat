@echo off
REM Start the Docsify documentation site at http://localhost:3000.
REM Installs docsify-cli globally on first run if it is not on PATH.

where docsify >NUL 2>&1
if errorlevel 1 (
  echo docsify-cli not found; installing globally...
  call npm i -g docsify-cli || exit /b 1
)

pushd "%~dp0.."
docsify serve docs --port 3000
popd
