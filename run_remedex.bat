@echo off
setlocal EnableDelayedExpansion
title RemedeX
echo ================================================
echo   RemedeX — Browser extension security ^& cleanup
echo ================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/
    pause
    exit /b 1
)

:menu
set "choice="
echo.
echo ==================== MENU ====================
echo.
echo   MANAGE EXTENSIONS
echo     1. Launch GUI
echo     2. List extensions
echo     3. List extensions (detailed)
echo     4. Remove extension by ID
echo.
echo   DOWNLOAD ^& ANALYZE
echo     5. Download extension from Chrome Web Store
echo     6. Copy installed extension for analysis
echo.
echo   CLEANUP
echo     7. Clean browser data (choose what to clean)
echo     8. Disable extension sync
echo.
echo   REMOTE SCRIPTS
echo     9. Generate remote cleanup script
echo    10. Generate extension lister script
echo.
echo   REPORTING
echo    11. Export forensic HTML report
echo.
echo    0. Exit
echo.
echo ===============================================

set /p "choice=Enter choice: "

if "!choice!"=="0" goto :eof
if "!choice!"=="1" goto opt_gui
if "!choice!"=="2" goto opt_list
if "!choice!"=="3" goto opt_list_detail
if "!choice!"=="4" goto opt_remove
if "!choice!"=="5" goto opt_download
if "!choice!"=="6" goto opt_copy
if "!choice!"=="7" goto opt_clean
if "!choice!"=="8" goto opt_sync
if "!choice!"=="9" goto opt_script
if "!choice!"=="10" goto opt_lister
if "!choice!"=="11" goto opt_export

echo Invalid choice
goto menu

:ask_browser
set "selbrowser="
echo.
echo Select browser filter:
echo   a. All browsers
echo   b. Chrome only
echo   c. Edge only
echo   d. Brave only
echo.
set /p "selbrowser=Choice [a]: "
if /i "!selbrowser!"=="" set "selbrowser=a"
if /i "!selbrowser!"=="a" set "browserarg=" & goto :eof
if /i "!selbrowser!"=="b" set "browserarg=-b chrome" & goto :eof
if /i "!selbrowser!"=="c" set "browserarg=-b edge" & goto :eof
if /i "!selbrowser!"=="d" set "browserarg=-b brave" & goto :eof
set "browserarg="
goto :eof

:opt_gui
python remedex.py --gui
goto menu

:opt_list
call :ask_browser
python remedex.py -l !browserarg!
pause
goto menu

:opt_list_detail
call :ask_browser
python remedex.py -l --details !browserarg!
pause
goto menu

:opt_remove
echo.
echo Listing installed extensions...
echo.
python remedex.py -l
echo.
set "extid="
set /p "extid=Enter extension ID to remove (or 'c' to cancel): "
if /i "!extid!"=="c" goto menu
if "!extid!"=="" goto menu

echo.
set "syncopt="
set /p "syncopt=Also disable extension sync to prevent re-download? [y/N]: "

echo.
echo WARNING: Close all browsers before continuing!
pause

if /i "!syncopt!"=="y" (
    python remedex.py -r !extid! --disable-sync --force
) else (
    python remedex.py -r !extid! --force
)
pause
goto menu

:opt_download
echo.
set "extid="
set /p "extid=Enter extension ID (32 chars) or full CWS URL: "
if "!extid!"=="" goto menu

echo.
echo Downloading extension...
if "!extid:https://=!" neq "!extid!" (
    python remedex.py --download-url "!extid!" --extract
) else (
    python remedex.py -D !extid! --extract
)
pause
goto menu

:opt_copy
echo.
echo Listing installed extensions...
python remedex.py -l
echo.
set "extid="
set /p "extid=Enter extension ID to copy (or 'c' to cancel): "
if /i "!extid!"=="c" goto menu
if "!extid!"=="" goto menu

python remedex.py --copy-installed !extid!
pause
goto menu

:opt_clean
echo.
echo WARNING: Close ALL browsers before cleaning!
echo.
call :ask_browser
echo.
echo What data should be cleaned?
echo   1. All data (localStorage, sessionStorage, cache, SW, IndexedDB)
echo   2. All data + cookies (will log you out of everything!)
echo   3. Only localStorage + sessionStorage
echo   4. Only cache + service workers
echo   5. Custom (choose each type)
echo   6. Cancel
echo.
set "cleanopt="
set /p "cleanopt=Choice: "

if "!cleanopt!"=="6" goto menu
if "!cleanopt!"=="1" (
    python remedex.py --clean-all --force !browserarg!
    pause
    goto menu
)
if "!cleanopt!"=="2" (
    python remedex.py --clean-all --cookies --force !browserarg!
    pause
    goto menu
)
if "!cleanopt!"=="3" (
    python remedex.py --clean-all --no-cache --no-sw --no-indexeddb --force !browserarg!
    pause
    goto menu
)
if "!cleanopt!"=="4" (
    python remedex.py --clean-all --no-storage --no-sessionstorage --no-indexeddb --force !browserarg!
    pause
    goto menu
)
if "!cleanopt!"=="5" goto opt_clean_custom
goto menu

:opt_clean_custom
echo.
set "c_ls=yes"
set "c_ss=yes"
set "c_cache=yes"
set "c_sw=yes"
set "c_idb=yes"
set "c_cookies=no"

set /p "c_ls=Clean localStorage? [yes]: "
set /p "c_ss=Clean sessionStorage? [yes]: "
set /p "c_cache=Clean cache? [yes]: "
set /p "c_sw=Clean service workers? [yes]: "
set /p "c_idb=Clean IndexedDB? [yes]: "
set /p "c_cookies=Clean cookies (logs you out)? [no]: "

set "cleanargs=--clean-all --force"
if /i "!c_ls!"=="no" set "cleanargs=!cleanargs! --no-storage"
if /i "!c_ss!"=="no" set "cleanargs=!cleanargs! --no-sessionstorage"
if /i "!c_cache!"=="no" set "cleanargs=!cleanargs! --no-cache"
if /i "!c_sw!"=="no" set "cleanargs=!cleanargs! --no-sw"
if /i "!c_idb!"=="no" set "cleanargs=!cleanargs! --no-indexeddb"
if /i "!c_cookies!"=="yes" set "cleanargs=!cleanargs! --cookies"

echo.
echo Running: python remedex.py !cleanargs! !browserarg!
python remedex.py !cleanargs! !browserarg!
pause
goto menu

:opt_sync
echo.
call :ask_browser
echo This will modify browser Preferences to prevent extension sync
echo from re-installing removed extensions.
echo.
set "confirmopt="
set /p "confirmopt=Disable extension sync? [y/N]: "
if /i "!confirmopt!" neq "y" goto menu

python remedex.py --disable-sync !browserarg!
pause
goto menu

:opt_script
echo.
echo Select script type:
echo   1. Python  (remote - cross-platform, best for SSH/Ansible)
echo   2. PowerShell (remote - Windows, for PSRemoting/SCCM/GPO)
echo   3. Bash    (remote - Linux/Mac, for SSH/Ansible)
echo   4. JavaScript (local - browser console, current site only)
echo.
set "scriptopt="
set /p "scriptopt=Choice [1]: "
if "!scriptopt!"=="" set "scriptopt=1"

if "!scriptopt!"=="1" set "stype=python" & set "sext=py"
if "!scriptopt!"=="2" set "stype=powershell" & set "sext=ps1"
if "!scriptopt!"=="3" set "stype=bash" & set "sext=sh"
if "!scriptopt!"=="4" set "stype=js" & set "sext=js"

set "outfile="
set /p "outfile=Save to file (enter filename or press Enter to print): "

if "!outfile!"=="" (
    python remedex.py -g --script-type !stype!
) else (
    python remedex.py -g --script-type !stype! -o "!outfile!"
    echo.
    echo Script saved to: !outfile!
)
pause
goto menu

:opt_lister
echo.
echo This generates a script you can copy and run on a remote
echo machine to list all installed browser extensions and their IDs.
echo.
echo The output is printed to screen - copy it manually or use
echo the GUI for a copyable version.
echo.
echo Select target OS:
echo   1. Windows (PowerShell)
echo   2. Mac     (Bash)
echo   3. Linux   (Bash)
echo.
set "osopt="
set /p "osopt=Choice [1]: "
if "!osopt!"=="" set "osopt=1"

echo.
echo === Launch the GUI for the Remote Lister feature ===
echo.
python remedex.py --gui
goto menu

:opt_export
echo.
echo This will scan all browsers and generate a detailed forensic HTML report.
set "outfile="
set /p "outfile=Enter output HTML filename (e.g., report.html) [report.html]: "
if "!outfile!"=="" set "outfile=report.html"
echo.
python remedex.py -l --export-report "!outfile!"
pause
goto menu
