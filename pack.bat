@echo off
if "%1"=="" goto usage
setlocal DISABLEDELAYEDEXPANSION

:: 7z (official version) or 7-zip32 (undll + common archiver) can be used
if "%SEVENZIP%"=="" set SEVENZIP=7-zip32

if not exist x86 mkdir x86
if not exist x64 mkdir x64

cd src
"%SEVENZIP%" a -m0=PPMd:o=32 ..\src.7z @..\srcfiles.lst
cd ..

copy /y src\objfre_wxp_x86\i386\ijexp32.dll x86
copy /y src\objfre_win7_amd64\amd64\ijexp32.dll x64
"%SEVENZIP%" a -mx=9 %1 @pkgfiles.lst

goto end

:usage
echo.
echo usage: pack ^<filename^>
echo.
echo ^<filename^>: ex. ije101k18.7z

:end
