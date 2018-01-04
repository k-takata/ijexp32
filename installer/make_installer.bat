@echo off
setlocal

rem Target OS
set target_x86=wxp
set target_x64=win7

rem Version
if "%1"=="" (
	echo Usage: make_installer VERSION
	echo e.g. make_installer 1.01k20
	goto :eof
)
set version=%1
echo Version: %version%

rem Remove and replace symbols in the version string for file name
set filever=%version:/=_%
set filever=%filever:.=%


rem Copy dll files to simpler direcotries

if not exist ..\x86 mkdir ..\x86
if not exist ..\x64 mkdir ..\x64

copy ..\src\objfre_%target_x86%_x86\i386\ijexp32.dll    ..\x86 /y
copy ..\src\objfre_%target_x64%_amd64\amd64\ijexp64.dll ..\x64 /y


rem Create an installer
"%ProgramFiles(x86)%\NSIS\makensis.exe" "/DMUI_VERSION=%version%" "/XOutFile ije%filever%.exe" ijexp.nsi
