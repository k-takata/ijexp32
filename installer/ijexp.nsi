﻿; Installer for i.j Shell Property Sheets Export/Import

Unicode true
SetCompressor /SOLID lzma
SetCompressorDictSize 16
ManifestDPIAware true

!define PRODUCT "ijexp"
!define PRODUCT_LONG "i.j Shell Property Sheets Export/Import"
;!define VERSION "1.01k20"
!define PRODUCT_FULL "${PRODUCT_LONG} ${VERSION}"
!define PRODUCT_REG_KEY "Software\${PRODUCT}"
!define INSTDIR_REG_VALNAME  "path"
!define INSTMODE_REG_VALNAME "mode"
!define INSTLANG_REG_VALNAME "Installer Language"
!define UNINST_REG_KEY     "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT}"
!define UNINST_REG_KEY_OLD "Software\Microsoft\Windows\CurrentVersion\Uninstall\ijexp32"
!define PUBLISHER "i.j and K.Takata"
!define IJE_CLSID "{00000001-23D0-0001-8000-004026419740}"

!define MULTIUSER_EXECUTIONLEVEL Highest
;!define MULTIUSER_USE_PROGRAMFILES64
!define MULTIUSER_MUI
!define MULTIUSER_INSTALLMODE_COMMANDLINE
;!define MULTIUSER_INSTALLMODE_INSTDIR "${PRODUCT}"
!define MULTIUSER_INSTALLMODE_INSTDIR_REGISTRY_KEY "${PRODUCT_REG_KEY}"
!define MULTIUSER_INSTALLMODE_INSTDIR_REGISTRY_VALUENAME "${INSTDIR_REG_VALNAME}"
!define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_KEY "${PRODUCT_REG_KEY}"
!define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_VALUENAME "${INSTMODE_REG_VALNAME}"
!define MULTIUSER_INSTALLMODE_FUNCTION InitInstDir
!include "MultiUser.nsh"

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

!packhdr "$%TEMP%\exehead.tmp" '"upx.exe" -9 "$%TEMP%\exehead.tmp"'

Name "${PRODUCT_FULL}"
;OutFile "ijexp_101k20.exe"

;InstallDir "$PROGRAMFILES\${PRODUCT}"


;--------------------------------
; Interface Settings

!define MUI_ABORTWARNING
!define MUI_UNABORTWARNING
!define MUI_LANGDLL_ALLLANGUAGES

; Uncomment the following lines for debugging.
;!define MUI_FINISHPAGE_NOAUTOCLOSE
;!define MUI_UNFINISHPAGE_NOAUTOCLOSE

;--------------------------------
; Language Selection Dialog Settings

; Remember the installer language
!define MUI_LANGDLL_REGISTRY_ROOT "SHCTX"
!define MUI_LANGDLL_REGISTRY_KEY "${PRODUCT_REG_KEY}"
!define MUI_LANGDLL_REGISTRY_VALUENAME "${INSTLANG_REG_VALNAME}"

;--------------------------------
; Pages

!insertmacro MULTIUSER_PAGE_INSTALLMODE
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

;--------------------------------
; Languages

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Japanese"

LangString MES_UNINST_OLD ${LANG_ENGLISH} "Old versions of ijexp32 are found. You should uninstall them to continue the installation. Uninstall them?"
LangString MES_UNINST_OLD ${LANG_JAPANESE} "古いバージョンのijexp32が見つかりました。インストールを進めるには、旧バージョンのアンインストールが必要です。アンインストールしますか？"

# Fix an NSIS Japanese translation. The access key was missing.
LangString ^InstallBtn ${LANG_JAPANESE} "インストール(&I)"

;--------------------------------
; Reserve Files

!insertmacro MUI_RESERVEFILE_LANGDLL
ReserveFile /plugin UserInfo.dll

;--------------------------------
; Installer Sections

!macro TryFile INFILE OUTFILE
  ClearErrors
  File /oname=${OUTFILE} "${INFILE}"
  ${If} ${Errors}
    GetTempFileName $0 $OUTDIR
    File /oname=$0 "${INFILE}"
    Rename /REBOOTOK $0 "${OUTFILE}"
  ${EndIf}
!macroend

Section "main files" main_section

  SetOutPath "$INSTDIR"

  ; DLLs
  SetOverwrite try
  !insertmacro TryFile "..\x86\ijexp32.dll" "ijexp32.dll"
  ${If} ${RunningX64}
    !insertmacro TryFile "..\x64\ijexp64.dll" "ijexp64.dll"
  ${EndIf}
  SetOverwrite lastused
  File "..\ijexp.ini"

  ; Documents & sample settings
  File "..\ijexp32.txt"
  File "..\ijexp32k.txt"
  File "..\vcbungle.txt"
  File "..\ijexp_sample_settings.reg"

  ; .exp files
  File "..\comctl32.exp"
  File "..\d2d1.exp"
  File "..\kernel32.exp"
  File "..\mfc30.exp"
  File "..\mfc40.exp"
  File "..\mfc42.exp"
  File "..\mfc42u.exp"
  File "..\mfc42!x64.exp"
  File "..\mfc42u!x64.exp"
  File "..\mfc70.exp"
  File "..\mfc70u.exp"
  File "..\mfc71.exp"
  File "..\mfc71u.exp"
  File "..\mfc80.exp"
  File "..\mfc80u.exp"
  File "..\mfc80!x64.exp"
  File "..\mfc80u!x64.exp"
  File "..\mfc120.exp"
  File "..\mfc120u.exp"
  File "..\mfc120!x64.exp"
  File "..\mfc120u!x64.exp"
  File "..\mfc140.exp"
  File "..\mfc140u.exp"
  File "..\mfc140!x64.exp"
  File "..\mfc140u!x64.exp"
  File "..\oleaut32.exp"
  File "..\olepro32.exp"
  File "..\shdocvw.exp"
  File "..\shell32.exp"
  File "..\shlwapi.exp"
  File "..\ws2_32.exp"
  File "..\wsock32.exp"

  ; Register servers
  WriteRegStr SHCTX "Software\Classes\*\shellex\PropertySheetHandlers\${IJE_CLSID}" "" "${PRODUCT_LONG}"
  SetRegView 32
  WriteRegStr SHCTX "Software\Classes\CLSID\${IJE_CLSID}" "" "${PRODUCT_LONG}"
  WriteRegStr SHCTX "Software\Classes\CLSID\${IJE_CLSID}\InProcServer32" "" "$INSTDIR\ijexp32.dll"
  WriteRegStr SHCTX "Software\Classes\CLSID\${IJE_CLSID}\InProcServer32" "ThreadingModel" "Apartment"
  SetRegView lastused
  ${If} ${RunningX64}
    WriteRegStr SHCTX "Software\Classes\CLSID\${IJE_CLSID}" "" "${PRODUCT_LONG}"
    WriteRegStr SHCTX "Software\Classes\CLSID\${IJE_CLSID}\InProcServer32" "" "$INSTDIR\ijexp64.dll"
    WriteRegStr SHCTX "Software\Classes\CLSID\${IJE_CLSID}\InProcServer32" "ThreadingModel" "Apartment"
  ${EndIf}

  ; Uninstall list
  ;WriteRegStr SHCTX "${UNINST_REG_KEY}" "DisplayIcon" '"$INSTDIR\ijexp.exe",0'
  WriteRegStr SHCTX "${UNINST_REG_KEY}" "DisplayName" "${PRODUCT_FULL}"
  WriteRegStr SHCTX "${UNINST_REG_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr SHCTX "${UNINST_REG_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr SHCTX "${UNINST_REG_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  SectionGetSize ${main_section} $0
  WriteRegDWORD SHCTX "${UNINST_REG_KEY}" "EstimatedSize" $0

  ; Store install folder & mode
  WriteRegStr SHCTX "${PRODUCT_REG_KEY}" "${INSTDIR_REG_VALNAME}" $INSTDIR
  WriteRegStr SHCTX "${PRODUCT_REG_KEY}" "${INSTMODE_REG_VALNAME}" $MultiUser.InstallMode

  WriteUninstaller "$INSTDIR\Uninstall.exe"

SectionEnd


Var CmdInstDir  ; Install path specified by /D=path.

Function .onInit

  ; Save the /D=path command line option (if available).
  StrCpy $CmdInstDir $INSTDIR

  ${If} ${RunningX64}
    SetRegView 64
  ${EndIf}

  !insertmacro MULTIUSER_INIT
  !insertmacro MUI_LANGDLL_DISPLAY

  ; Check old version of ijexp32
  ; $0: Uninstall command for 32-bit, $1: for 64-bit
  StrCpy $1 ""
  ReadRegStr $0 HKLM32 "${UNINST_REG_KEY_OLD}" "UninstallString"
  ${If} ${RunningX64}
    ReadRegStr $1 HKLM64 "${UNINST_REG_KEY_OLD}" "UninstallString"
  ${EndIf}

  ${If} "$0$1" != ""
    ${Do}
      ${If} ${Cmd} `MessageBox MB_YESNO|MB_ICONQUESTION $(MES_UNINST_OLD) /SD IDYES IDYES`
        ${ExitDo}
      ${EndIf}
      ${If} ${Cmd} `MessageBox MB_YESNO|MB_ICONEXCLAMATION "${MUI_ABORTWARNING_TEXT}" IDYES`
        Abort
      ${EndIf}
    ${Loop}

    ; Uninstall 64-bit version
    ${If} "$1" != ""
      ${DisableX64FSRedirection}
      ExecWait '$1'
      ${EnableX64FSRedirection}
    ${EndIf}

    ; Uninstall 32-bit version
    ${If} "$0" != ""
      ExecWait '$0'
    ${EndIf}
  ${EndIf}

FunctionEnd

Function InitInstDir

  ; MultiUser.nsh doesn't handle the /D=path command line option.
  ; Handle it by ourself.

  ; Load install folder
  ReadRegStr $0 SHCTX "${PRODUCT_REG_KEY}" "${INSTDIR_REG_VALNAME}"
  ${If} "$0" == ""
    ; Not previously installed.
    ${If} "$CmdInstDir" == ""
      ; Install folder is not specified by the command line. (/D=path)
      ${If} $MultiUser.InstallMode == "AllUsers"
        ${If} ${RunningX64}
          StrCpy $INSTDIR "$PROGRAMFILES64\${PRODUCT}"
        ${Else}
          StrCpy $INSTDIR "$PROGRAMFILES\${PRODUCT}"
        ${EndIf}
      ${Else}
        StrCpy $INSTDIR "$LOCALAPPDATA\${PRODUCT}"
      ${EndIf}
    ${EndIf}
  ${Else}
    ; Old version might be already installed. Install there. (Ignore /D.)
    StrCpy $INSTDIR $0
  ${EndIf}

FunctionEnd

;--------------------------------
; Uninstaller Section

Section "Uninstall"

  ; Unregister servers
  DeleteRegKey SHCTX "Software\Classes\*\shellex\PropertySheetHandlers\${IJE_CLSID}"
  SetRegView 32
  DeleteRegKey SHCTX "Software\Classes\CLSID\${IJE_CLSID}"
  SetRegView lastused
  ${If} ${RunningX64}
    DeleteRegKey SHCTX "Software\Classes\CLSID\${IJE_CLSID}"
  ${EndIf}

  ; DLLs
  ${If} ${RunningX64}
    Delete /REBOOTOK "$INSTDIR\ijexp64.dll"
  ${EndIf}
  Delete /REBOOTOK "$INSTDIR\ijexp32.dll"
  Delete /REBOOTOK "$INSTDIR\ijexp.ini"

  ; Documents & sample settings
  Delete /REBOOTOK "$INSTDIR\ijexp32.txt"
  Delete /REBOOTOK "$INSTDIR\ijexp32k.txt"
  Delete /REBOOTOK "$INSTDIR\vcbungle.txt"
  Delete /REBOOTOK "$INSTDIR\ijexp_sample_settings.reg"

  ; .exp files
  Delete /REBOOTOK "$INSTDIR\comctl32.exp"
  Delete /REBOOTOK "$INSTDIR\d2d1.exp"
  Delete /REBOOTOK "$INSTDIR\kernel32.exp"
  Delete /REBOOTOK "$INSTDIR\mfc30.exp"
  Delete /REBOOTOK "$INSTDIR\mfc40.exp"
  Delete /REBOOTOK "$INSTDIR\mfc42.exp"
  Delete /REBOOTOK "$INSTDIR\mfc42u.exp"
  Delete /REBOOTOK "$INSTDIR\mfc42!x64.exp"
  Delete /REBOOTOK "$INSTDIR\mfc42u!x64.exp"
  Delete /REBOOTOK "$INSTDIR\mfc70.exp"
  Delete /REBOOTOK "$INSTDIR\mfc70u.exp"
  Delete /REBOOTOK "$INSTDIR\mfc71.exp"
  Delete /REBOOTOK "$INSTDIR\mfc71u.exp"
  Delete /REBOOTOK "$INSTDIR\mfc80.exp"
  Delete /REBOOTOK "$INSTDIR\mfc80u.exp"
  Delete /REBOOTOK "$INSTDIR\mfc80!x64.exp"
  Delete /REBOOTOK "$INSTDIR\mfc80u!x64.exp"
  Delete /REBOOTOK "$INSTDIR\mfc120.exp"
  Delete /REBOOTOK "$INSTDIR\mfc120u.exp"
  Delete /REBOOTOK "$INSTDIR\mfc120!x64.exp"
  Delete /REBOOTOK "$INSTDIR\mfc120u!x64.exp"
  Delete /REBOOTOK "$INSTDIR\mfc140.exp"
  Delete /REBOOTOK "$INSTDIR\mfc140u.exp"
  Delete /REBOOTOK "$INSTDIR\mfc140!x64.exp"
  Delete /REBOOTOK "$INSTDIR\mfc140u!x64.exp"
  Delete /REBOOTOK "$INSTDIR\oleaut32.exp"
  Delete /REBOOTOK "$INSTDIR\olepro32.exp"
  Delete /REBOOTOK "$INSTDIR\shdocvw.exp"
  Delete /REBOOTOK "$INSTDIR\shell32.exp"
  Delete /REBOOTOK "$INSTDIR\shlwapi.exp"
  Delete /REBOOTOK "$INSTDIR\ws2_32.exp"
  Delete /REBOOTOK "$INSTDIR\wsock32.exp"

  Delete /REBOOTOK "$INSTDIR\Uninstall.exe"

  RMDir /REBOOTOK "$INSTDIR"

  DeleteRegKey SHCTX "${UNINST_REG_KEY}"
  DeleteRegKey SHCTX "${PRODUCT_REG_KEY}"

SectionEnd

;--------------------------------
; Uninstaller Functions

Function un.onInit

  ${If} ${RunningX64}
    SetRegView 64
  ${EndIf}

  !insertmacro MULTIUSER_UNINIT
  !insertmacro MUI_UNGETLANGUAGE

FunctionEnd

; vim: ts=2 sw=2 et:
