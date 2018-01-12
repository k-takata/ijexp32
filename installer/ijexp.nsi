; Installer for i.j Shell Property Sheets Export/Import

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

!packhdr "$%TEMP%\exehead.tmp" '"upx.exe" -9 "$%TEMP%\exehead.tmp"'

Unicode true
!define MUI_PRODUCT "ijexp"
!define MUI_PRODUCT_LONG "i.j Shell Property Sheets Export/Import"
;!define MUI_VERSION "1.01k20"
!define MUI_PRODUCT_FULL "${MUI_PRODUCT_LONG} ${MUI_VERSION}"
Name "${MUI_PRODUCT_FULL}"
;OutFile "ijexp_101k20.exe"

!define UNINSTALL_REG "Software\Microsoft\Windows\CurrentVersion\Uninstall\${MUI_PRODUCT}"
!define UNINSTALL_REG_OLD "Software\Microsoft\Windows\CurrentVersion\Uninstall\ijexp32"
!define MUI_PUBLISHER "K.Takata"
!define IJE_CLSID "{00000001-23D0-0001-8000-004026419740}"

InstallDir "$PROGRAMFILES\${MUI_PRODUCT}"

SetCompressor /SOLID lzma
RequestExecutionLevel admin
ManifestDPIAware true

;--------------------------------
; Interface Settings

!define MUI_ABORTWARNING
!define MUI_UNABORTWARNING
!define MUI_LANGDLL_ALLLANGUAGES

;--------------------------------
; Language Selection Dialog Settings

; Remember the installer language
!define MUI_LANGDLL_REGISTRY_ROOT "HKLM"
!define MUI_LANGDLL_REGISTRY_KEY "Software\${MUI_PRODUCT}"
!define MUI_LANGDLL_REGISTRY_VALUENAME "Installer Language"

;--------------------------------
; Pages

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

;--------------------------------
; Reserve Files

!insertmacro MUI_RESERVEFILE_LANGDLL

;--------------------------------
; Installer Sections

!macro TryFile INFILE OUTFILE
  ClearErrors
  File "${INFILE}"
  ${If} ${Errors}
    GetTempFileName $0
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

  ; Documents
  File "..\ijexp32.txt"
  File "..\ijexp32k.txt"
  File "..\vcbungle.txt"

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
  WriteRegStr HKCR "*\shellex\PropertySheetHandlers\${IJE_CLSID}" "" "${MUI_PRODUCT_LONG}"
  WriteRegStr HKCR32 "CLSID\${IJE_CLSID}" "" "${MUI_PRODUCT_LONG}"
  WriteRegStr HKCR32 "CLSID\${IJE_CLSID}\InProcServer32" "" "$INSTDIR\ijexp32.dll"
  WriteRegStr HKCR32 "CLSID\${IJE_CLSID}\InProcServer32" "ThreadingModel" "Apartment"
  ${If} ${RunningX64}
    WriteRegStr HKCR64 "CLSID\${IJE_CLSID}" "" "${MUI_PRODUCT_LONG}"
    WriteRegStr HKCR64 "CLSID\${IJE_CLSID}\InProcServer32" "" "$INSTDIR\ijexp64.dll"
    WriteRegStr HKCR64 "CLSID\${IJE_CLSID}\InProcServer32" "ThreadingModel" "Apartment"
  ${EndIf}

  ; Uninstall list
  ;WriteRegStr HKLM "${UNINSTALL_REG}" "DisplayIcon" '"$INSTDIR\ijexp.exe",0'
  WriteRegStr HKLM "${UNINSTALL_REG}" "DisplayName" "${MUI_PRODUCT_FULL}"
  WriteRegStr HKLM "${UNINSTALL_REG}" "Publisher" "${MUI_PUBLISHER}"
  WriteRegStr HKLM "${UNINSTALL_REG}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  SectionGetSize ${main_section} $0
  WriteRegDWORD HKLM "${UNINSTALL_REG}" "EstimatedSize" $0

  ; Store install folder
  WriteRegStr HKLM "Software\${MUI_PRODUCT}" "path" $INSTDIR

  WriteUninstaller "$INSTDIR\Uninstall.exe"

SectionEnd

Function .onInit

  ${If} ${RunningX64}
    SetRegView 64
  ${EndIf}

  !insertmacro MUI_LANGDLL_DISPLAY

  ; Check old version of ijexp32
  ; $0: Uninstall command for 32-bit, $1: for 64-bit
  StrCpy $1 ""
  ReadRegStr $0 HKLM32 "${UNINSTALL_REG_OLD}" "UninstallString"
  ${If} ${RunningX64}
    ReadRegStr $1 HKLM64 "${UNINSTALL_REG_OLD}" "UninstallString"
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

  ; Load install folder
  ReadRegStr $INSTDIR HKLM "Software\${MUI_PRODUCT}" "path"
  ${If} "$INSTDIR" == ""
    ${If} ${RunningX64}
      StrCpy $INSTDIR "$PROGRAMFILES64\${MUI_PRODUCT}"
    ${Else}
      StrCpy $INSTDIR "$PROGRAMFILES\${MUI_PRODUCT}"
    ${EndIf}
  ${EndIf}

FunctionEnd

;--------------------------------
; Uninstaller Section

Section "Uninstall"

  ; Unregister servers
  DeleteRegKey HKCR "*\shellex\PropertySheetHandlers\${IJE_CLSID}"
  DeleteRegKey HKCR32 "CLSID\${IJE_CLSID}"
  ${If} ${RunningX64}
    DeleteRegKey HKCR64 "CLSID\${IJE_CLSID}"
  ${EndIf}

  ; DLLs
  ${If} ${RunningX64}
    Delete /REBOOTOK "$INSTDIR\ijexp64.dll"
  ${EndIf}
  Delete /REBOOTOK "$INSTDIR\ijexp32.dll"
  Delete /REBOOTOK "$INSTDIR\ijexp.ini"

  ; Documents
  Delete /REBOOTOK "$INSTDIR\ijexp32.txt"
  Delete /REBOOTOK "$INSTDIR\ijexp32k.txt"
  Delete /REBOOTOK "$INSTDIR\vcbungle.txt"

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

  DeleteRegKey HKLM "${UNINSTALL_REG}"
  DeleteRegKey HKLM "Software\${MUI_PRODUCT}"

SectionEnd

;--------------------------------
; Uninstaller Functions

Function un.onInit

  ${If} ${RunningX64}
    SetRegView 64
  ${EndIf}

  !insertmacro MUI_UNGETLANGUAGE

FunctionEnd

; vim: ts=2 sw=2 et:
