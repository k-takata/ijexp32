//
// ijexp32.cpp
// Copyright (C) 1999 i.j , All rights reserved.
//

#include "stdafx.h"
#include <afxdllx.h>
#include <objbase.h>  // DEFINE_GUID()
#include <initguid.h> // CLSID_ExeHdr, CLSID_Export, CLSID_Import
#include <shlwapi.h>
#include "ijexp32.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#ifdef ICC_LISTVIEW_CLASSES
extern "C" {
	typedef WINCOMMCTRLAPI BOOL (WINAPI *LPFNINITCOMCTLEX)(LPINITCOMMONCONTROLSEX);
}
#endif

#ifdef UNICODE
#define CF_TTEXT	CF_UNICODETEXT
#else
#define CF_TTEXT	CF_TEXT
#endif

LONG    g_nComponents;
LONG    g_nServerLocks;
HMODULE g_hModule;

static AFX_EXTENSION_MODULE ijexp32DLL = { NULL, NULL };

extern "C" int APIENTRY
DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	UNREFERENCED_PARAMETER(lpReserved);

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		TRACE0("ijexp32.dll is initializing...\n");

		if (!AfxInitExtensionModule(ijexp32DLL, hInstance))
			return 0;

		new CDynLinkLibrary(ijexp32DLL);

#ifdef ICC_LISTVIEW_CLASSES
		HMODULE hmodComCtl = ::LoadLibrary(_T("comctl32.dll"));
		if (hmodComCtl) {
			LPFNINITCOMCTLEX lpfnInitComCtlEx = (LPFNINITCOMCTLEX)::GetProcAddress(hmodComCtl, "InitCommonControlsEx");
			if (lpfnInitComCtlEx) {
				INITCOMMONCONTROLSEX icc;
				icc.dwSize = sizeof(INITCOMMONCONTROLSEX);
				icc.dwICC  = ICC_LISTVIEW_CLASSES;
				(*lpfnInitComCtlEx)(&icc);
			}
			::FreeLibrary(hmodComCtl);
		}
#endif
		g_hModule = hInstance;
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		TRACE0("ijexp32.dll is terminating...\n");
		AfxTermExtensionModule(ijexp32DLL);
	}
	return 1;
}

STDAPI DllCanUnloadNow(void)
{
	if (g_nComponents) {
		return S_FALSE;
	}
	if (g_nServerLocks) {
		return S_FALSE;
	}
	return S_OK;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv)
{
	DWORD dwID;
	if (rclsid == CLSID_ExeHdr) {
		dwID = ID_EXEHDR;
	} else
	if (rclsid == CLSID_Export) {
		dwID = ID_EXPORT;
	} else
	if (rclsid == CLSID_Import) {
		dwID = ID_IMPORT;
	} else {
		return CLASS_E_CLASSNOTAVAILABLE;
	}
	CFactory *pFactory = new CFactory(dwID);
	if (pFactory == NULL) {
		return E_OUTOFMEMORY;
	}
	HRESULT hr = pFactory->QueryInterface(riid, ppv);
	pFactory->Release();
	return hr;
}

#if 0
#include "ijdll32.h"

TCHAR szAppNameHdr[] = _T("i.j Shell Property Sheet ExeHdr 32");
TCHAR szAppNameExp[] = _T("i.j Shell Property Sheet Export 32");
TCHAR szAppNameImp[] = _T("i.j Shell Property Sheet Import 32");

STDAPI DllRegisterServer(void)
{
	TCHAR szBuff[1024];
	::GetModuleFileName(g_hModule, szBuff, lengthof(szBuff));
	::ijRegisterServer(CLSID_ExeHdr, IJDLL32_RSF_SERVER_TYPE_INPROC | IJDLL32_RSF_THREADING_MODEL_APARTMENT, szBuff, szAppNameHdr, NULL, NULL, 0, NULL, 0);
	::ijRegisterServer(CLSID_Export, IJDLL32_RSF_SERVER_TYPE_INPROC | IJDLL32_RSF_THREADING_MODEL_APARTMENT, szBuff, szAppNameExp, NULL, NULL, 0, NULL, 0);
	::ijRegisterServer(CLSID_Import, IJDLL32_RSF_SERVER_TYPE_INPROC | IJDLL32_RSF_THREADING_MODEL_APARTMENT, szBuff, szAppNameImp, NULL, NULL, 0, NULL, 0);
	::ijStringFromGuid(CLSID_ExeHdr, szBuff, lengthof(szBuff));
	::ijRegSetKeyAndStrValue(HKEY_CLASSES_ROOT, _T("dllfile\\shellex\\PropertySheetHandlers"), szBuff, NULL, szAppNameHdr);
	::ijRegSetKeyAndStrValue(HKEY_CLASSES_ROOT, _T("exefile\\shellex\\PropertySheetHandlers"), szBuff, NULL, szAppNameHdr);
	::ijStringFromGuid(CLSID_Export, szBuff, lengthof(szBuff));
	::ijRegSetKeyAndStrValue(HKEY_CLASSES_ROOT, _T("dllfile\\shellex\\PropertySheetHandlers"), szBuff, NULL, szAppNameExp);
	::ijStringFromGuid(CLSID_Import, szBuff, lengthof(szBuff));
	::ijRegSetKeyAndStrValue(HKEY_CLASSES_ROOT, _T("dllfile\\shellex\\PropertySheetHandlers"), szBuff, NULL, szAppNameImp);
	::ijRegSetKeyAndStrValue(HKEY_CLASSES_ROOT, _T("exefile\\shellex\\PropertySheetHandlers"), szBuff, NULL, szAppNameImp);
	return S_OK;
}

STDAPI DllUnregisterServer(void)
{
	::ijUnregisterServer(CLSID_Import, NULL, NULL);
	::ijUnregisterServer(CLSID_Export, NULL, NULL);
	::ijUnregisterServer(CLSID_ExeHdr, NULL, NULL);
	return S_OK;
}
#endif

void MsgBox(HWND hwnd, LPCTSTR lpszCaption, UINT nId)
{
	CString strMsg;
	strMsg.LoadString(nId);
	::MessageBox(hwnd, strMsg, lpszCaption, MB_OK);
}

bool SetClipboardText(HWND hwnd, const CString &strText)
{
	bool ret = false;
	if (::OpenClipboard(hwnd)) {
		::EmptyClipboard();
		HGLOBAL hGlobal = ::GlobalAlloc(GMEM_MOVEABLE, (strText.GetLength() + 1) * sizeof(TCHAR));
		if (hGlobal != NULL) {
			LPTSTR str = reinterpret_cast<LPTSTR>(::GlobalLock(hGlobal));
			::lstrcpy(str, strText);
			::GlobalUnlock(hGlobal);
			::SetClipboardData(CF_TTEXT, hGlobal);
			ret = true;
		}
		::CloseClipboard();
	}
	return ret;
}

void LoadSetting(LPCTSTR lpKey, LPTSTR lpBuf, DWORD nSize, LPCTSTR lpDefault)
{
	if (lpBuf == NULL) {
		return;
	}
	if (lpDefault == NULL) {
		lpDefault = _T("");
	}
	::lstrcpy(lpBuf, lpDefault);

	DWORD cb = nSize * sizeof(TCHAR), type = 0;
	// Try to read from the registry first.
	if ((::SHGetValue(HKEY_CURRENT_USER, IJE_REG_KEY, lpKey,
				&type, lpBuf, &cb) != ERROR_SUCCESS) || (type != REG_SZ)) {
		// Try to read from the .ini file.
		TCHAR szIni[MAX_PATH];
		if (::GetModuleFileName(g_hModule, szIni, lengthof(szIni))) {
			int len = ::lstrlen(szIni) - 4;
			::lstrcpy(szIni + len, _T(".ini"));
			::GetPrivateProfileString(_T("ijexp32"), lpKey, lpDefault,
					lpBuf, nSize, szIni);
		}
	}
}
