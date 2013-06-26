//
// expprsht.cpp
// Copyright (C) 1999 i.j , All rights reserved.
//

#include "stdafx.h"
#include <winnt.h>  // IMAGE_DIRECTORY_ENTRY_EXPORT
#include <windowsx.h>
#include "ijexp32.h"
#include "resource.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CExpPropSheet::CExpPropSheet()
{
//OutputDebugString(_T("CExpPropSheet::CExpPropSheet()\n"));
	m_nRef = 1;
	m_szPath[0] = _T('\0');
	::InterlockedIncrement(&g_nComponents);
}

CExpPropSheet::~CExpPropSheet()
{
//OutputDebugString(_T("CExpPropSheet::~CExpPropSheet()\n"));
	::InterlockedDecrement(&g_nComponents);
}

HRESULT STDMETHODCALLTYPE CExpPropSheet::QueryInterface(REFIID riid, LPVOID *ppv)
{
	if (riid == IID_IUnknown) {
		*ppv = static_cast<IShellExtInit *>(this);
	} else
	if (riid == IID_IShellExtInit) {
		*ppv = static_cast<IShellExtInit *>(this);
	} else
	if (riid == IID_IShellPropSheetExt) {
		*ppv = static_cast<IShellPropSheetExt *>(this);
	} else {
		*ppv = NULL;
		return E_NOINTERFACE;
	}
	static_cast<IUnknown *>(*ppv)->AddRef();
	return S_OK;
}

ULONG STDMETHODCALLTYPE CExpPropSheet::AddRef(void)
{
	return ::InterlockedIncrement(&m_nRef);
}

ULONG STDMETHODCALLTYPE CExpPropSheet::Release(void)
{
	if (::InterlockedDecrement(&m_nRef) == 0) {
		delete this;
		return 0;
	}
	return m_nRef;
}

HRESULT STDMETHODCALLTYPE CExpPropSheet::Initialize(LPCITEMIDLIST pidlFolder, LPDATAOBJECT lpDatObj, HKEY hkeyProgID)
{
	// This PropSheet is added only when an export section is available.
	// Just return E_FAIL here.
	return E_FAIL;
}

HRESULT STDMETHODCALLTYPE CExpPropSheet::AddPages(LPFNADDPROPSHEETPAGE lpfnAddPage, LPARAM lParam)
{
	PROPSHEETPAGE psp;
	psp.dwSize      = sizeof(PROPSHEETPAGE);
	psp.dwFlags     = PSP_USEREFPARENT | PSP_USECALLBACK;
	psp.hInstance   = g_hModule;
	psp.pszTemplate = MAKEINTRESOURCE(IsWindowsXP() ? IDD_EXPPROPPAGE_EX : IDD_EXPPROPPAGE);
	psp.pszIcon     = 0;
	psp.pszTitle    = NULL;
	psp.pfnDlgProc  = (DLGPROC) DlgProc;
	psp.lParam      = reinterpret_cast<LPARAM>(this);
	psp.pfnCallback = PropSheetPageProc;
	psp.pcRefParent = reinterpret_cast<UINT *>(&g_nComponents);

	HPROPSHEETPAGE hPage = ::CreatePropertySheetPage(&psp);
	if (hPage) {
		if (!lpfnAddPage(hPage, lParam)) {
			::DestroyPropertySheetPage(hPage);
			return E_FAIL;
		}
	}
	AddRef();
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CExpPropSheet::ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE lpfnReplacePage, LPARAM lParam)
{
	return E_FAIL;
}

void CExpPropSheet::SetPath(LPCTSTR szPath)
{
	::lstrcpy(m_szPath, szPath);
}

UINT CALLBACK CExpPropSheet::PropSheetPageProc(HWND hwnd, UINT msg, LPPROPSHEETPAGE ppsp)
{
	switch (msg) {
	case PSPCB_RELEASE:
		reinterpret_cast<CImpPropSheet *>(ppsp->lParam)->Release();
		return TRUE;
	}
	return TRUE;
}

INT_PTR CALLBACK CExpPropSheet::DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_INITDIALOG:
		{
			PROPSHEETPAGE *pPSP = reinterpret_cast<PROPSHEETPAGE *>(lParam);
			::SetWindowLongPtr(hwnd, DWLP_USER, pPSP->lParam);
			CAnalyzer ana;
			if (ana.Open(hwnd, reinterpret_cast<CExpPropSheet *>(pPSP->lParam)->m_szPath)) {
				if (ana.ReadSection(hwnd, IMAGE_DIRECTORY_ENTRY_EXPORT)) {
					HWND hwndMsg  = ::GetDlgItem(hwnd, IDC_MSG);
					HWND hwndList = ::GetDlgItem(hwnd, IDC_LIST);
					::ShowWindow(hwndMsg,  SW_NORMAL);
					::ShowWindow(hwndList, SW_HIDE);
					::SendMessage(::GetDlgItem(hwnd, IDC_VC), BM_SETCHECK, BST_CHECKED, 0);
					ana.AnalyzeExportInit(hwndList);
					ana.AnalyzeExport(hwndMsg, hwndList, true);
				}
				ana.Close();
			}
		}
		return TRUE;
//	case WM_DESTROY:
//		reinterpret_cast<CImpPropSheet *>(::GetWindowLongPtr(hwnd, DWLP_USER))->Release();
//		return TRUE;
	case WM_COMMAND:
		if (HIWORD(wParam) == BN_CLICKED) {
			bool bDecode = (::SendMessage(::GetDlgItem(hwnd, IDC_VC), BM_GETCHECK, 0, 0) == BST_CHECKED);
			switch (LOWORD(wParam)) {
			case IDC_VC:
				::ShowWindow(::GetDlgItem(hwnd, IDC_MSG),  bDecode);
				::ShowWindow(::GetDlgItem(hwnd, IDC_LIST), !bDecode);
				return TRUE;
			case IDC_SAVE:
				{
					CWnd wnd;
					wnd.Attach(hwnd);
					CString strWork;
					strWork.LoadString(IDS_FILE_MATCH);
					CFileDialog dlg(FALSE, NULL, NULL, OFN_HIDEREADONLY | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR, strWork, &wnd);
					if (dlg.DoModal() == IDOK) {
						CStdioFile file;
						if (file.Open(dlg.GetPathName(), CFile::modeCreate | CFile::modeWrite | CFile::shareExclusive | CFile::typeText)) {
							try {
								file.WriteString(GetText(hwnd, false, bDecode, false));
							} catch (CException *e) {
								e->Delete();
							}
							file.Close();
						}
					}
					wnd.Detach();
					return TRUE;
				}
			case IDC_COPY:
				SetClipboardText(hwnd, GetText(hwnd, true, bDecode, false));
				return TRUE;
			case IDC_COPY_SELECTED_LINE:
				SetClipboardText(hwnd, GetText(hwnd, true, bDecode, true));
				return TRUE;
			}
		}
		break;
	case WM_CONTEXTMENU:
		if ((HWND) wParam == ::GetDlgItem(hwnd, IDC_LIST)) {
			CMenu menu;
			menu.LoadMenu(IDM_CONTEXTMENU);
			CMenu *popupmenu = menu.GetSubMenu(0);
			::TrackPopupMenu(HMENU(*popupmenu), TPM_RIGHTBUTTON,
					GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam),
					0, hwnd, NULL);
		}
	}
	return FALSE;
}

CString CExpPropSheet::GetText(HWND hwnd, bool bBinary, bool bDecode, bool bSelectedOnly)
{
	CString strText;
	CString strEOL = (bBinary) ? _T("\r\n") : _T("\n");
	if (bDecode) {
		HWND hwndMsg = ::GetDlgItem(hwnd, IDC_MSG);
		CWnd wndMsg;
		wndMsg.Attach(hwndMsg);
		wndMsg.GetWindowText(strText);
		wndMsg.Detach();
		if (!bBinary) {
			strText.Remove(_T('\r'));
		}
	} else {
		CListCtrl list;
		list.Attach(::GetDlgItem(hwnd, IDC_LIST));
		for (int nCount = 0; nCount < list.GetItemCount(); nCount++) {
			if (bSelectedOnly && !list.GetItemState(nCount, LVIS_SELECTED)) {
				continue;
			}
			strText += list.GetItemText(nCount, 0) + _T(", ");
			strText += list.GetItemText(nCount, 1) + strEOL;
		}
		list.Detach();
	}
	return strText;
}
