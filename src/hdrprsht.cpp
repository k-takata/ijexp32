//
// hdrprsht.cpp
// Copyright (C) 1999 i.j , All rights reserved.
//

#include "stdafx.h"
#include "winnt.h"  // PE format structures
#include "ijexp32.h"
#include "resource.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CHdrPropSheet::CHdrPropSheet()
{
	m_nRef = 1;
	m_szPath[0] = _T('\0');
	::InterlockedIncrement(&g_nComponents);
}

CHdrPropSheet::~CHdrPropSheet()
{
	::InterlockedDecrement(&g_nComponents);
}

HRESULT STDMETHODCALLTYPE CHdrPropSheet::QueryInterface(REFIID riid, LPVOID *ppv)
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

ULONG STDMETHODCALLTYPE CHdrPropSheet::AddRef(void)
{
	return ::InterlockedIncrement(&m_nRef);
}

ULONG STDMETHODCALLTYPE CHdrPropSheet::Release(void)
{
	if (::InterlockedDecrement(&m_nRef) == 0) {
		delete this;
		return 0;
	}
	return m_nRef;
}

HRESULT STDMETHODCALLTYPE CHdrPropSheet::Initialize(LPCITEMIDLIST pidlFolder, LPDATAOBJECT lpDatObj, HKEY hkeyProgID)
{
	if (lpDatObj == NULL) {
		return E_FAIL;
	}
	FORMATETC fmtetc;
	STGMEDIUM medium;
	fmtetc.cfFormat = CF_HDROP;
	fmtetc.ptd      = NULL;
	fmtetc.dwAspect = DVASPECT_CONTENT;
	fmtetc.lindex   = -1;
	fmtetc.tymed    = TYMED_HGLOBAL;
	if (FAILED(lpDatObj->GetData(&fmtetc, &medium))) {
		return E_FAIL;
	}
	HDROP hDrop = static_cast<HDROP>(medium.hGlobal);
	if (::DragQueryFile(hDrop, -1, NULL, 0) != 1) { // not multi files.
		::ReleaseStgMedium(&medium);
		return E_FAIL;
	}
	::DragQueryFile(hDrop, 0, m_szPath, sizeof(m_szPath));
	::ReleaseStgMedium(&medium);
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CHdrPropSheet::AddPages(LPFNADDPROPSHEETPAGE lpfnAddPage, LPARAM lParam)
{
	PROPSHEETPAGE psp;
	psp.dwSize      = sizeof(PROPSHEETPAGE);
	psp.dwFlags     = PSP_USEREFPARENT;
	psp.hInstance   = g_hModule;
	psp.pszTemplate = MAKEINTRESOURCE(IsWindowsXP() ? IDD_HDRPROPPAGE_EX : IDD_HDRPROPPAGE);
	psp.pszIcon     = 0;
	psp.pszTitle    = NULL;
	psp.pfnDlgProc  = (DLGPROC) DlgProc;
	psp.lParam      = reinterpret_cast<LPARAM>(this);
	psp.pfnCallback = NULL;
	psp.pcRefParent = reinterpret_cast<UINT *>(&g_nComponents);

	HPROPSHEETPAGE hPage = ::CreatePropertySheetPage(&psp);
	if (hPage) {
		if (!lpfnAddPage(hPage, lParam)) {
			::DestroyPropertySheetPage(hPage);
		}
	}
	AddRef();
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CHdrPropSheet::ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE lpfnReplacePage, LPARAM lParam)
{
	return E_FAIL;
}

INT_PTR CALLBACK CHdrPropSheet::DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_INITDIALOG:
		{
			PROPSHEETPAGE *pPSP = reinterpret_cast<PROPSHEETPAGE *>(lParam);
			::SetWindowLongPtr(hwnd, DWLP_USER, pPSP->lParam);
			CAnalyzer ana;
			if (ana.Open(hwnd, reinterpret_cast<CHdrPropSheet *>(pPSP->lParam)->m_szPath)) {
				ana.Close();
				HWND hwndHdrList = ::GetDlgItem(hwnd, IDC_HDR_LIST);
				HWND hwndDirList = ::GetDlgItem(hwnd, IDC_DIR_LIST);
				HWND hwndSecList = ::GetDlgItem(hwnd, IDC_SEC_LIST);
				::ShowWindow(hwndHdrList, SW_NORMAL);
				::ShowWindow(hwndDirList, SW_HIDE);
				::ShowWindow(hwndSecList, SW_HIDE);
				ana.AnalyzeExeHdrInit(hwndHdrList, hwndDirList, hwndSecList);
				ana.AnalyzeExeHdr(hwndHdrList, hwndDirList, hwndSecList);
			}
		}
		return TRUE;
	case WM_DESTROY:
		reinterpret_cast<CImpPropSheet *>(::GetWindowLongPtr(hwnd, DWLP_USER))->Release();
		return TRUE;
	case WM_COMMAND:
		if (HIWORD(wParam) == BN_CLICKED) {
			switch (LOWORD(wParam)) {
			case IDC_HDR:
				::ShowWindow(::GetDlgItem(hwnd, IDC_HDR_LIST), SW_NORMAL);
				::ShowWindow(::GetDlgItem(hwnd, IDC_DIR_LIST), SW_HIDE);
				::ShowWindow(::GetDlgItem(hwnd, IDC_SEC_LIST), SW_HIDE);
				return TRUE;
			case IDC_DIR:
				::ShowWindow(::GetDlgItem(hwnd, IDC_HDR_LIST), SW_HIDE);
				::ShowWindow(::GetDlgItem(hwnd, IDC_DIR_LIST), SW_NORMAL);
				::ShowWindow(::GetDlgItem(hwnd, IDC_SEC_LIST), SW_HIDE);
				return TRUE;
			case IDC_SEC:
				::ShowWindow(::GetDlgItem(hwnd, IDC_HDR_LIST), SW_HIDE);
				::ShowWindow(::GetDlgItem(hwnd, IDC_DIR_LIST), SW_HIDE);
				::ShowWindow(::GetDlgItem(hwnd, IDC_SEC_LIST), SW_NORMAL);
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
								file.WriteString(GetText(hwnd, false));
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
				SetClipboardText(hwnd, GetText(hwnd, true));
				return TRUE;
			}
		}
		break;
	}
	return FALSE;
}

CString CHdrPropSheet::GetText(HWND hwnd, bool bBinary)
{
	CString strText;
	CString strEOL = (bBinary) ? _T("\r\n") : _T("\n");
	CListCtrl list;
	list.Attach(::GetDlgItem(hwnd, IDC_HDR_LIST));
	for (int nCount = 0; nCount < list.GetItemCount(); nCount++) {
		strText += list.GetItemText(nCount, 0);
		CString strValue = list.GetItemText(nCount, 1);
		if (!strValue.IsEmpty()) {
			strText += _T(", ") + strValue;
		}
		strText += strEOL;
	}
	list.Detach();
	strText += strEOL + _T("Directories :") + strEOL;
	list.Attach(::GetDlgItem(hwnd, IDC_DIR_LIST));
	for (int nCount = 0; nCount < list.GetItemCount(); nCount++) {
		strText += list.GetItemText(nCount, 0) + _T(", ") + list.GetItemText(nCount, 1) + _T(", ") + list.GetItemText(nCount, 2) + strEOL;
	}
	list.Detach();
	strText += strEOL + _T("Sections :") + strEOL;
	list.Attach(::GetDlgItem(hwnd, IDC_SEC_LIST));
	for (int nCount = 0; nCount < list.GetItemCount(); nCount++) {
		strText += list.GetItemText(nCount, 0);
		for (int nSub = 1; nSub <= 9; nSub++) {
			strText += _T(", ") + list.GetItemText(nCount, nSub);
		}
		strText += strEOL;
	}
	list.Detach();
	return strText;
}
