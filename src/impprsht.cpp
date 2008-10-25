//
// impprsht.cpp
// Copyright (C) 1999 i.j , All rights reserved.
//

#include "stdafx.h"
#include "winnt.h"  // IMAGE_DIRECTORY_ENTRY_IMPORT
#include "ijexp32.h"
#include "resource.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CImpPropSheet::CImpPropSheet()
{
	m_nRef = 1;
	m_szPath[0] = _T('\0');
	::InterlockedIncrement(&g_nComponents);
}

CImpPropSheet::~CImpPropSheet()
{
	::InterlockedDecrement(&g_nComponents);
}

HRESULT STDMETHODCALLTYPE CImpPropSheet::QueryInterface(REFIID riid, LPVOID *ppv)
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

ULONG STDMETHODCALLTYPE CImpPropSheet::AddRef(void)
{
	return ::InterlockedIncrement(&m_nRef);
}

ULONG STDMETHODCALLTYPE CImpPropSheet::Release(void)
{
	if (::InterlockedDecrement(&m_nRef) == 0) {
		delete this;
		return 0;
	}
	return m_nRef;
}

HRESULT STDMETHODCALLTYPE CImpPropSheet::Initialize(LPCITEMIDLIST pidlFolder, LPDATAOBJECT lpDatObj, HKEY hkeyProgID)
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

HRESULT STDMETHODCALLTYPE CImpPropSheet::AddPages(LPFNADDPROPSHEETPAGE lpfnAddPage, LPARAM lParam)
{
	PROPSHEETPAGE psp;
	psp.dwSize      = sizeof(PROPSHEETPAGE);
	psp.dwFlags     = PSP_USEREFPARENT;
	psp.hInstance   = g_hModule;
	psp.pszTemplate = MAKEINTRESOURCE(IsWindowsXP() ? IDD_IMPPROPPAGE_EX : IDD_IMPPROPPAGE);
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

HRESULT STDMETHODCALLTYPE CImpPropSheet::ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE lpfnReplacePage, LPARAM lParam)
{
	return E_FAIL;
}

INT_PTR CALLBACK CImpPropSheet::DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_INITDIALOG:
		{
			PROPSHEETPAGE *pPSP = reinterpret_cast<PROPSHEETPAGE *>(lParam);
			::SetWindowLongPtr(hwnd, DWLP_USER, pPSP->lParam);
			CAnalyzer ana;
			if (ana.Open(hwnd, reinterpret_cast<CImpPropSheet *>(pPSP->lParam)->m_szPath)) {
				if (ana.ReadSection(hwnd, IMAGE_DIRECTORY_ENTRY_IMPORT)) {
					::SendMessage(::GetDlgItem(hwnd, IDC_FUNC), BM_SETCHECK, BST_CHECKED, 0);
					::SendMessage(::GetDlgItem(hwnd, IDC_VC),   BM_SETCHECK, BST_CHECKED, 0);
					HWND hwndList = ::GetDlgItem(hwnd, IDC_LIST);
					ana.AnalyzeImportInit(hwndList);
					ana.AnalyzeImport(hwndList, true, true);
				}
				ana.Close();
			}
		}
		return TRUE;
	case WM_DESTROY:
		reinterpret_cast<CImpPropSheet *>(::GetWindowLongPtr(hwnd, DWLP_USER))->Release();
		return TRUE;
	case WM_COMMAND:
		if (HIWORD(wParam) == BN_CLICKED) {
			switch (LOWORD(wParam)) {
			case IDC_FUNC:
			case IDC_VC:
				{
					CAnalyzer ana;
					if (ana.Open(hwnd, reinterpret_cast<CImpPropSheet *>(::GetWindowLongPtr(hwnd, DWLP_USER))->m_szPath)) {
						if (ana.ReadSection(hwnd, IMAGE_DIRECTORY_ENTRY_IMPORT)) {
							bool bFunc   = ::SendMessage(::GetDlgItem(hwnd, IDC_FUNC), BM_GETCHECK, 0, 0) == BST_CHECKED;
							bool bDecode = ::SendMessage(::GetDlgItem(hwnd, IDC_VC),   BM_GETCHECK, 0, 0) == BST_CHECKED;
							ana.AnalyzeImport(::GetDlgItem(hwnd, IDC_LIST), bFunc, bDecode);
						}
						ana.Close();
					}
				}
				return TRUE;
			case IDC_SAVE:
				CWnd wnd;
				wnd.Attach(hwnd);
				CString strWork;
				strWork.LoadString(IDS_FILE_MATCH);
				CFileDialog dlg(FALSE, NULL, NULL, OFN_HIDEREADONLY | OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR, strWork, &wnd);
				if (dlg.DoModal() == IDOK) {
					CStdioFile file;
					if (file.Open(dlg.GetPathName(), CFile::modeCreate | CFile::modeWrite | CFile::shareExclusive | CFile::typeText)) {
						try {
							bool bFunc = ::SendMessage(::GetDlgItem(hwnd, IDC_FUNC), BM_GETCHECK, 0, 0) == BST_CHECKED;
							CString strLine;
							CListCtrl list;
							list.Attach(::GetDlgItem(hwnd, IDC_LIST));
							for (int nCount = 0; nCount < list.GetItemCount(); nCount++) {
								strLine = list.GetItemText(nCount, 0);
								if (bFunc) {
									strLine += _T(", ") + list.GetItemText(nCount, 1) + _T(", ") + list.GetItemText(nCount, 2);
								}
								strLine += _T("\n");
								file.WriteString(strLine);
							}
							list.Detach();
						} catch (CException *e) {
							e->Delete();
						}
						file.Close();
					}
				}
				wnd.Detach();
				return TRUE;
			}
		}
		break;
	}
	return FALSE;
}
