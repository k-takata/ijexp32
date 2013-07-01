//
// impprsht.cpp
// Copyright (C) 1999 i.j , All rights reserved.
//

#include "stdafx.h"
#include <winnt.h>  // IMAGE_DIRECTORY_ENTRY_IMPORT
#include <windowsx.h>
#include "ijexp32.h"
#include "resource.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CImpPropSheet::CImpPropSheet()
{
//OutputDebugString(_T("CImpPropSheet::CImpPropSheet()\n"));
	m_nRef = 1;
	m_szPath[0] = _T('\0');
	::InterlockedIncrement(&g_nComponents);
}

CImpPropSheet::~CImpPropSheet()
{
//OutputDebugString(_T("CImpPropSheet::~CImpPropSheet()\n"));
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
	// This PropSheet is added only when an import section is available.
	// Just return E_FAIL here.
	return E_FAIL;
}

HRESULT STDMETHODCALLTYPE CImpPropSheet::AddPages(LPFNADDPROPSHEETPAGE lpfnAddPage, LPARAM lParam)
{
	PROPSHEETPAGE psp;
	psp.dwSize      = sizeof(PROPSHEETPAGE);
	psp.dwFlags     = PSP_USEREFPARENT | PSP_USECALLBACK;
	psp.hInstance   = g_hModule;
	psp.pszTemplate = MAKEINTRESOURCE(IsWindowsXP() ? IDD_IMPPROPPAGE_EX : IDD_IMPPROPPAGE);
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
	for (int i = 0; i < IMP_STATUS_NUM; i++) {
		m_SortStatus[i] = 0;
	}
	AddRef();
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CImpPropSheet::ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE lpfnReplacePage, LPARAM lParam)
{
	return E_FAIL;
}

void CImpPropSheet::SetPath(LPCTSTR szPath)
{
	::lstrcpy(m_szPath, szPath);
}

UINT CALLBACK CImpPropSheet::PropSheetPageProc(HWND hwnd, UINT msg, LPPROPSHEETPAGE ppsp)
{
	switch (msg) {
	case PSPCB_RELEASE:
		reinterpret_cast<CImpPropSheet *>(ppsp->lParam)->Release();
		return TRUE;
	}
	return TRUE;
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
//	case WM_DESTROY:
//		reinterpret_cast<CImpPropSheet *>(::GetWindowLongPtr(hwnd, DWLP_USER))->Release();
//		return TRUE;
	case WM_COMMAND:
		if (HIWORD(wParam) == BN_CLICKED) {
			switch (LOWORD(wParam)) {
			case IDC_FUNC:
			case IDC_VC:
				{
					CAnalyzer ana;
					CImpPropSheet *impprop = reinterpret_cast<CImpPropSheet *>(::GetWindowLongPtr(hwnd, DWLP_USER));
					if (ana.Open(hwnd, impprop->m_szPath)) {
						if (ana.ReadSection(hwnd, IMAGE_DIRECTORY_ENTRY_IMPORT)) {
							bool bFunc   = ::SendMessage(::GetDlgItem(hwnd, IDC_FUNC), BM_GETCHECK, 0, 0) == BST_CHECKED;
							bool bDecode = ::SendMessage(::GetDlgItem(hwnd, IDC_VC),   BM_GETCHECK, 0, 0) == BST_CHECKED;
							ana.AnalyzeImport(::GetDlgItem(hwnd, IDC_LIST), bFunc, bDecode);
						}
						ana.Close();
					}

					int bSort = 0;
					for (int i = 0; i < IMP_STATUS_NUM; i++) {
						bSort |= impprop->m_SortStatus[i];
					}
					if (bSort) {
						CListCtrl list;
						list.Attach(::GetDlgItem(hwnd, IDC_LIST));
						list.SortItems(Compare, reinterpret_cast<DWORD_PTR>(hwnd));
						list.Detach();
					}
				}
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
								file.WriteString(GetText(hwnd, false, false));
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
				SetClipboardText(hwnd, GetText(hwnd, true, false));
				return TRUE;
			case IDC_COPY_SELECTED_LINE:
				SetClipboardText(hwnd, GetText(hwnd, true, true));
				return TRUE;
			}
		}
		break;
	case WM_CONTEXTMENU:
		if ((HWND) wParam == ::GetDlgItem(hwnd, IDC_LIST)) {
			CMenu menu;
			menu.LoadMenu(IDM_CONTEXTMENU);
			CMenu *popupmenu = menu.GetSubMenu(0);
			popupmenu->TrackPopupMenu(TPM_RIGHTBUTTON,
					GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam),
					CWnd::FromHandle(hwnd), NULL);
		}
		break;
	case WM_NOTIFY:
		{
			LPNMHDR hdr = reinterpret_cast<LPNMHDR>(lParam);
			if ((hdr->idFrom == IDC_LIST) && (hdr->code == LVN_COLUMNCLICK)) {
				LPNMLISTVIEW nmlv = reinterpret_cast<LPNMLISTVIEW>(hdr);
				CImpPropSheet *impprop = reinterpret_cast<CImpPropSheet *>(::GetWindowLongPtr(hwnd, DWLP_USER));
				impprop->OnColumnClick(hwnd, nmlv);
			}
		}
		break;
	}
	return FALSE;
}

CString CImpPropSheet::GetText(HWND hwnd, bool bBinary, bool bSelectedOnly)
{
	CString strText;
	CString strEOL = (bBinary) ? _T("\r\n") : _T("\n");
	bool bFunc = ::SendMessage(::GetDlgItem(hwnd, IDC_FUNC), BM_GETCHECK, 0, 0) == BST_CHECKED;
	CListCtrl list;
	list.Attach(::GetDlgItem(hwnd, IDC_LIST));
	for (int nCount = 0; nCount < list.GetItemCount(); nCount++) {
		if (bSelectedOnly && !list.GetItemState(nCount, LVIS_SELECTED)) {
			continue;
		}
		strText += list.GetItemText(nCount, 0);
		if (bFunc) {
			strText += _T(", ") + list.GetItemText(nCount, 1) + _T(", ") + list.GetItemText(nCount, 2);
		}
		strText += strEOL;
	}
	list.Detach();
	return strText;
}

void CImpPropSheet::OnColumnClick(HWND hwnd, LPNMLISTVIEW nmlv)
{
	CListCtrl list;
	list.Attach(nmlv->hdr.hwndFrom);

	// No Sort -> Sort Up -> Sort Down -> No Sort -> ...
	int &status = m_SortStatus[nmlv->iSubItem];
	if (status & HDF_SORTUP) {
		status = HDF_SORTDOWN;
	} else if (status & HDF_SORTDOWN) {
		status = 0;
	} else {
		status = HDF_SORTUP;
	}

	if (status) {
		// Sorting by name and ordinal are exclusive.
		if (nmlv->iSubItem > 0) {
			m_SortStatus[IMP_STATUS_NUM - nmlv->iSubItem] = 0;

			// Always sort by server name.
			if ((m_SortStatus[0] & (HDF_SORTDOWN | HDF_SORTUP)) == 0) {
				m_SortStatus[0] = HDF_SORTUP;
			}
		}
	}

	// Set the status to the header control.
	CHeaderCtrl *hdrctrl = list.GetHeaderCtrl();
	for (int i = 0; i < IMP_STATUS_NUM; i++) {
		HDITEM hditem;
		hditem.mask = HDI_FORMAT;
		hdrctrl->GetItem(i, &hditem);
		hditem.fmt &= ~(HDF_SORTDOWN | HDF_SORTUP);
		hditem.fmt |= m_SortStatus[i];
		hdrctrl->SetItem(i, &hditem);
	}

	// Do sorting.
	list.SortItems(Compare, reinterpret_cast<DWORD_PTR>(hwnd));
	list.Detach();
}

int CALLBACK CImpPropSheet::Compare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	HWND hwnd = reinterpret_cast<HWND>(lParamSort);
	CImpPropSheet *impprop = reinterpret_cast<CImpPropSheet *>(::GetWindowLongPtr(hwnd, DWLP_USER));

	// Check the sorting type: by name or ordinal
	int subitem = 0;
	for (int i = 1; i < IMP_STATUS_NUM; i++) {
		if (impprop->m_SortStatus[i]) {
			subitem = i;
			break;
		}
	}
	if ((subitem == 0) && (impprop->m_SortStatus[0] == 0)) {
		// Do not sort.
		return static_cast<int>(lParam1 - lParam2);
	}

	int ret = 0;
	CListCtrl list;
	list.Attach(::GetDlgItem(hwnd, IDC_LIST));

	LVFINDINFO lvfi = {0};
	lvfi.flags = LVFI_PARAM;
	lvfi.lParam = lParam1;
	int item1 = list.FindItem(&lvfi);
	lvfi.lParam = lParam2;
	int item2 = list.FindItem(&lvfi);

	// Always sort by server name first.
	CString strServer1 = list.GetItemText(static_cast<int>(item1), 0);
	CString strServer2 = list.GetItemText(static_cast<int>(item2), 0);
	ret = strServer1.Compare(strServer2);
	if (impprop->m_SortStatus[0] & HDF_SORTDOWN) {
		ret = -ret;
	}
	// Sort by name or ordinal if needed.
	if (ret == 0) {
		if (subitem) {
			CString str1 = list.GetItemText(static_cast<int>(item1), subitem);
			CString str2 = list.GetItemText(static_cast<int>(item2), subitem);
			ret = str1.Compare(str2);
			if (impprop->m_SortStatus[subitem] & HDF_SORTDOWN) {
				ret = -ret;
			}
		} else {
			ret = static_cast<int>(lParam1 - lParam2);
		}
	}
	list.Detach();
	return ret;
}
