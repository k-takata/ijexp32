//
// analyzer.cpp
// Copyright (C) 1999 i.j , All rights reserved.
//

#include "stdafx.h"
#include "tchar.h" // _tcsrchr(), _tcstoul()
#include "ijexp32.h"
#include "resource.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

static TCHAR szHex4Fmt[] = _T("%04x");
static TCHAR szHex8Fmt[] = _T("%08x");
static TCHAR szAddrFmt[] = _T("%04x:%04x");
static TCHAR szVerFmt [] = _T("%d.%d");

setstr_t defaultSetStr; // for m_mapCls[strCls].resize()

/////////////////////////////////////////////////////////////////////////////
// CAnalyzer ダイアログ

CAnalyzer::CAnalyzer()
{
	m_bOpCast = false;
	m_dwDirAddr = 0;
	m_dwSecAddr = 0;
	::ZeroMemory(&m_dos_hdr, sizeof(m_dos_hdr));
	::ZeroMemory(&m_nt_hdr,  sizeof(m_nt_hdr));
}

CAnalyzer::~CAnalyzer()
{
}

void CAnalyzer::LoadExpFile(LPCTSTR lpszServer)
{
	TCHAR szBuff[1024];
	if (::GetModuleFileName(g_hModule, szBuff, lengthof(szBuff))) {
		LPTSTR lpszTemp = _tcsrchr(szBuff, _T('\\'));
		if (lpszTemp) {
			::lstrcpy(lpszTemp + 1, lpszServer);
			lpszTemp = _tcsrchr(szBuff, _T('.'));
			if (lpszTemp) {
				*lpszTemp = _T('\0');
			}
			::lstrcat(szBuff, _T(".exp"));
			CStdioFile file;
			if (file.Open(szBuff, CFile::modeRead | CFile::shareDenyWrite | CFile::typeText)) {
				try {
					CString strLine, strOrdinal, strName;
					while (file.ReadString(strLine)) {
						strLine.TrimLeft();
						if (strLine[0] != _T('#')) { // not comment line.
							int nOffset = strLine.Find(_T(','));
							if (nOffset > 1) {
								strOrdinal = strLine.Left(nOffset);
								strOrdinal.TrimRight();
								strName = strLine.Mid(nOffset + 1);
								strName.TrimLeft();
								DWORD dwOrdinal = _tcstoul(strOrdinal, NULL, 16); // string -> hex.
								if (dwOrdinal) {
									m_mapExp[lpszServer][dwOrdinal] = strName;
								}
							}
						}
					}
				} catch (CException *e) {
					e->Delete();
				}
				file.Close();
			}
		}
	}
}

bool CAnalyzer::Open(HWND hwnd, LPCTSTR lpszPath)
{
	if (m_file.Open(lpszPath, CFile::modeRead | CFile::shareDenyWrite) == FALSE) {
		::MsgBox(hwnd, lpszPath, IDS_COULD_NOT_OPEN);
		return false;
	}
	try {
		m_file.Read(&m_dos_hdr, sizeof(IMAGE_DOS_HEADER)); // read MZ hdr
		if (m_dos_hdr.e_magic == IMAGE_DOS_SIGNATURE) {
			if (m_dos_hdr.e_cparhdr >= (sizeof(IMAGE_DOS_HEADER) + 0x0f) >> 4) { // unit : paragraph
				DWORD dwPeHdrOffset = m_dos_hdr.e_lfanew;
				m_file.Seek(dwPeHdrOffset, CFile::begin);
				m_file.Read(&m_nt_hdr, sizeof(IMAGE_NT_HEADERS)); // read PE hdr
				if (m_nt_hdr.Signature == IMAGE_NT_SIGNATURE) {
					if ((m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) && (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
						if (m_nt_hdr.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
//							DWORD dwPeHdrOffset = m_dos_hdr.e_lfanew;
							DWORD dwSecEntry = m_nt_hdr.FileHeader.NumberOfSections;
							DWORD dwSecOffset = dwPeHdrOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + m_nt_hdr.FileHeader.SizeOfOptionalHeader;
							m_file.Seek(dwSecOffset, CFile::begin);
							m_vecSecHdr.resize(dwSecEntry);
							m_file.Read(&m_vecSecHdr.front(), IMAGE_SIZEOF_SECTION_HEADER * dwSecEntry); // read section hdr. block.
							return true;
						} else {
							::MsgBox(hwnd, m_file.GetFilePath(), IDS_NOT_OPT_HDR);
						}
					} else {
						::MsgBox(hwnd, m_file.GetFilePath(), IDS_NOT_EXE32);
					}
				} else {
					::MsgBox(hwnd, m_file.GetFilePath(), IDS_NOT_PE_FILE);
				}
			} else {
				::MsgBox(hwnd, m_file.GetFilePath(), IDS_NOT_NEW_HDR);
			}
		} else {
			::MsgBox(hwnd, m_file.GetFilePath(), IDS_NOT_EXEC);
		}
	} catch (CFileException *e) {
		e->Delete();
		::MsgBox(hwnd, m_file.GetFilePath(), IDS_COULD_NOT_READ);
	}
	m_file.Close();
	return false;
}

void CAnalyzer::Close(void)
{
	m_file.Close();
}

bool CAnalyzer::ReadSection(HWND hwnd, int nDirectory)
{
	try {
		m_dwDirAddr = m_nt_hdr.OptionalHeader.DataDirectory[nDirectory].VirtualAddress;
		for (vector<IMAGE_SECTION_HEADER>::const_iterator it = m_vecSecHdr.begin(); it != m_vecSecHdr.end(); ++it) {
			m_dwSecAddr = it->VirtualAddress;
			DWORD dwOffset = m_dwDirAddr - m_dwSecAddr; // a result is unsigned, because need to wrap-around to big number, when underflow.
			DWORD dwSecSize = it->Misc.VirtualSize;
			if (dwOffset < dwSecSize) {
				m_file.Seek(it->PointerToRawData, CFile::begin); // seek to start of target section.
				m_vecBuff.resize(dwSecSize);
				m_file.Read(&m_vecBuff.front(), dwSecSize); // read target section.
				return true;
			}
		}
		::MsgBox(hwnd, m_file.GetFilePath(), IDS_COULD_NOT_FIND_SECTION);
	} catch (CFileException *e) {
		e->Delete();
		::MsgBox(hwnd, m_file.GetFilePath(), IDS_COULD_NOT_READ);
	}
	m_file.Close();
	return false;
}

void CAnalyzer::AnalyzeExeHdrInit(HWND hwndHdrList, HWND hwndDirList, HWND hwndSecList)
{
	CListCtrl list;
	LV_COLUMN lvcolumn;

	list.Attach(hwndHdrList);

#ifdef LVM_SETEXTENDEDLISTVIEWSTYLE
	list.SendMessage(LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
#endif

	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Name");
	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 128;
	list.InsertColumn(0, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Value");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 200;
	list.InsertColumn(1, &lvcolumn);

	list.Detach();

	list.Attach(hwndDirList);

#ifdef LVM_SETEXTENDEDLISTVIEWSTYLE
	list.SendMessage(LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
#endif

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Name");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 64;
	list.InsertColumn(0, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Addr");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 64;
	list.InsertColumn(1, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Size");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 64;
	list.InsertColumn(2, &lvcolumn);

	list.Detach();

	list.Attach(hwndSecList);

#ifdef LVM_SETEXTENDEDLISTVIEWSTYLE
	list.SendMessage(LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
#endif

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Section");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 64;
	list.InsertColumn(0, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Addr");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 64;
	list.InsertColumn(1, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Size");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 64;
	list.InsertColumn(2, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("AlignSize");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 64;
	list.InsertColumn(3, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("FileOff");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 64;
	list.InsertColumn(4, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("RelocOff");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 64;
	list.InsertColumn(5, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Lin#Off");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 64;
	list.InsertColumn(6, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Rel#");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 40;
	list.InsertColumn(7, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Lin#");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 40;
	list.InsertColumn(8, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Flags");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 160;	//80
	list.InsertColumn(9, &lvcolumn);

	list.Detach();
}

void CAnalyzer::AnalyzeExportInit(HWND hwndList)
{
	CListCtrl list;
	list.Attach(hwndList);

#ifdef LVM_SETEXTENDEDLISTVIEWSTYLE
	list.SendMessage(LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
#endif

	LV_COLUMN lvcolumn;

	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Ord");
	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 40;
	list.InsertColumn(0, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Name");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 292;
	list.InsertColumn(1, &lvcolumn);

	list.Detach();
}

void CAnalyzer::AnalyzeImportInit(HWND hwndList)
{
	CListCtrl list;
	list.Attach(hwndList);

#ifdef LVM_SETEXTENDEDLISTVIEWSTYLE
	list.SendMessage(LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT);
#endif

	LV_COLUMN lvcolumn;

	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Server");
	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 80;
	list.InsertColumn(0, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Ord");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 48;
	list.InsertColumn(1, &lvcolumn);

//	lvcolumn.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
//	lvcolumn.fmt = LVCFMT_LEFT;
	lvcolumn.pszText = _T("Name");
//	lvcolumn.iSubItem = 0;
	lvcolumn.cx = 216;
	list.InsertColumn(2, &lvcolumn);

	list.Detach();
};

LPCTSTR alpszDirName[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {
	_T("Export"),
	_T("Import"),
	_T("Resource"),
	_T("Exception"),
	_T("Security"),
	_T("BaseReloc"),
	_T("Debug"),
	_T("CopyRight"),
	_T("GlobalPtr"),
	_T("TLS"),
	_T("Ld.Config"),
	_T("BoundImp"),
	_T("ImpAdrTbl"),
	_T("DelayImp"),		//	_T("#0000000d")
	_T("#0000000e"),
	_T("#0000000f"),
};

bool CAnalyzer::AnalyzeExeHdr(HWND hwndHdrList, HWND hwndDirList, HWND hwndSecList)
{
	LPCTSTR lpszValue;
	CString strValue;
	CListCtrl list;

	list.Attach(hwndHdrList);
	list.DeleteAllItems();

	int nCount = 0;
	list.InsertItem (nCount, _T("DOS Header :"));
	nCount++;
	strValue.Format(szHex4Fmt, m_dos_hdr.e_magic);
	list.InsertItem (nCount, _T("Magic number"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex4Fmt, m_dos_hdr.e_cblp);
	list.InsertItem (nCount, _T("Last page size [byte]"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex4Fmt, m_dos_hdr.e_cp);
	list.InsertItem (nCount, _T("All pages"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex4Fmt, m_dos_hdr.e_crlc);
	list.InsertItem (nCount, _T("Relocation entries"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex4Fmt, m_dos_hdr.e_cparhdr);
	list.InsertItem (nCount, _T("Header size [para]"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex4Fmt, m_dos_hdr.e_minalloc);
	list.InsertItem (nCount, _T("Min extra memory [para]"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex4Fmt, m_dos_hdr.e_maxalloc);
	list.InsertItem (nCount, _T("Max extra memory [para]"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szAddrFmt, m_dos_hdr.e_ss, m_dos_hdr.e_sp);
	list.InsertItem (nCount, _T("Stack address"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex4Fmt, m_dos_hdr.e_csum);
	list.InsertItem (nCount, _T("Check sum 16"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szAddrFmt, m_dos_hdr.e_cs, m_dos_hdr.e_ip);
	list.InsertItem (nCount, _T("Start address"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex4Fmt, m_dos_hdr.e_lfarlc);
	list.InsertItem (nCount, _T("Relocation table address"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex4Fmt, m_dos_hdr.e_ovno);
	list.InsertItem (nCount, _T("Overlay No."));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szAddrFmt, m_dos_hdr.e_oemid, m_dos_hdr.e_oeminfo);
	list.InsertItem (nCount, _T("OEM ID:info"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_dos_hdr.e_lfanew);
	list.InsertItem (nCount, _T("New header address"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;

	list.InsertItem (nCount, _T(""));
	nCount++;

	list.InsertItem (nCount, _T("PE Header :"));
	nCount++;
	switch (m_nt_hdr.FileHeader.Machine) {
	case IMAGE_FILE_MACHINE_I386:
		lpszValue = _T("x86");
		break;
	case IMAGE_FILE_MACHINE_R3000:
		lpszValue = _T("R3000");
		break;
	case IMAGE_FILE_MACHINE_R4000:
		lpszValue = _T("R4000");
		break;
	case IMAGE_FILE_MACHINE_R10000:
		lpszValue = _T("R10000");
		break;
	case IMAGE_FILE_MACHINE_ALPHA:
		lpszValue = _T("ALPHA");
		break;
	case IMAGE_FILE_MACHINE_POWERPC:
		lpszValue = _T("Power PC");
		break;
	default:
		lpszValue = _T("unknown");
		break;
	}
	list.InsertItem (nCount, _T("Target CPU type"));
	list.SetItemText(nCount, 1, lpszValue);
	nCount++;
	strValue.Format(szHex4Fmt, m_nt_hdr.FileHeader.NumberOfSections);
	list.InsertItem (nCount, _T("Section No."));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	CTime tm(static_cast<time_t>(m_nt_hdr.FileHeader.TimeDateStamp));
	strValue.Format(_T("%04d/%02d/%02d %02d:%02d:%02d (%08x)"), tm.GetYear(), tm.GetMonth(), tm.GetDay(), tm.GetHour(), tm.GetMinute(), tm.GetSecond(), m_nt_hdr.FileHeader.TimeDateStamp);
	list.InsertItem (nCount, _T("Link time stamp"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.FileHeader.PointerToSymbolTable);
	list.InsertItem (nCount, _T("Symbol table file offset"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.FileHeader.NumberOfSymbols);
	list.InsertItem (nCount, _T("Symbol No."));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex4Fmt, m_nt_hdr.FileHeader.SizeOfOptionalHeader);
	list.InsertItem (nCount, _T("Optional header size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Empty();
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_HI) {
		strValue += _T("HiBytesReversed, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) {
		strValue += _T("UpSystemOnly, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_DLL) {
		strValue += _T("DLL, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_SYSTEM) {
		strValue += _T("System, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) {
		strValue += _T("NetRunFromSwap, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) {
		strValue += _T("RemovableRunFromSwap, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) {
		strValue += _T("Debug, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) {
		strValue += _T("32-bit, ");
	} else {
		strValue += _T("16-bit, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_LO) {
		strValue += _T("LoBytesReversed, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM) {
		strValue += _T("AggresiveWsTrim, ");
	}
	if (!(m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)) {
		strValue += _T("Symbol, ");
	}
	if (!(m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)) {
		strValue += _T("LineNo, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
		strValue += _T("Executable, ");
	} else {
		strValue += _T("NonExecutable, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
		strValue += _T("NonRelocationsInfo, ");
	} else {
		strValue += _T("RelocationsInfo, ");
	}
	if (!strValue.IsEmpty()) {
		strValue = strValue.Left(strValue.GetLength() - 2);
	}
	list.InsertItem (nCount, _T("Flags"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;

	strValue.Format(szHex4Fmt, m_nt_hdr.OptionalHeader.Magic);
	list.InsertItem (nCount, _T("Signeture"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szVerFmt, m_nt_hdr.OptionalHeader.MajorLinkerVersion, m_nt_hdr.OptionalHeader.MinorLinkerVersion);
	list.InsertItem (nCount, _T("Linker version"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.SizeOfCode);
	list.InsertItem (nCount, _T("Code section size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.SizeOfInitializedData);
	list.InsertItem (nCount, _T("Init.data section size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.SizeOfUninitializedData);
	list.InsertItem (nCount, _T("Uninit.data section size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.ImageBase + m_nt_hdr.OptionalHeader.AddressOfEntryPoint);
	list.InsertItem (nCount, _T("Start address"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.ImageBase + m_nt_hdr.OptionalHeader.BaseOfCode);
	list.InsertItem (nCount, _T("Code section base addr."));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.ImageBase + m_nt_hdr.OptionalHeader.BaseOfData);
	list.InsertItem (nCount, _T("Data section base addr."));
	list.SetItemText(nCount, 1, strValue);
	nCount++;

	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.ImageBase);
	list.InsertItem (nCount, _T("Image base address"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.SectionAlignment);
	list.InsertItem (nCount, _T("Section alignment size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.FileAlignment);
	list.InsertItem (nCount, _T("File alignment size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szVerFmt, m_nt_hdr.OptionalHeader.MajorOperatingSystemVersion, m_nt_hdr.OptionalHeader.MinorOperatingSystemVersion);
	list.InsertItem (nCount, _T("Operation system version"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szVerFmt, m_nt_hdr.OptionalHeader.MajorImageVersion, m_nt_hdr.OptionalHeader.MinorImageVersion);
	list.InsertItem (nCount, _T("User defined version"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szVerFmt, m_nt_hdr.OptionalHeader.MajorSubsystemVersion, m_nt_hdr.OptionalHeader.MinorSubsystemVersion);
	list.InsertItem (nCount, _T("Sub-system version"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.Win32VersionValue);
	list.InsertItem (nCount, _T("Reserved"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.SizeOfImage);
	list.InsertItem (nCount, _T("Image size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.SizeOfHeaders);
	list.InsertItem (nCount, _T("Headers size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.CheckSum);
	list.InsertItem (nCount, _T("Check sum 32"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	switch (m_nt_hdr.OptionalHeader.Subsystem) {
	case IMAGE_SUBSYSTEM_NATIVE:
		lpszValue = _T("Native");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_GUI:
		lpszValue = _T("Windows GUI");
		break;
	case IMAGE_SUBSYSTEM_WINDOWS_CUI:
		lpszValue = _T("Windows CUI");
		break;
	case IMAGE_SUBSYSTEM_OS2_CUI:
		lpszValue = _T("OS2 CUI");
		break;
	case IMAGE_SUBSYSTEM_POSIX_CUI:
		lpszValue = _T("POSIX CUI");
		break;
	default:
		lpszValue = _T("unknown");
		break;
	}
	list.InsertItem (nCount, _T("Sub-system"));
	list.SetItemText(nCount, 1, lpszValue);
	nCount++;
	strValue.Format(szHex4Fmt, m_nt_hdr.OptionalHeader.DllCharacteristics);
	list.InsertItem (nCount, _T("DLL init.func.flags"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.SizeOfStackReserve);
	list.InsertItem (nCount, _T("Reserved stack size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.SizeOfStackCommit);
	list.InsertItem (nCount, _T("Commit stack size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.SizeOfHeapReserve);
	list.InsertItem (nCount, _T("Reserved heap size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.SizeOfHeapCommit);
	list.InsertItem (nCount, _T("Commit heap size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.LoaderFlags);
	list.InsertItem (nCount, _T("Loader flags"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.NumberOfRvaAndSizes);
	list.InsertItem (nCount, _T("Data directory No."));
	list.SetItemText(nCount, 1, strValue);
//	nCount++;
	list.Detach();

	list.Attach(hwndDirList);
	list.DeleteAllItems();

	nCount = 0;
	for (DWORD dwEntry = 0; dwEntry < m_nt_hdr.OptionalHeader.NumberOfRvaAndSizes; dwEntry++) {
		list.InsertItem(nCount, alpszDirName[dwEntry]);
		DWORD dwAddr = m_nt_hdr.OptionalHeader.DataDirectory[dwEntry].VirtualAddress;
		if (dwAddr) {
			dwAddr += m_nt_hdr.OptionalHeader.ImageBase;
		}
		strValue.Format(szHex8Fmt, dwAddr);
		list.SetItemText(nCount, 1, strValue);
		strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.DataDirectory[dwEntry].Size);
		list.SetItemText(nCount, 2, strValue);
		nCount++;
	}
	list.Detach();

	list.Attach(hwndSecList);
	list.DeleteAllItems();

	nCount = 0;
	for (vector<IMAGE_SECTION_HEADER>::iterator it = m_vecSecHdr.begin(); it != m_vecSecHdr.end(); ++it) {
		list.InsertItem(nCount, CString(reinterpret_cast<LPSTR>(it->Name), IMAGE_SIZEOF_SHORT_NAME));
		strValue.Format(szHex8Fmt, m_nt_hdr.OptionalHeader.ImageBase + it->VirtualAddress);
		list.SetItemText(nCount, 1, strValue);
		strValue.Format(szHex8Fmt, it->Misc.VirtualSize);
		list.SetItemText(nCount, 2, strValue);
		strValue.Format(szHex8Fmt, it->SizeOfRawData);
		list.SetItemText(nCount, 3, strValue);
		strValue.Format(szHex8Fmt, it->PointerToRawData);
		list.SetItemText(nCount, 4, strValue);
		strValue.Format(szHex8Fmt, it->PointerToRelocations);
		list.SetItemText(nCount, 5, strValue);
		strValue.Format(szHex8Fmt, it->PointerToLinenumbers);
		list.SetItemText(nCount, 6, strValue);
		strValue.Format(szHex4Fmt, it->NumberOfRelocations);
		list.SetItemText(nCount, 7, strValue);
		strValue.Format(szHex4Fmt, it->NumberOfLinenumbers);
		list.SetItemText(nCount, 8, strValue);
		strValue.Empty();
		if (it->Characteristics & IMAGE_SCN_MEM_WRITE) {
			strValue += _T("Write, ");
		}
		if (it->Characteristics & IMAGE_SCN_MEM_READ) {
			strValue += _T("Read, ");
		}
		if (it->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			strValue += _T("Execute, ");
		}
		if (it->Characteristics & IMAGE_SCN_MEM_SHARED) {
			strValue += _T("Shared, ");
		}
		if (it->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) {
			strValue += _T("NotPaged, ");
		}
		if (it->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
			strValue += _T("NotCached, ");
		}
		if (it->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
			strValue += _T("Discardable, ");
		}
		if (it->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) {
			strValue += _T("Ext.Reloc., ");
		}
		if (it->Characteristics & IMAGE_SCN_MEM_PRELOAD) {
			strValue += _T("Preload, ");
		}
		if (it->Characteristics & IMAGE_SCN_MEM_LOCKED) {
			strValue += _T("Locked, ");
		}
		if (it->Characteristics & IMAGE_SCN_MEM_PURGEABLE) {
			strValue += _T("Purgeable, ");
		}
		if (it->Characteristics & IMAGE_SCN_MEM_FARDATA) {
			strValue += _T("FarData, ");
		}
		if (it->Characteristics & IMAGE_SCN_LNK_COMDAT) {
			strValue += _T("ComDat, ");
		}
		if (it->Characteristics & IMAGE_SCN_LNK_REMOVE) {
			strValue += _T("Remove, ");
		}
		if (it->Characteristics & IMAGE_SCN_LNK_INFO) {
			strValue += _T("Info, ");
		}
		if (it->Characteristics & IMAGE_SCN_LNK_OTHER) {
			strValue += _T("Other, ");
		}
		if (it->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			strValue += _T("Uninit.Data, ");
		}
		if (it->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
			strValue += _T("Init.Data, ");
		}
		if (it->Characteristics & IMAGE_SCN_CNT_CODE) {
			strValue += _T("Code, ");
		}
		if (it->Characteristics & IMAGE_SCN_TYPE_NO_PAD) {
			strValue += _T("NoPad, ");
		}
		strValue = strValue.Left(strValue.GetLength() - 2);
		list.SetItemText(nCount, 9, strValue);
		nCount++;
	}

	list.Detach();
	return true;
}

LPCTSTR aszAccessName[] = {
	_T("private"),
	_T("protected"),
	_T("public"),
};

bool CAnalyzer::AnalyzeExport(HWND hwndMsg, HWND hwndList, bool bDecode)
{
	CListCtrl list;
	list.Attach(hwndList);
	list.DeleteAllItems();
	int nCount = 0;
	CString strMsg, strOrdinal, strName;
	m_mapCls.clear();
	PIMAGE_EXPORT_DIRECTORY pExpDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(&m_vecBuff[m_dwDirAddr - m_dwSecAddr]);
	DWORD dwAddrOfNameOrds = /*reinterpret_cast<DWORD>*/(pExpDir->AddressOfNameOrdinals);
	LPWORD lpwOrdTable = reinterpret_cast<LPWORD>(&m_vecBuff[dwAddrOfNameOrds - m_dwSecAddr]);
	DWORD dwAddrOfNames = /*reinterpret_cast<DWORD>*/(pExpDir->AddressOfNames);
	LPDWORD lpdwNameTable = reinterpret_cast<LPDWORD>(&m_vecBuff[dwAddrOfNames - m_dwSecAddr]);
	for (DWORD dwCount = 0; dwCount < pExpDir->NumberOfNames; dwCount++) {
		strOrdinal.Format(szHex4Fmt, *lpwOrdTable++ + pExpDir->Base);
		list.InsertItem(nCount, strOrdinal);
		strName = reinterpret_cast<LPSTR>(&m_vecBuff[*lpdwNameTable++ - m_dwSecAddr]);
		list.SetItemText(nCount, 1, strName);
		nCount++;
		strName = AnalyzeName(strName, true);
		if (!strName.IsEmpty()) {
			strMsg += strName;
			strMsg += _T("\r\n");
		}
	}
	list.Detach();
	for (mapcls_t::const_iterator mit = m_mapCls.begin(); mit != m_mapCls.end(); ++mit) {
		strMsg += _T("class ") + mit->first + _T(" {\r\n");
		for (int nAcc = 0; nAcc < lengthof(aszAccessName); nAcc++) {
			const setstr_t& setMem = mit->second[nAcc];
			if (setMem.size()) {
				strMsg += aszAccessName[nAcc];
				strMsg += _T(":\r\n");
				for (setstr_t::const_iterator sit = setMem.begin(); sit != setMem.end(); ++sit) {
					strMsg += _T("    "); // indent
					strMsg += *sit;
					strMsg += _T("\r\n");
				}
			}
		}
		strMsg += _T("};\r\n");
	}
	::SetWindowText(hwndMsg, strMsg);
	return true;
}

bool CAnalyzer::AnalyzeImport(HWND hwndList, bool bFunc, bool bDecode)
{
	CListCtrl list;
	list.Attach(hwndList);
	list.DeleteAllItems();
	int nCount = 0;
	bool bIAT = (m_nt_hdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress != 0);
	CString strOrdinal, strName;
	PIMAGE_IMPORT_DESCRIPTOR pImpDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(&m_vecBuff[m_dwDirAddr - m_dwSecAddr]);
//	for (int nDesc = 0; pImpDesc[nDesc].Characteristics; nDesc++) {
	for (int nDesc = 0; pImpDesc[nDesc].FirstThunk; nDesc++) {
		LPTSTR lpszServer = reinterpret_cast<LPTSTR>(&m_vecBuff[pImpDesc[nDesc].Name - m_dwSecAddr]);
		if (!bFunc) {
			list.InsertItem(nCount++, lpszServer);
		} else {
//			DWORD dwFirstThunk = /*reinterpret_cast<DWORD>*/(pImpDesc[nDesc].OriginalFirstThunk);
			DWORD dwFirstThunk = (bIAT) ? pImpDesc[nDesc].OriginalFirstThunk : pImpDesc[nDesc].FirstThunk;
			PIMAGE_THUNK_DATA pThkDat = reinterpret_cast<PIMAGE_THUNK_DATA>(&m_vecBuff[dwFirstThunk - m_dwSecAddr]);
			bool bLoadedExpFile = false;
			DWORD dwOrdinal;
			for (int nThunk = 0; dwOrdinal = pThkDat[nThunk].u1.Ordinal; nThunk++) {
				list.InsertItem(nCount, lpszServer);
				if (IMAGE_SNAP_BY_ORDINAL(dwOrdinal)) {
					// 0x80000000 ... 0xffffffff
					dwOrdinal = IMAGE_ORDINAL(dwOrdinal);
					strOrdinal.Format(szHex4Fmt, dwOrdinal);
					strName = _T("<unknown name>");
					if (!bLoadedExpFile) {
						if (m_mapExp.find(lpszServer) == m_mapExp.end()) {
							LoadExpFile(lpszServer);
						}
						bLoadedExpFile = true;
					}
					if (m_mapExp.find(lpszServer) != m_mapExp.end()) {
						if (m_mapExp[lpszServer].find(dwOrdinal) != m_mapExp[lpszServer].end()) {
							strName = m_mapExp[lpszServer][dwOrdinal];
						}
					}
				} else {
					// 0x00000000 ... 0x7fffffff
					PIMAGE_IMPORT_BY_NAME pImpName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(&m_vecBuff[dwOrdinal - m_dwSecAddr]);
					strOrdinal.Format(_T("(%04x)"), pImpName->Hint);
					strName = reinterpret_cast<LPSTR>(pImpName->Name);
				}
				list.SetItemText(nCount, 1, strOrdinal);
				if (bDecode) {
					strName = AnalyzeName(strName, false);
				}
				list.SetItemText(nCount, 2, strName);
				nCount++;
			}
		}
	}
	list.Detach();
	return true;
}

enum {
	accessPrivate,
	accessProtected,
	accessPublic,
	accessNone,
};
enum {
	attrNormal,
	attrStatic,
	attrVirtual,
	attrExport,
};

struct {
	CHAR cName;
	BYTE bAccess;
	BYTE bAttr;
	bool bFunc;
	bool bType;
	bool bDeco;
	bool bClassName;
} aAttrTable[] = {
	'A', accessPrivate,   attrNormal,  true,  true,  true,  false,
	'C', accessPrivate,   attrStatic,  true,  true,  false, false,
	'E', accessPrivate,   attrVirtual, true,  true,  true,  false,
	'I', accessProtected, attrNormal,  true,  true,  true,  false,
	'K', accessProtected, attrStatic,  true,  true,  false, false,
	'M', accessProtected, attrVirtual, true,  true,  true,  false,
	'Q', accessPublic,    attrNormal,  true,  true,  true,  false,
	'S', accessPublic,    attrStatic,  true,  true,  false, false,
	'U', accessPublic,    attrVirtual, true,  true,  true,  false,
	'Y', accessNone,      attrExport,  true,  true,  false, false,
	'0', accessPrivate,   attrStatic,  false, true,  true,  false,
	'1', accessProtected, attrStatic,  false, true,  true,  false,
	'2', accessPublic,    attrStatic,  false, true,  true,  false,
	'3', accessNone,      attrExport,  false, true,  true,  false,
	'6', accessNone,      attrNormal,  false, false, true,  true,
	'7', accessNone,      attrNormal,  false, false, true,  true,
};

CString CAnalyzer::AnalyzeName(LPCSTR lpszName, bool bPushCls)
{
	if (*lpszName != '\?') {
		return lpszName;
	}
	m_bOpCast = false;
	m_vecName.clear();
	LPCSTR lpszStr = lpszName + 1;
	int nClsLen;
	CString strName = AnalyzeVcName(&lpszStr, true, &nClsLen);
	CHAR cAttr = *lpszStr++;
	for (int nAttr = 0; nAttr < lengthof(aAttrTable); nAttr++) {
		if (aAttrTable[nAttr].cName == cAttr) {
			break;
		}
	}
	if (nAttr >= lengthof(aAttrTable)) {
		return lpszName;
	}
	CString strAll, strCls, strDeco, strType;
	int nAcc = aAttrTable[nAttr].bAccess;
	if (nAcc != accessNone) {
		if (bPushCls) {
			strCls  = strName.Left(nClsLen); // separate class name.
			strName = strName.Mid(nClsLen + 2);
		} else {
			strAll += aszAccessName[nAcc]; // add access type.
			strAll += _T(": ");
		}
	}
	switch (aAttrTable[nAttr].bAttr) {
	case attrStatic:
		strAll += _T("static ");
		break;
	case attrVirtual:
		strAll += _T("virtual ");
		break;
	case attrExport:
		strAll += _T("_declspec(dllexport) ");
		break;
	}
	if (aAttrTable[nAttr].bFunc) {
		CHAR cDeco = '\0';
		if (aAttrTable[nAttr].bDeco) {
			cDeco = *lpszStr++;
		}
		CString strFunc = AnalyzeFunc(&lpszStr, strName, false);
//		if (strFunc.IsEmpty()) {
//			return lpszName; // analyze error.
//		}
		strAll += strFunc;
		if (cDeco) {
			strDeco = AnalyzeDeco(cDeco);
			if (!strDeco.IsEmpty()) {
				strAll += _T(' ');
				strAll += strDeco;
			}
		}
	} else {
		if (aAttrTable[nAttr].bType) {
			strType = AnalyzeVarType(&lpszStr, true);
		}
		if (aAttrTable[nAttr].bDeco) {
			strDeco = AnalyzeDeco(*lpszStr++);
			if (!strDeco.IsEmpty()) {
				strAll += strDeco;
				strAll += _T(' ');
			}
		}
		if (aAttrTable[nAttr].bType) {
			strAll += strType;
			strAll += _T(' ');
		}
		strAll += strName;
		if (aAttrTable[nAttr].bClassName) {
			strName = AnalyzeVcName(&lpszStr, false, NULL);
			if (!strName.IsEmpty()) {
				strAll += _T('(');
				strAll += strName;
				strAll += _T(')');
			}
		}
	}
	strAll += _T(';');
	if (bPushCls && (nAcc != accessNone)) {
		m_mapCls[strCls].resize(lengthof(aszAccessName), defaultSetStr);
		m_mapCls[strCls][nAcc].insert(strAll);
		return _T("");
	}
	return strAll;
}

LPCTSTR aszSpcName1[] = {
	_T("0$"), // constructor
	_T("1$~"), // destructor
	_T("2@ new"),
	_T("3@ delete"),
	_T("4@="),
	_T("5@>>"),
	_T("6@<<"),
	_T("7@!"),
	_T("8@=="),
	_T("9@!="),
	_T("A@[]"),
	_T("B@#"), // operator char, int, ...
	_T("C@->"),
	_T("D@*"),
	_T("E@++"),
	_T("F@--"),
	_T("G@-"),
	_T("H@+"),
	_T("I@&"),
	_T("J@->*"),
	_T("K@/"),
	_T("L@%"),
	_T("M@<"),
	_T("N@<="),
	_T("O@>"),
	_T("P@>="),
	_T("Q@,"),
	_T("R@()"),
	_T("S@~"),
	_T("T@^"),
	_T("U@|"),
	_T("V@&&"),
	_T("W@||"),
	_T("X@*="),
	_T("Y@+="),
	_T("Z@-="),
};
LPCTSTR aszSpcName2[] = {
	_T("0@/="),
	_T("1@%="),
	_T("2@>>="),
	_T("3@<<="),
	_T("4@&="),
	_T("5@|="),
	_T("6@^="),
	_T("7vftable"),
	_T("8virtual_base_class"),
	_T("Evector_deleting_destructor"),
	_T("Gscalar_deleting_destructor"),
	_T("U@ new[]"),
	_T("V@ delete[]"),
};

CString CAnalyzer::AnalyzeVcName(LPCSTR *plpszStr, bool bRec, int *pnClsLen)
{
	bool bConstDest = false;
	CString strName;
	CHAR c = *(*plpszStr)++;
	if (c == '?') {
		c = *(*plpszStr)++;
		if (c == '$') {  // template name
			c = *(*plpszStr)++;
			if (c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
				do {
					strName += c;
					c = *(*plpszStr)++;
				} while (c != '@');
				strName += _T('<');
				bool bCommaFlag = false;
				while (*(*plpszStr) != '@') {
					if (bCommaFlag) {
						strName += _T(", ");
					}
					strName += AnalyzeVarType(plpszStr, false);
					bCommaFlag = true;
				}
				(*plpszStr)++;
				strName += _T('>');
				if (bRec) {
					m_vecName.push_back(strName);
				}
			} else {
				strName = _T("<unknown temp name : ") + c + _T('>');
			}
		} else {
			LPCTSTR lpszSpcName = NULL;
			if (c == '_') {
				c = *(*plpszStr)++;
				for (int i = 0; i < lengthof(aszSpcName2); i++) { // _0-_9, _A-_Z
					if (aszSpcName2[i][0] == c) {
						lpszSpcName = &aszSpcName2[i][1];
						break;
					}
				}
			} else {
				for (int i = 0; i < lengthof(aszSpcName1); i++) { // 0-9, A-Z
					if (aszSpcName1[i][0] == c) {
						lpszSpcName = &aszSpcName1[i][1];
						break;
					}
				}
			}
			if (lpszSpcName) {
				if (lpszSpcName[0] == _T('$')) { // constructor, destoructor
					bConstDest = true;
					strName = &lpszSpcName[1];
				} else if (lpszSpcName[0] == _T('@')) { // operators
					strName = _T("operator");
					if (lpszSpcName[1] == _T('#')) {
						m_bOpCast = true;
					} else {
						strName += &lpszSpcName[1];
					}
				} else { // others
					strName = lpszSpcName;
				}
			} else {
				strName = _T("<unknown spc name : ") + c + _T('>');
			}
		}
	} else
	if (c >= '0' && c <= '9') { // name repeaters
		if ((c - '0') < m_vecName.size()) {
			strName = m_vecName[c - '0'];
		} else {
			strName = _T("<unknown rep name : ") + c + _T('>');
		}
	} else
	if (c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
		do {
			strName += c;
			c = *(*plpszStr)++;
		} while (c != '@');
		if (bRec) {
			m_vecName.push_back(strName);
		}
	} else
	if (c == '@') { // for class name, namespace name.
		return _T("");
	} else {
		strName = _T("<unknown name : ") + c + _T('>');
	}
	if (**plpszStr != '@') { // for class name, namespace name.
		CString strWork = AnalyzeVcName(plpszStr, bRec, NULL);
		if (pnClsLen) {
			*pnClsLen = strWork.GetLength();
		}
		strName = strWork + _T("::") + strName;
		if (bConstDest) {
			strName += m_vecName[0];
		}
	} else {
		(*plpszStr)++;
	}
	return strName;
}

CString CAnalyzer::AnalyzeFunc(LPCSTR *plpszStr, LPCTSTR lpszName, bool bFuncPtr)
{
	CString strWork;
	CHAR cCallSeq = *(*plpszStr)++;
	if (lpszName == NULL || !m_bOpCast) {
		strWork = AnalyzeVarType(plpszStr, true); // return value type.
		strWork += _T(' ');
	}
	if (bFuncPtr) {
		strWork += _T('(');
	}
	switch (cCallSeq) { // calling sequence
	case 'A':
		strWork += _T("_cdecl ");
		break;
	case 'E':
		strWork += _T("_thiscall ");
		break;
	case 'G':
		strWork += _T("_stdcall ");
		break;
	case 'I':
		strWork += _T("_fastcall ");
		break;
	default:
		strWork += _T("<unknown call seq : ") + cCallSeq;
		strWork += _T("> ");
	}
	if (lpszName) {
		strWork += lpszName; // function name.
		if (m_bOpCast) { // operator char, int, ...
			strWork += _T(' ') + AnalyzeVarType(plpszStr, true); // return value type.
			m_bOpCast = false;
		}
	}
	if (bFuncPtr) {
		strWork += _T("*)");
	}
	strWork += _T('('); // arguments start.
	if (*(*plpszStr) == 'X') {
		strWork += _T("void");
	} else {
		m_vecArg.clear();
		bool bCommaFlag = false;
		while (*(*plpszStr) != '@') {
			if (bCommaFlag) {
				strWork += _T(", ");
			}
			if (*(*plpszStr) == 'Z') { // variable argument
				strWork += _T("...");
				break;
			}
			strWork += AnalyzeVarType(plpszStr, true);
			bCommaFlag = true;
		}
		(*plpszStr)++;
		CHAR c = *(*plpszStr)++;
		if (c != 'Z') { // a function name has terminated by 'Z'.
			return strWork + _T("<unknown term : ") + c + _T('>');
		}
	}
	strWork += _T(')'); // arguments end.
	return strWork;
}

CString CAnalyzer::AnalyzeDeco(CHAR cDeco)
{
	switch (cDeco) {
	case 'A':
		return _T("");
	case 'B':
		return _T("const");
	case 'C':
		return _T("volatile");
	case 'D':
		return _T("const volatile");
	}
	return _T("<unknown deco : ") + cDeco + _T('>');
}

CString CAnalyzer::AnalyzeVarType(LPCSTR *plpszStr, bool bRec)
{
	CHAR c = *(*plpszStr)++;
	if (c >= '0' && c <= '9') { // argument repeaters
		if ((c - '0') >= m_vecArg.size()) {
			return _T("<unknown arg : ") + c + _T('>');
		}
		return m_vecArg[c - '0'];
	}
	switch (c) {
	case '@':
		return _T("<no ret>");
	case 'A': // reference
		{
			CString strWork = AnalyzeDeco(*(*plpszStr)++);
			if (!strWork.IsEmpty()) {
				strWork += _T(" ");
			}
			strWork += AnalyzeVarType(plpszStr, bRec) + _T(" &");
			m_vecArg.push_back(strWork);
			return strWork;
		}
//	case 'B': // unknown
	case 'C':
		return _T("signed char");
	case 'D':
		return _T("char");
	case 'E':
		return _T("unsigned char");
	case 'F':
		return _T("short");
	case 'G':
		return _T("unsigned short");
	case 'H':
		return _T("int");
	case 'I':
		return _T("unsigned int");
	case 'J':
		return _T("long");
	case 'K':
		return _T("unsigned long");
//	case 'L': // unknown
	case 'M':
		return _T("float");
	case 'N':
		return _T("double");
	case 'O':
		return _T("long double");
	case 'P':
		return AnalyzeVarTypePtr(plpszStr, bRec);
	case 'Q': // why needs ?
		return _T('(') + AnalyzeVarTypePtr(plpszStr, bRec) + _T(')');
//	case 'R': // unknown
//	case 'S': // unknown
	case 'T':
		return _T("union ") + AnalyzeVcName(plpszStr, bRec, NULL);
	case 'U':
		return _T("struct ") + AnalyzeVcName(plpszStr, bRec, NULL);
	case 'V':
		return _T("class ") + AnalyzeVcName(plpszStr, bRec, NULL);
	case 'W':
		if (*(*plpszStr) == '4') {
			(*plpszStr)++;
			return _T("enum ") + AnalyzeVcName(plpszStr, bRec, NULL);
		}
		break;
	case 'X':
		return _T("void");
//	case 'Y': // unknown
//	case 'Z': // unknown
	case '?': // union, struct, class, enum with decolattion.
		{
			CString strWork = AnalyzeDeco(*(*plpszStr)++);
			if (!strWork.IsEmpty()) {
				strWork += _T(" ");
			}
			strWork += AnalyzeVarType(plpszStr, bRec);
			m_vecArg.push_back(strWork);
			return strWork;
		}
	case '_': // enhanced name
		switch (c = *(*plpszStr)++) {
		case 'J':
			return _T("_int64");
		case 'K':
			return _T("unsigned _int64");
		case 'N':
			return _T("bool");
		}
	}
	return _T("<unknown type : ") + c + _T('>');
}

CString CAnalyzer::AnalyzeVarTypePtr(LPCSTR *plpszStr, bool bRec)
{
	CHAR c = *(*plpszStr)++;
	if (c == '6') { // function pointer
		CString strFunc = AnalyzeFunc(plpszStr, NULL, true);
//		if (strFunc.IsEmpty()) {
//			return _T("<unknown func ptr>");
//		}
		return strFunc;
	}
	if (c == '8') { // function pointer with class
		CString strCls  = AnalyzeVcName(plpszStr, bRec, NULL) + _T("::");
		CString strDeco = AnalyzeDeco(*(*plpszStr)++);
		CString strFunc = AnalyzeFunc(plpszStr, strCls, true);
//		if (strFunc.IsEmpty()) {
//			return _T("<unknown func ptr>");
//		}
		if (!strDeco.IsEmpty()) {
			strFunc += _T(' ');
			strFunc += strDeco;
		}
		return strFunc;
	}
	CString strWork = AnalyzeDeco(c);
	if (!strWork.IsEmpty()) {
		strWork += _T(" ");
	}
	strWork += AnalyzeVarType(plpszStr, bRec) + _T(" *");
	m_vecArg.push_back(strWork);
	return strWork;
}
