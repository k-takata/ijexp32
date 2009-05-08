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
static TCHAR szHex16Fmt[] = _T("%016I64x");
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
//	::ZeroMemory(&m_nt_hdr,  sizeof(m_nt_hdr));
	::ZeroMemory(&m_nt_hdr64, sizeof(m_nt_hdr64));
	m_b32bit = false;
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

bool CAnalyzer::Open(HWND hwnd, LPCTSTR lpszPath, bool bQuiet)
{
	if (m_file.Open(lpszPath, CFile::modeRead | CFile::shareDenyWrite) == FALSE) {
		if (!bQuiet) {
			::MsgBox(hwnd, lpszPath, IDS_COULD_NOT_OPEN);
		}
		return false;
	}
	try {
		m_file.Read(&m_dos_hdr, sizeof(IMAGE_DOS_HEADER)); // read MZ hdr
		if (m_dos_hdr.e_magic == IMAGE_DOS_SIGNATURE) {
			DWORD dwPeHdrOffset = m_dos_hdr.e_lfanew;
			if (dwPeHdrOffset >= sizeof(IMAGE_DOS_HEADER)) {
				m_file.Seek(dwPeHdrOffset, CFile::begin);
				m_file.Read(&m_nt_hdr, sizeof(IMAGE_NT_HEADERS64)); // read PE hdr
				if (m_nt_hdr.Signature == IMAGE_NT_SIGNATURE) {
					if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
						if (((m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE)
									&& (m_nt_hdr32.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC))
								|| (m_nt_hdr64.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)) {
							if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) {
								m_b32bit = true;
							}
//							DWORD dwPeHdrOffset = m_dos_hdr.e_lfanew;
							DWORD dwSecEntry = m_nt_hdr.FileHeader.NumberOfSections;
							DWORD dwSecOffset = dwPeHdrOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + m_nt_hdr.FileHeader.SizeOfOptionalHeader;
							m_file.Seek(dwSecOffset, CFile::begin);
							m_vecSecHdr.resize(dwSecEntry);
							m_file.Read(&m_vecSecHdr.front(), IMAGE_SIZEOF_SECTION_HEADER * dwSecEntry); // read section hdr. block.
							return true;
						} else if (!bQuiet) {
							::MsgBox(hwnd, m_file.GetFilePath(), IDS_NOT_OPT_HDR);
						}
					} else if (!bQuiet) {
						::MsgBox(hwnd, m_file.GetFilePath(), IDS_NOT_EXE32);
					}
				} else if (!bQuiet) {
					::MsgBox(hwnd, m_file.GetFilePath(), IDS_NOT_PE_FILE);
				}
			} else if (!bQuiet) {
				::MsgBox(hwnd, m_file.GetFilePath(), IDS_NOT_NEW_HDR);
			}
		} else if (!bQuiet) {
			::MsgBox(hwnd, m_file.GetFilePath(), IDS_NOT_EXEC);
		}
	} catch (CFileException *e) {
		e->Delete();
		if (!bQuiet) {
			::MsgBox(hwnd, m_file.GetFilePath(), IDS_COULD_NOT_READ);
		}
	}
	m_file.Close();
	return false;
}

void CAnalyzer::Close(void)
{
	m_file.Close();
}

bool CAnalyzer::ReadSection(HWND hwnd, int nDirectory, bool bQuiet, bool bCheckOnly)
{
	try {
		if (m_b32bit) {
			m_dwDirAddr = m_nt_hdr32.OptionalHeader.DataDirectory[nDirectory].VirtualAddress;
		} else {
			m_dwDirAddr = m_nt_hdr64.OptionalHeader.DataDirectory[nDirectory].VirtualAddress;
		}
		for (vector<IMAGE_SECTION_HEADER>::const_iterator it = m_vecSecHdr.begin(); it != m_vecSecHdr.end(); ++it) {
			m_dwSecAddr = it->VirtualAddress;
			DWORD dwOffset = m_dwDirAddr - m_dwSecAddr; // a result is unsigned, because need to wrap-around to big number, when underflow.
			DWORD dwSecSize = it->Misc.VirtualSize;
			if (dwOffset < dwSecSize) {
				if (!bCheckOnly) {
					m_file.Seek(it->PointerToRawData, CFile::begin); // seek to start of target section.
					m_vecBuff.resize(dwSecSize);
					m_file.Read(&m_vecBuff.front(), dwSecSize); // read target section.
				}
				return true;
			}
		}
		if (!bQuiet) {
			::MsgBox(hwnd, m_file.GetFilePath(), IDS_COULD_NOT_FIND_SECTION);
		}
	} catch (CFileException *e) {
		e->Delete();
		if (!bQuiet) {
			::MsgBox(hwnd, m_file.GetFilePath(), IDS_COULD_NOT_READ);
		}
	}
	m_file.Close();
	return false;
}

bool CAnalyzer::FindSection(HWND hwnd, int nDirectory, bool bQuiet)
{
	return ReadSection(hwnd, nDirectory, bQuiet, true);
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
	_T("Copyright"),
	_T("GlobalPtr"),
	_T("TLS"),
	_T("Ld.Config"),
	_T("BoundImp"),
	_T("ImpAdrTbl"),
	_T("DelayImp"),		//	_T("#0000000d")
	_T("COM Desc"),		//	_T("#0000000e")
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
	case IMAGE_FILE_MACHINE_IA64:
		lpszValue = _T("IA64");
		break;
	case IMAGE_FILE_MACHINE_AMD64:
		lpszValue = _T("x64");
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
	case IMAGE_FILE_MACHINE_SH4:
		lpszValue = _T("SH4");
		break;
	case IMAGE_FILE_MACHINE_ARM:
		lpszValue = _T("ARM");
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
		strValue += _T("DebugStripped, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) {
		strValue += _T("32-bit, ");
	} else {
//		strValue += _T("16-bit, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_LO) {
		strValue += _T("LoBytesReversed, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) {
		strValue += _T("LargeAddressAware, ");
	}
	if (m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM) {
		strValue += _T("AggresiveWsTrim, ");
	}
	if (!(m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)) {
		strValue += _T("SymbolsStripped, ");
	}
	if (!(m_nt_hdr.FileHeader.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)) {
		strValue += _T("LineNumsStripped, ");
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

	strValue.Format(szHex4Fmt, m_nt_hdr32.OptionalHeader.Magic);
	list.InsertItem (nCount, _T("Signeture"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szVerFmt, m_nt_hdr32.OptionalHeader.MajorLinkerVersion, m_nt_hdr32.OptionalHeader.MinorLinkerVersion);
	list.InsertItem (nCount, _T("Linker version"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.SizeOfCode);
	list.InsertItem (nCount, _T("Code section size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.SizeOfInitializedData);
	list.InsertItem (nCount, _T("Init.data section size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.SizeOfUninitializedData);
	list.InsertItem (nCount, _T("Uninit.data section size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	if (m_b32bit) {
		strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.ImageBase + m_nt_hdr32.OptionalHeader.AddressOfEntryPoint);
		list.InsertItem (nCount, _T("Start address"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.ImageBase + m_nt_hdr32.OptionalHeader.BaseOfCode);
		list.InsertItem (nCount, _T("Code section base addr."));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.ImageBase + m_nt_hdr32.OptionalHeader.BaseOfData);
		list.InsertItem (nCount, _T("Data section base addr."));
		list.SetItemText(nCount, 1, strValue);
		nCount++;

		strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.ImageBase);
		list.InsertItem (nCount, _T("Image base address"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
	} else {
		strValue.Format(szHex16Fmt, m_nt_hdr64.OptionalHeader.ImageBase + m_nt_hdr64.OptionalHeader.AddressOfEntryPoint);
		list.InsertItem (nCount, _T("Start address"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex16Fmt, m_nt_hdr64.OptionalHeader.ImageBase + m_nt_hdr64.OptionalHeader.BaseOfCode);
		list.InsertItem (nCount, _T("Code section base addr."));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
//		strValue.Format(szHex16Fmt, m_nt_hdr64.OptionalHeader.ImageBase + m_nt_hdr64.OptionalHeader.BaseOfData);
//		list.InsertItem (nCount, _T("Data section base addr."));
//		list.SetItemText(nCount, 1, strValue);
//		nCount++;

		strValue.Format(szHex16Fmt, m_nt_hdr64.OptionalHeader.ImageBase);
		list.InsertItem (nCount, _T("Image base address"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
	}
	strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.SectionAlignment);
	list.InsertItem (nCount, _T("Section alignment size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.FileAlignment);
	list.InsertItem (nCount, _T("File alignment size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szVerFmt, m_nt_hdr32.OptionalHeader.MajorOperatingSystemVersion, m_nt_hdr32.OptionalHeader.MinorOperatingSystemVersion);
	list.InsertItem (nCount, _T("Operating system version"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szVerFmt, m_nt_hdr32.OptionalHeader.MajorImageVersion, m_nt_hdr32.OptionalHeader.MinorImageVersion);
	list.InsertItem (nCount, _T("User defined version"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szVerFmt, m_nt_hdr32.OptionalHeader.MajorSubsystemVersion, m_nt_hdr32.OptionalHeader.MinorSubsystemVersion);
	list.InsertItem (nCount, _T("Sub-system version"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.Win32VersionValue);
	list.InsertItem (nCount, _T("Reserved"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.SizeOfImage);
	list.InsertItem (nCount, _T("Image size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.SizeOfHeaders);
	list.InsertItem (nCount, _T("Headers size"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.CheckSum);
	list.InsertItem (nCount, _T("Check sum 32"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	switch (m_nt_hdr32.OptionalHeader.Subsystem) {
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
	case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		lpszValue = _T("Windows CE GUI");
		break;
	default:
		lpszValue = _T("unknown");
		break;
	}
	list.InsertItem (nCount, _T("Sub-system"));
	list.SetItemText(nCount, 1, lpszValue);
	nCount++;
//	strValue.Format(szHex4Fmt, m_nt_hdr32.OptionalHeader.DllCharacteristics);
	strValue.Empty();
	if (m_nt_hdr32.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
		strValue += _T("DynamicBase, ");
	}
	if (m_nt_hdr32.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) {
		strValue += _T("ForceIntegrity, ");
	}
	if (m_nt_hdr32.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
		strValue += _T("NX Compatible, ");
	}
	if (m_nt_hdr32.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION) {
		strValue += _T("NoIsolation, ");
	}
	if (m_nt_hdr32.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
		strValue += _T("NoSEH, ");
	}
	if (m_nt_hdr32.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND) {
		strValue += _T("NoBind, ");
	}
	if (m_nt_hdr32.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER) {
		strValue += _T("WDM Driver, ");
	}
	if (m_nt_hdr32.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) {
		strValue += _T("TerminalServerAware, ");
	}
	if (!strValue.IsEmpty()) {
		strValue = strValue.Left(strValue.GetLength() - 2);
	}
	list.InsertItem (nCount, _T("DLL init.func.flags"));
	list.SetItemText(nCount, 1, strValue);
	nCount++;
	if (m_b32bit) {
		strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.SizeOfStackReserve);
		list.InsertItem (nCount, _T("Reserved stack size"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.SizeOfStackCommit);
		list.InsertItem (nCount, _T("Commit stack size"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.SizeOfHeapReserve);
		list.InsertItem (nCount, _T("Reserved heap size"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.SizeOfHeapCommit);
		list.InsertItem (nCount, _T("Commit heap size"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.LoaderFlags);
		list.InsertItem (nCount, _T("Loader flags"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.NumberOfRvaAndSizes);
		list.InsertItem (nCount, _T("Data directory No."));
		list.SetItemText(nCount, 1, strValue);
	//	nCount++;
	} else {
		strValue.Format(szHex16Fmt, m_nt_hdr64.OptionalHeader.SizeOfStackReserve);
		list.InsertItem (nCount, _T("Reserved stack size"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex16Fmt, m_nt_hdr64.OptionalHeader.SizeOfStackCommit);
		list.InsertItem (nCount, _T("Commit stack size"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex16Fmt, m_nt_hdr64.OptionalHeader.SizeOfHeapReserve);
		list.InsertItem (nCount, _T("Reserved heap size"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex16Fmt, m_nt_hdr64.OptionalHeader.SizeOfHeapCommit);
		list.InsertItem (nCount, _T("Commit heap size"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex8Fmt, m_nt_hdr64.OptionalHeader.LoaderFlags);
		list.InsertItem (nCount, _T("Loader flags"));
		list.SetItemText(nCount, 1, strValue);
		nCount++;
		strValue.Format(szHex8Fmt, m_nt_hdr64.OptionalHeader.NumberOfRvaAndSizes);
		list.InsertItem (nCount, _T("Data directory No."));
		list.SetItemText(nCount, 1, strValue);
	//	nCount++;
	}
	list.SetColumnWidth(1, LVSCW_AUTOSIZE);
	list.Detach();

	list.Attach(hwndDirList);
	list.DeleteAllItems();

	nCount = 0;
	if (m_b32bit) {
		for (DWORD dwEntry = 0; dwEntry < m_nt_hdr32.OptionalHeader.NumberOfRvaAndSizes; dwEntry++) {
			list.InsertItem(nCount, alpszDirName[dwEntry]);
			DWORD dwAddr = m_nt_hdr32.OptionalHeader.DataDirectory[dwEntry].VirtualAddress;
			if (dwAddr) {
				dwAddr += m_nt_hdr32.OptionalHeader.ImageBase;
			}
			strValue.Format(szHex8Fmt, dwAddr);
			list.SetItemText(nCount, 1, strValue);
			strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.DataDirectory[dwEntry].Size);
			list.SetItemText(nCount, 2, strValue);
			nCount++;
		}
	} else {
		for (DWORD dwEntry = 0; dwEntry < m_nt_hdr64.OptionalHeader.NumberOfRvaAndSizes; dwEntry++) {
			list.InsertItem(nCount, alpszDirName[dwEntry]);
			ULONGLONG qwAddr = m_nt_hdr64.OptionalHeader.DataDirectory[dwEntry].VirtualAddress;
			if (qwAddr) {
				qwAddr += m_nt_hdr64.OptionalHeader.ImageBase;
			}
			strValue.Format(szHex16Fmt, qwAddr);
			list.SetItemText(nCount, 1, strValue);
			strValue.Format(szHex8Fmt, m_nt_hdr64.OptionalHeader.DataDirectory[dwEntry].Size);
			list.SetItemText(nCount, 2, strValue);
			nCount++;
		}
	}
	list.SetColumnWidth(1, LVSCW_AUTOSIZE);
	list.Detach();

	list.Attach(hwndSecList);
	list.DeleteAllItems();

	nCount = 0;
	for (vector<IMAGE_SECTION_HEADER>::iterator it = m_vecSecHdr.begin(); it != m_vecSecHdr.end(); ++it) {
		list.InsertItem(nCount, CString(reinterpret_cast<LPSTR>(it->Name), IMAGE_SIZEOF_SHORT_NAME));
		if (m_b32bit) {
			strValue.Format(szHex8Fmt, m_nt_hdr32.OptionalHeader.ImageBase + it->VirtualAddress);
		} else {
			strValue.Format(szHex16Fmt, m_nt_hdr64.OptionalHeader.ImageBase + it->VirtualAddress);
		}
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
	list.SetColumnWidth(1, LVSCW_AUTOSIZE);
	list.SetColumnWidth(9, LVSCW_AUTOSIZE);
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
	DWORD dwAddrOfNameOrds = pExpDir->AddressOfNameOrdinals;
	LPWORD lpwOrdTable = reinterpret_cast<LPWORD>(&m_vecBuff[dwAddrOfNameOrds - m_dwSecAddr]);
	DWORD dwAddrOfNames = pExpDir->AddressOfNames;
	LPDWORD lpdwNameTable = reinterpret_cast<LPDWORD>(&m_vecBuff[dwAddrOfNames - m_dwSecAddr]);
	strMsg.Format(_T("# Number of functions: %u\r\n# Number of names: %u\r\n\r\n"),
			pExpDir->NumberOfFunctions, pExpDir->NumberOfNames);
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
	list.SetColumnWidth(1, LVSCW_AUTOSIZE);
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
	CString strOrdinal, strName;
	PIMAGE_IMPORT_DESCRIPTOR pImpDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(&m_vecBuff[m_dwDirAddr - m_dwSecAddr]);
//	for (int nDesc = 0; pImpDesc[nDesc].Characteristics; nDesc++) {
	for (int nDesc = 0; pImpDesc[nDesc].FirstThunk; nDesc++) {
	//	LPTSTR lpszServer = reinterpret_cast<LPTSTR>(&m_vecBuff[pImpDesc[nDesc].Name - m_dwSecAddr]);
		CString lpszServer = reinterpret_cast<LPSTR>(&m_vecBuff[pImpDesc[nDesc].Name - m_dwSecAddr]);
		if (!bFunc) {
			list.InsertItem(nCount++, lpszServer);
		} else {
//			DWORD dwFirstThunk = /*reinterpret_cast<DWORD>*/(pImpDesc[nDesc].OriginalFirstThunk);
			DWORD dwFirstThunk = (pImpDesc[nDesc].OriginalFirstThunk) ? pImpDesc[nDesc].OriginalFirstThunk : pImpDesc[nDesc].FirstThunk;
			if (m_b32bit) {
				PIMAGE_THUNK_DATA32 pThkDat = reinterpret_cast<PIMAGE_THUNK_DATA32>(&m_vecBuff[dwFirstThunk - m_dwSecAddr]);
				bool bLoadedExpFile = false;
				DWORD dwOrdinal;
				for (int nThunk = 0; dwOrdinal = pThkDat[nThunk].u1.Ordinal; nThunk++) {
					list.InsertItem(nCount, lpszServer);
					if (IMAGE_SNAP_BY_ORDINAL32(dwOrdinal)) {
						// 0x80000000 ... 0xffffffff
						dwOrdinal = IMAGE_ORDINAL32(dwOrdinal);
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
			} else {
				PIMAGE_THUNK_DATA64 pThkDat = reinterpret_cast<PIMAGE_THUNK_DATA64>(&m_vecBuff[dwFirstThunk - m_dwSecAddr]);
				bool bLoadedExpFile = false;
				ULONGLONG qwOrdinal;
				for (int nThunk = 0; qwOrdinal = pThkDat[nThunk].u1.Ordinal; nThunk++) {
					list.InsertItem(nCount, lpszServer);
					if (IMAGE_SNAP_BY_ORDINAL64(qwOrdinal)) {
						// 0x80000000'00000000 ... 0xffffffff'ffffffff
						DWORD dwOrdinal = static_cast<DWORD>(IMAGE_ORDINAL64(qwOrdinal));
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
						// 0x00000000'00000000 ... 0x7fffffff'ffffffff
						PIMAGE_IMPORT_BY_NAME pImpName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(&m_vecBuff[(DWORD)qwOrdinal - m_dwSecAddr]);
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
	}
	list.SetColumnWidth(0, LVSCW_AUTOSIZE);
	if (bFunc) {
		list.SetColumnWidth(2, LVSCW_AUTOSIZE);
	} else {
		list.SetColumnWidth(2, 48);
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
	TCHAR cName;
	BYTE bAccess;
	BYTE bAttr;
	bool bFunc;
	bool bType;
	bool bDeco;
	bool bClassName;
} aAttrTable[] = {
	_T('A'), accessPrivate,   attrNormal,  true,  true,  true,  false,
	_T('C'), accessPrivate,   attrStatic,  true,  true,  false, false,
	_T('E'), accessPrivate,   attrVirtual, true,  true,  true,  false,
	_T('I'), accessProtected, attrNormal,  true,  true,  true,  false,
	_T('K'), accessProtected, attrStatic,  true,  true,  false, false,
	_T('M'), accessProtected, attrVirtual, true,  true,  true,  false,
	_T('Q'), accessPublic,    attrNormal,  true,  true,  true,  false,
	_T('S'), accessPublic,    attrStatic,  true,  true,  false, false,
	_T('U'), accessPublic,    attrVirtual, true,  true,  true,  false,
	_T('Y'), accessNone,      attrExport,  true,  true,  false, false,
	_T('0'), accessPrivate,   attrStatic,  false, true,  true,  false,
	_T('1'), accessProtected, attrStatic,  false, true,  true,  false,
	_T('2'), accessPublic,    attrStatic,  false, true,  true,  false,
	_T('3'), accessNone,      attrExport,  false, true,  true,  false,
	_T('6'), accessNone,      attrNormal,  false, false, true,  true,
	_T('7'), accessNone,      attrNormal,  false, false, true,  true,
};

CString CAnalyzer::AnalyzeName(LPCTSTR lpszName, bool bPushCls)
{
	if (*lpszName != _T('?')) {
		return lpszName;
	}
	m_bOpCast = false;
	m_vecNameStack.clear();
	m_vecNameStack.push_back(vector<CString>());
	m_vecName = &m_vecNameStack[0];
	m_vecName->clear();
	m_vecArg.clear();
	LPCTSTR lpszStr = lpszName + 1;
	int nClsLen;
	CString strName = AnalyzeVcName(&lpszStr, true, &nClsLen);
	TCHAR cAttr = *lpszStr++;
	int nAttr;
	for (nAttr = 0; nAttr < lengthof(aAttrTable); nAttr++) {
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
		strAll += _T("__declspec(dllexport) ");
		break;
	}
	if (aAttrTable[nAttr].bFunc) {
//		TCHAR cDeco = _T('\0');
		if (aAttrTable[nAttr].bDeco) {
			strDeco = AnalyzeDeco(&lpszStr);
		}
		CString strFunc = AnalyzeFunc(&lpszStr, strName, NULL, PTR_NONE);
//		if (strFunc.IsEmpty()) {
//			return lpszName; // analyze error.
//		}
		strAll += strFunc;
		if (!strDeco.IsEmpty()) {
			strAll += _T(' ');
			strAll += strDeco;
		}
	} else {
		if (aAttrTable[nAttr].bType) {
			strType = AnalyzeVarType(&lpszStr, NULL, true);
		}
		if (aAttrTable[nAttr].bDeco) {
			strDeco = AnalyzeDeco(&lpszStr);
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
	_T("7`vftable'"),
	_T("8`vbtable'"),
	_T("9`vcall'"),
	_T("A`typeof'"),
	_T("B`local static guard'"),
	_T("C`string'"),
	_T("D`vbase destructor'"),
	_T("E`vector deleting destructor'"),
	_T("F`default constructor closure'"),
	_T("G`scalar deleting destructor'"),
	_T("H`vector constructor iterator'"),
	_T("I`vector destructor iterator'"),
	_T("J`vector vbase constructor iterator'"),
	_T("K`virtual displacement map'"),
	_T("L`eh vector constructor iterator'"),
	_T("M`eh vector destructor iterator'"),
	_T("N`eh vector vbase constructor iterator'"),
	_T("O`copy constructor closure'"),
	_T("S`local vftable'"),
	_T("T`local vftable constructor closure'"),
	_T("U@ new[]"),
	_T("V@ delete[]"),
	_T("X`placement delete closure'"),
	_T("Y`placement delete[] closure'"),
};

CString CAnalyzer::AnalyzeVcName(LPCTSTR *plpszStr, bool bRec, int *pnClsLen)
{
	bool bConstDest = false;
	CString strName;
	TCHAR c = *(*plpszStr)++;
	if (c == _T('?')) {
		c = *(*plpszStr);
		if (c == _T('$')) {  // template name
			(*plpszStr)++;
			c = *(*plpszStr)++;
			if (c == _T('_') || _istalpha(c) || c == _T('?')) {
				bool bPush = false;
				if (c == _T('?')) {
					strName = AnalyzeSpc(plpszStr, bConstDest);
				} else {
					do {
						strName += c;
						c = *(*plpszStr)++;
					} while (c != _T('@'));
					if (bRec) {
						bPush = true;
					}
				}
				m_vecNameStack.push_back(vector<CString>());
				m_vecName = &m_vecNameStack.back();
				if (bPush) {
					m_vecName->push_back(strName);
				}
				strName += _T('<');
				bool bCommaFlag = false;
				while (*(*plpszStr) != _T('@')) {
					if (bCommaFlag) {
						strName += _T(", ");
					}
					strName += AnalyzeVarType(plpszStr, NULL, /*false*/ true);
					bCommaFlag = true;
				}
				(*plpszStr)++;
				if (strName.Right(1) == _T('>')) {
					strName += _T(' ');
				}
				strName += _T('>');
				m_vecNameStack.pop_back();
				m_vecName = &m_vecNameStack.back();
				if (bPush && (pnClsLen == NULL)) {
					m_vecName->push_back(strName);
				}
			} else {
				strName = CString(_T("<unknown temp name : ")) + c + _T('>');
			}
		} else {
			strName = AnalyzeSpc(plpszStr, bConstDest);
		}
	} else
	if (_istdigit(c)) { // name repeaters
		if ((c - _T('0')) < (int)m_vecName->size()) {
			strName = (*m_vecName)[c - _T('0')];
		} else {
			strName = CString(_T("<unknown rep name : ")) + c + _T('>');
		}
	} else
	if (c == _T('_') || _istalpha(c)) {
		do {
			strName += c;
			c = *(*plpszStr)++;
		} while (c != _T('@'));
		if (bRec) {
			m_vecName->push_back(strName);
		}
	} else
	if (c == _T('@')) { // for class name, namespace name.
		return _T("");
	} else {
		strName = CString(_T("<unknown name : ")) + c + _T('>');
	}
	if (**plpszStr != _T('@')) { // for class name, namespace name.
		CString strWork = AnalyzeVcName(plpszStr, bRec, NULL);
		if (pnClsLen) {
			*pnClsLen = strWork.GetLength();
		}
		strName = strWork + _T("::") + strName;
		if (bConstDest) {
			strName += (*m_vecName)[0];
		}
	} else {
		(*plpszStr)++;
	}
	return strName;
}

CString CAnalyzer::AnalyzeSpc(LPCTSTR *plpszStr, bool &bConstDest)
{
	LPCTSTR lpszSpcName = NULL;
	CString strName;
	TCHAR c = *(*plpszStr)++;
	if (c == _T('_')) {
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
		strName = CString(_T("<unknown spc name : ")) + c + _T('>');
	}
	return strName;
}

CString CAnalyzer::AnalyzeFunc(LPCTSTR *plpszStr, LPCTSTR lpszName, LPCTSTR lpszPtrStr, PtrType eFuncPtr, bool bFuncRet)
{
	CString strWork, strWork2;
	TCHAR cCallSeq = *(*plpszStr)++;
	if (lpszName == NULL || !m_bOpCast) {
		strWork = AnalyzeVarType(plpszStr, NULL, true, true); // return value type.
		int i;
		if ((i = strWork.Find(_T('|'))) >= 0) {
			strWork2 = strWork.Mid(i + 1);
			strWork = strWork.Left(i);
		}
		strWork += _T(' ');
	}
	if (eFuncPtr != PTR_NONE) {
		strWork += _T('(');
	}
	switch (cCallSeq) { // calling sequence
	case _T('A'):
		strWork += _T("__cdecl ");
		break;
	case _T('C'):
		strWork += _T("__pascal ");
		break;
	case _T('E'):
		strWork += _T("__thiscall ");
		break;
	case _T('G'):
		strWork += _T("__stdcall ");
		break;
	case _T('I'):
		strWork += _T("__fastcall ");
		break;
	default:
		strWork += _T("<unknown call seq : ") + cCallSeq;
		strWork += _T("> ");
	}
	if (lpszName) {
		strWork += lpszName; // function name.
		if (m_bOpCast) { // operator char, int, ...
			strWork += _T(' ') + AnalyzeVarType(plpszStr, NULL, true, true); // return value type.
			m_bOpCast = false;
			int i;
			if ((i = strWork.Find(_T('|'))) >= 0) {
				strWork2 = strWork.Mid(i + 1);
				strWork = strWork.Left(i);
			}
		}
	}
	if (eFuncPtr != PTR_NONE) {
		strWork += _T('*');
		CString strWork2;
		switch (eFuncPtr) {
		case PTR_NORMAL:
			break;
		case PTR_CONST:
			strWork2 = _T(" const");
			break;
		case PTR_VOLATILE:
			strWork2 = _T(" volatile");
			break;
		case PTR_CONST_VOLATILE:
			strWork2 = _T(" const volatile");
			break;
		}
		CString strPtrStr(lpszPtrStr);
		if (strPtrStr.Left(strWork2.GetLength()) != strWork2) {
			strWork += strWork2;
		}
		strWork += lpszPtrStr;
		if (bFuncRet) {
			strWork += _T('|');	// '|': placeholder
		}
		strWork += _T(')');
	}
	strWork += _T('('); // arguments start.
	if (*(*plpszStr) == _T('X')) {
		strWork += _T("void");
	} else {
	//	m_vecArg.clear();
		bool bCommaFlag = false;
		while (*(*plpszStr) != _T('@')) {
			if (bCommaFlag) {
				strWork += _T(", ");
			}
			if (*(*plpszStr) == _T('Z')) { // variable argument
				strWork += _T("...");
				break;
			}
			strWork += AnalyzeVarType(plpszStr, NULL, true, false, true);
			bCommaFlag = true;
		}
	}
	(*plpszStr)++;
	TCHAR c = *(*plpszStr)++;
	if (c != _T('Z')) { // a function name has terminated by 'Z'.
		return strWork + _T("<unknown term : ") + c + _T('>');
	}
	strWork += _T(')'); // arguments end.
	strWork += strWork2;
	return strWork;
}

CString CAnalyzer::AnalyzeDeco(LPCTSTR *plpszStr)
{
	TCHAR c = *(*plpszStr)++;
	CString strWork;
	switch (c) {
	case _T('A'):
		return _T("");
	case _T('B'):
		return _T("const");
	case _T('C'):
		return _T("volatile");
	case _T('D'):
		return _T("const volatile");
	case _T('E'):
		strWork = AnalyzeDeco(plpszStr);
		if (!strWork.IsEmpty()) {
			strWork = _T(" ") + strWork;
		}
		return _T("__ptr64") + strWork;
	}
	return CString(_T("<unknown deco : ")) + c + _T('>');
}

CString CAnalyzer::AnalyzeVarType(LPCTSTR *plpszStr, LPCTSTR lpszPtrStr, bool bRec, bool bFuncRet, bool bArg)
{
	CString strPtr(lpszPtrStr);
	TCHAR c = *(*plpszStr)++;
	if (_istdigit(c)) { // argument repeaters
		if ((c - _T('0')) >= (int)m_vecArg.size()) {
			return CString(_T("<unknown arg : ")) + c + _T('>');
		}
		return m_vecArg[c - _T('0')];
	}
	switch (c) {
	case _T('@'):
		return _T("<no ret>");
	case _T('A'): // reference
		{
			CString strWork2 = AnalyzeDeco(plpszStr);
			CString strWork = AnalyzeVarType(plpszStr, NULL, bRec);
			if (strWork.Right(strWork2.GetLength()) != strWork2) {
				strWork += _T(" ") +strWork2;
			}
			strWork += _T(" &") + strPtr;
			if (bArg) {
				m_vecArg.push_back(strWork);
			}
			return strWork;
		}
//	case _T('B'): // unknown
	case _T('C'):
		return _T("signed char") + strPtr;
	case _T('D'):
		return _T("char") + strPtr;
	case _T('E'):
		return _T("unsigned char") + strPtr;
	case _T('F'):
		return _T("short") + strPtr;
	case _T('G'):
		return _T("unsigned short") + strPtr;
	case _T('H'):
		return _T("int") + strPtr;
	case _T('I'):
		return _T("unsigned int") + strPtr;
	case _T('J'):
		return _T("long") + strPtr;
	case _T('K'):
		return _T("unsigned long") + strPtr;
//	case _T('L'): // unknown
	case _T('M'):
		return _T("float") + strPtr;
	case _T('N'):
		return _T("double") + strPtr;
	case _T('O'):
		return _T("long double") + strPtr;
	case _T('P'): // pointer
		{
			CString strWork = AnalyzeVarTypePtr(plpszStr, lpszPtrStr, bRec, PTR_NORMAL, bFuncRet);
			if (bArg) {
				m_vecArg.push_back(strWork);
			}
			return strWork;
		}
	case _T('Q'): // const pointer
		{
			CString strWork = AnalyzeVarTypePtr(plpszStr, lpszPtrStr, bRec, PTR_CONST, bFuncRet);
			if (bArg) {
				m_vecArg.push_back(strWork);
			}
			return strWork;
		}
	case _T('R'): // volatile pointer
		{
			CString strWork = AnalyzeVarTypePtr(plpszStr, lpszPtrStr, bRec, PTR_VOLATILE, bFuncRet);
			if (bArg) {
				m_vecArg.push_back(strWork);
			}
			return strWork;
		}
	case _T('S'): // const volatile pointer
		{
			CString strWork = AnalyzeVarTypePtr(plpszStr, lpszPtrStr, bRec, PTR_CONST_VOLATILE, bFuncRet);
			if (bArg) {
				m_vecArg.push_back(strWork);
			}
			return strWork;
		}
	case _T('T'):
		{
			CString strWork = _T("union ") + AnalyzeVcName(plpszStr, bRec, NULL) + strPtr;
			if (bArg) {
				m_vecArg.push_back(strWork);
			}
			return strWork;
		}
	case _T('U'):
		{
			CString strWork = _T("struct ") + AnalyzeVcName(plpszStr, bRec, NULL) + strPtr;
			if (bArg) {
				m_vecArg.push_back(strWork);
			}
			return strWork;
		}
	case _T('V'):
		{
			CString strWork = _T("class ") + AnalyzeVcName(plpszStr, bRec, NULL) + strPtr;
			if (bArg) {
				m_vecArg.push_back(strWork);
			}
			return strWork;
		}
	case _T('W'):
		if (*(*plpszStr) == _T('4')) {
			(*plpszStr)++;
			CString strWork = _T("enum ") + AnalyzeVcName(plpszStr, bRec, NULL) + strPtr;
			if (bArg) {
				m_vecArg.push_back(strWork);
			}
			return strWork;
		}
		break;
	case _T('X'):
		return _T("void") + strPtr;
//	case _T('Y'): // unknown
//	case _T('Z'): // unknown
	case _T('?'): // union, struct, class, enum with decolattion.
		{
			CString strWork = AnalyzeDeco(plpszStr);
			if (!strWork.IsEmpty()) {
				strWork += _T(" ");
			}
			strWork += AnalyzeVarType(plpszStr, NULL, bRec) + strPtr;
			if (bArg) {
				m_vecArg.push_back(strWork);
			}
			return strWork;
		}
	case _T('_'): // enhanced name
		{
			CString strWork;
			switch (c = *(*plpszStr)++) {
			case _T('D'):
				strWork = _T("__int8") + strPtr;
				break;
			case _T('E'):
				strWork = _T("unsigned __int8") + strPtr;
				break;
			case _T('F'):
				strWork = _T("__int16") + strPtr;
				break;
			case _T('G'):
				strWork = _T("unsigned __int16") + strPtr;
				break;
			case _T('H'):
				strWork = _T("__int32") + strPtr;
				break;
			case _T('I'):
				strWork = _T("unsigned __int32") + strPtr;
				break;
			case _T('J'):
				strWork = _T("__int64") + strPtr;
				break;
			case _T('K'):
				strWork = _T("unsigned __int64") + strPtr;
				break;
			case _T('L'):
				strWork = _T("__int128") + strPtr;
				break;
			case _T('M'):
				strWork = _T("unsigned __int128") + strPtr;
				break;
			case _T('N'):
				strWork = _T("bool") + strPtr;
				break;
			case _T('W'):
				strWork = _T("wchar_t") + strPtr;
				break;
			}
			if (!strWork.IsEmpty() && bArg) {
				m_vecArg.push_back(strWork);
			}
			return strWork;
		}
	case _T('$'): // template parameter
		switch (c = *(*plpszStr)++) {
		case _T('0'): // integer
			{
				CString strWork;
				if (**plpszStr == _T('?')) {
					(*plpszStr)++;
					strWork.Format(_T("-%I64u"), AnalyzeUInt(plpszStr));
				} else {
					strWork.Format(_T("%I64u"), AnalyzeUInt(plpszStr));
				}
				strWork += strPtr;
				return strWork;
			}
		case _T('2'): // real number
			{
				CString strWork, strCoef;
				bool bMinus = false;
				if (**plpszStr == _T('?')) {
					(*plpszStr)++;
					bMinus = true;
				}
				ULONGLONG coef = AnalyzeUInt(plpszStr);
				LONGLONG exp = AnalyzeInt(plpszStr);
				strCoef.Format(_T("%I64u"), coef);
				strCoef.Insert(1, _T('.'));
				strWork.Format(_T("%s%se%I64d"), (bMinus) ? _T("-") : _T(""),
						static_cast<LPCTSTR>(strCoef), exp);
				strWork += strPtr;
				return strWork;
			}
		}
		return CString(_T("<unknown type/size : ")) + c + _T('>') + strPtr;
	}
	return CString(_T("<unknown type : ")) + c + _T('>') + strPtr;
}

CString CAnalyzer::AnalyzeVarTypePtr(LPCTSTR *plpszStr, LPCTSTR lpszPtrStr, bool bRec, PtrType ePtrType, bool bFuncRet)
{
	TCHAR c = *(*plpszStr)++;
	if (c == _T('6')) { // function pointer
		CString strFunc = AnalyzeFunc(plpszStr, NULL, lpszPtrStr, ePtrType, bFuncRet);
//		if (strFunc.IsEmpty()) {
//			return _T("<unknown func ptr>");
//		}
		return strFunc;
	}
	if (c == _T('8')) { // function pointer with class
		CString strCls  = AnalyzeVcName(plpszStr, bRec, NULL) + _T("::");
		CString strDeco = AnalyzeDeco(plpszStr);
		CString strFunc = AnalyzeFunc(plpszStr, strCls, lpszPtrStr, ePtrType, bFuncRet);
//		if (strFunc.IsEmpty()) {
//			return _T("<unknown func ptr>");
//		}
		if (!strDeco.IsEmpty()) {
			strFunc += _T(' ');
			strFunc += strDeco;
		}
		return strFunc;
	}
	--(*plpszStr);
	CString strWork = AnalyzeDeco(plpszStr);
	if (!strWork.IsEmpty()) {
		strWork = _T(" ") + strWork;
	}
	strWork += _T(" *");
	CString strWork2;
	switch (ePtrType) {
	case PTR_NORMAL:
		break;
	case PTR_CONST:
		strWork2 = _T(" const");
		break;
	case PTR_VOLATILE:
		strWork2 = _T(" volatile");
		break;
	case PTR_CONST_VOLATILE:
		strWork2 = _T(" const volatile");
		break;
	}
	CString strPtrStr(lpszPtrStr);
	if (strPtrStr.Left(strWork2.GetLength()) != strWork2) {
		strWork += strWork2;
	}
	strWork += lpszPtrStr;
	strWork = AnalyzeVarType(plpszStr, strWork, bRec);
//	m_vecArg.push_back(strWork);
	return strWork;
}

LONGLONG CAnalyzer::AnalyzeInt(LPCTSTR *plpszStr)
{
	int sign = 1;
	if (**plpszStr == _T('?')) {
		(*plpszStr)++;
		sign = -1;
	}
	return AnalyzeUInt(plpszStr) * sign;
}

ULONGLONG CAnalyzer::AnalyzeUInt(LPCTSTR *plpszStr)
{
	TCHAR c = *(*plpszStr)++;
	if (_istdigit(c)) {
		return c - _T('0') + 1;
	} else if ((_T('A') <= c) && (c <= _T('P'))) {
		ULONGLONG i = 0;
		do {
			i = (i << 4) + (c - _T('A'));
			c = *(*plpszStr)++;
		} while (c != _T('@'));
		return i;
	}
	return 0;
}
