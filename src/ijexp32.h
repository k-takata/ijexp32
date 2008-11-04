//
// ijexp32.h
// Copyright (C) 1999 i.j , All rights reserved.
//
#ifndef __IJEXP32_H__
#define __IJEXP32_H__

#include "winnt.h"  // PE format structures
#include "shlobj.h" // IShellExtInit, IShellPropSheetExt
#include <vector>
#include <map>
#include <set>

using namespace std;

/* for VC6 compatibility */
#ifndef _W64
typedef unsigned long DWORD_PTR;
typedef long LONG_PTR;
typedef unsigned long ULONG_PTR;

#define SetWindowLongPtr	SetWindowLong
#define GetWindowLongPtr	GetWindowLong
#define GWLP_WNDPROC	GWL_WNDPROC
#define GWLP_HINSTANCE	GWL_HINSTANCE
#define GWLP_ID			GWL_ID
#define GWLP_USERDATA	GWL_USERDATA
#define DWLP_DLGPROC	DWL_DLGPROC
#define DWLP_MSGRESULT	DWL_MSGRESULT
#define DWLP_USER		DWL_USER
#endif

/* for scope */
#define for if (0) ; else for


#ifndef IMAGE_FILE_MACHINE_AMD64
#define IMAGE_FILE_MACHINE_AMD64	0x8664	// AMD64
#endif /* IMAGE_FILE_MACHINE_AMD64 */

#ifndef lengthof
#define lengthof(x) (sizeof(x) / sizeof(*(x)))
#endif

enum {
	ID_EXEHDR,
	ID_EXPORT,
	ID_IMPORT,
};

extern LONG    g_nComponents;
extern LONG    g_nServerLocks;
extern HMODULE g_hModule;

// {00000001-23D0-0001-8000-004026419740}
DEFINE_GUID(CLSID_ExeHdr,
0x00000001, 0x23d0, 0x0001, 0x80, 0x00, 0x00, 0x40, 0x26, 0x41, 0x97, 0x40);

// {00000002-23D0-0001-8000-004026419740}
DEFINE_GUID(CLSID_Export,
0x00000002, 0x23d0, 0x0001, 0x80, 0x00, 0x00, 0x40, 0x26, 0x41, 0x97, 0x40);

// {00000003-23D0-0001-8000-004026419740}
DEFINE_GUID(CLSID_Import,
0x00000003, 0x23d0, 0x0001, 0x80, 0x00, 0x00, 0x40, 0x26, 0x41, 0x97, 0x40);

// ijexp32.cpp
void MsgBox(HWND hwnd, LPCTSTR lpszCaption, UINT nId);
bool IsWindowsXP(void);
bool SetClipboardText(HWND hwnd, const CString &strText);

// factory.cpp
class CFactory : public IClassFactory
{
public:
	LONG  m_nRef;
	DWORD m_dwID;
public:
	CFactory(DWORD dwID);
	~CFactory();
public:
	virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, LPVOID *ppv);
	virtual ULONG   STDMETHODCALLTYPE AddRef(void);
	virtual ULONG   STDMETHODCALLTYPE Release(void);
public:
	virtual HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown *pUnknownOuter, REFIID riid, LPVOID *ppv);
	virtual HRESULT STDMETHODCALLTYPE LockServer(BOOL bLock);
};

// hdrpprsht.cpp
class CHdrPropSheet : public IShellExtInit, IShellPropSheetExt
{
public:
	LONG  m_nRef;
	TCHAR m_szPath[1024];
public:
	CHdrPropSheet();
	~CHdrPropSheet();
public: // IUnknown
	virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, LPVOID *ppv);
	virtual ULONG   STDMETHODCALLTYPE AddRef(void);
	virtual ULONG   STDMETHODCALLTYPE Release(void);
public: // IShellExtInit
	virtual HRESULT STDMETHODCALLTYPE Initialize(LPCITEMIDLIST pidlFolder, LPDATAOBJECT lpDatObj, HKEY hkeyProgID);
public: // IShellPropSheetExt
	virtual HRESULT STDMETHODCALLTYPE AddPages(LPFNADDPROPSHEETPAGE lpfnAddPage, LPARAM lParam);
	virtual HRESULT STDMETHODCALLTYPE ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE lpfnReplacePage, LPARAM lParam);
public:
	static INT_PTR CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
private:
	static CString GetText(HWND hwnd, bool bBinary);
};

// expprsht.cpp
class CExpPropSheet : public IShellExtInit, IShellPropSheetExt
{
public:
	LONG  m_nRef;
	TCHAR m_szPath[1024];
public:
	CExpPropSheet();
	~CExpPropSheet();
public: // IUnknown
	virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, LPVOID *ppv);
	virtual ULONG   STDMETHODCALLTYPE AddRef(void);
	virtual ULONG   STDMETHODCALLTYPE Release(void);
public: // IShellExtInit
	virtual HRESULT STDMETHODCALLTYPE Initialize(LPCITEMIDLIST pidlFolder, LPDATAOBJECT lpDatObj, HKEY hkeyProgID);
public: // IShellPropSheetExt
	virtual HRESULT STDMETHODCALLTYPE AddPages(LPFNADDPROPSHEETPAGE lpfnAddPage, LPARAM lParam);
	virtual HRESULT STDMETHODCALLTYPE ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE lpfnReplacePage, LPARAM lParam);
public:
	static INT_PTR CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
private:
	static CString GetText(HWND hwnd, bool bBinary, bool bDecode);
};

// impprsht.cpp
class CImpPropSheet : public IShellExtInit, IShellPropSheetExt
{
public:
	LONG  m_nRef;
	TCHAR m_szPath[1024];
public:
	CImpPropSheet();
	~CImpPropSheet();
public: // IUnknown
	virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, LPVOID *ppv);
	virtual ULONG   STDMETHODCALLTYPE AddRef(void);
	virtual ULONG   STDMETHODCALLTYPE Release(void);
public: // IShellExtInit
	virtual HRESULT STDMETHODCALLTYPE Initialize(LPCITEMIDLIST pidlFolder, LPDATAOBJECT lpDatObj, HKEY hkeyProgID);
public: // IShellPropSheetExt
	virtual HRESULT STDMETHODCALLTYPE AddPages(LPFNADDPROPSHEETPAGE lpfnAddPage, LPARAM lParam);
	virtual HRESULT STDMETHODCALLTYPE ReplacePage(UINT uPageID, LPFNADDPROPSHEETPAGE lpfnReplacePage, LPARAM lParam);
public:
	static INT_PTR CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
private:
	static CString GetText(HWND hwnd, bool bBinary);
};

typedef set<CString> setstr_t; // class members list
typedef vector<setstr_t> vecacc_t; // private, protected, public
typedef map<CString, vecacc_t> mapcls_t; // classes list

struct NoCase {
	inline bool operator()(const CString& s1, const CString& s2) const
	{
		return (s1.CompareNoCase(s2) == +1);
	}
};
typedef map<DWORD, CString> mapname_t; // ordinal, export name
typedef map<CString, mapname_t, NoCase> mapexp_t; // server, <ordinal, export name>

// analizer.cpp
class CAnalyzer
{
public:
	bool             m_bOpCast;
	DWORD            m_dwDirAddr;
	DWORD            m_dwSecAddr;
	CFile            m_file;
	mapcls_t         m_mapCls;  // classes list
	mapexp_t         m_mapExp;  // export name list
	vector<BYTE>     m_vecBuff; // section data
	vector<CString>  *m_vecName; // VC : name stack
	vector<vector<CString> > m_vecNameStack; // VC : name stack
	vector<CString>  m_vecArg;  // VC : arguments stack
	IMAGE_DOS_HEADER m_dos_hdr;
	union {
		struct {
			DWORD Signature;
			IMAGE_FILE_HEADER FileHeader;
		} m_nt_hdr;
		IMAGE_NT_HEADERS32 m_nt_hdr32;
		IMAGE_NT_HEADERS64 m_nt_hdr64;
	};
	bool m_b32bit;
	vector<IMAGE_SECTION_HEADER> m_vecSecHdr;
public:
	CAnalyzer();
	~CAnalyzer();
public:
	void    LoadExpFile(LPCTSTR lpszServer);
	bool    Open(HWND hwnd, LPCTSTR lpszPath);
	void    Close(void);
	bool    ReadSection(HWND hwnd, int nDirectory);
	void    AnalyzeExeHdrInit(HWND hwndHdrList, HWND hwndDirList, HWND hwndSecList);
	void    AnalyzeExportInit(HWND hwndList);
	void    AnalyzeImportInit(HWND hwndList);
	bool    AnalyzeExeHdr(HWND hwndHdrList, HWND hwndDirList, HWND hwndSecList);
	bool    AnalyzeExport(HWND hwndMsg, HWND hwndList, bool bDecode);
	bool    AnalyzeImport(HWND hwndList, bool bFunc, bool bDecode);
	CString AnalyzeName  (LPCTSTR lpszName, bool bPushCls);
	CString AnalyzeVcName(LPCTSTR *plpszStr, bool bRec, int *pnClsLen);
	CString AnalyzeSpc   (LPCTSTR *plpszStr, bool &bConstDest);
	CString AnalyzeFunc  (LPCTSTR *plpszStr, LPCTSTR lpszName, bool bFuncPtr, bool bFuncRet = false);
	CString AnalyzeDeco  (LPCTSTR *plpszStr);
	CString AnalyzeVarType   (LPCTSTR *plpszStr, bool bRec, bool bFuncRet = false, bool bArg = false);
	CString AnalyzeVarTypePtr(LPCTSTR *plpszStr, bool bRec, bool bFuncRet = false);
	__int64 AnalyzeInt(LPCTSTR *plpszStr);
	unsigned __int64 AnalyzeUInt(LPCTSTR *plpszStr);
};

#endif
