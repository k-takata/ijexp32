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
	static BOOL CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
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
	static BOOL CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
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
	static BOOL CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
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
	vector<CString>  m_vecName; // VC : name stack
	vector<CString>  m_vecArg;  // VC : arguments stack
	IMAGE_DOS_HEADER m_dos_hdr;
	IMAGE_NT_HEADERS m_nt_hdr;
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
	CString AnalyzeName  (LPCSTR lpszName, bool bPushCls);
	CString AnalyzeVcName(LPCSTR *plpszStr, bool bRec, int *pnClsLen);
	CString AnalyzeFunc  (LPCSTR *plpszStr, LPCTSTR lpszName, bool bFuncPtr);
	CString AnalyzeDeco  (CHAR cDeco);
	CString AnalyzeVarType   (LPCSTR *plpszStr, bool bRec);
	CString AnalyzeVarTypePtr(LPCSTR *plpszStr, bool bRec);
};

#endif
