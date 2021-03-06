//
// ijexp32.h
// Copyright (C) 1999 i.j , All rights reserved.
//
#ifndef __IJEXP32_H__
#define __IJEXP32_H__

#include <winnt.h>  // PE format structures
#include <shlobj.h> // IShellExtInit, IShellPropSheetExt
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


#ifndef IMAGE_FILE_MACHINE_ARMNT
#define IMAGE_FILE_MACHINE_ARMNT	0x01c4	// ARM Thumb-2 Little-Endian
#endif /* IMAGE_FILE_MACHINE_ARMNT */
#ifndef IMAGE_FILE_MACHINE_EBC
#define IMAGE_FILE_MACHINE_EBC		0x0EBC	// EFI Byte Code
#endif /* IMAGE_FILE_MACHINE_EBC */
#ifndef IMAGE_FILE_MACHINE_AMD64
#define IMAGE_FILE_MACHINE_AMD64	0x8664	// AMD64
#endif /* IMAGE_FILE_MACHINE_AMD64 */
#ifndef IMAGE_FILE_MACHINE_M32R
#define IMAGE_FILE_MACHINE_M32R		0x9041	// M32R little-endian
#endif /* IMAGE_FILE_MACHINE_M32R */
#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64	0xAA64	// ARM64 Little-Endian
#endif /* IMAGE_FILE_MACHINE_ARM64 */

#ifndef IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
#define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA	0x0020
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE		0x0040
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY	0x0080
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NX_COMPAT
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT			0x0100
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION		0x0200
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NO_SEH
#define IMAGE_DLLCHARACTERISTICS_NO_SEH				0x0400
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NO_BIND
#define IMAGE_DLLCHARACTERISTICS_NO_BIND			0x0800
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_APPCONTAINER
#define IMAGE_DLLCHARACTERISTICS_APPCONTAINER		0x1000
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF			0x4000
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE	0x8000
#endif

#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES		((DWORD)-1)
#endif

#ifndef HDF_SORTDOWN
#define HDF_SORTDOWN	0x0200
#endif
#ifndef HDF_SORTUP
#define HDF_SORTUP		0x0400
#endif


#ifndef lengthof
#define lengthof(x) (sizeof(x) / sizeof(*(x)))
#endif

#define IJE_REG_KEY				_T("Software\\ijexp")
#define IJE_INI_KEY				_T("ijexp")
#define DEFAULT_CXXFILT_PATH	_T("C:\\MinGW\\bin\\c++filt.exe")
#define DEFAULT_EXTS			_T(".exe;.dll;.sys")

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
bool SetClipboardText(HWND hwnd, const CString &strText);
CString LoadSetting(LPCTSTR lpKey, LPCTSTR lpDefault = NULL);

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
	CString m_strPath;
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
	static UINT CALLBACK PropSheetPageProc(HWND hwnd, UINT msg, LPPROPSHEETPAGE ppsp);
private:
	static CString GetText(HWND hwnd, bool bBinary);
	HRESULT CheckFileType(void);
};

// expprsht.cpp
#define EXP_STATUS_NUM	2
class CExpPropSheet : public IShellExtInit, IShellPropSheetExt
{
public:
	LONG  m_nRef;
	CString m_strPath;
	int m_SortStatus[EXP_STATUS_NUM];
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
	void SetPath(const CString &strPath);
	static INT_PTR CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
	static UINT CALLBACK PropSheetPageProc(HWND hwnd, UINT msg, LPPROPSHEETPAGE ppsp);
private:
	static CString GetText(HWND hwnd, bool bBinary, bool bDecode, bool bSelectedOnly);
	void OnColumnClick(HWND hwnd, LPNMLISTVIEW nmlv);
	static int CALLBACK Compare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
};

// impprsht.cpp
#define IMP_STATUS_NUM	3
class CImpPropSheet : public IShellExtInit, IShellPropSheetExt
{
public:
	LONG  m_nRef;
	CString m_strPath;
	int m_SortStatus[IMP_STATUS_NUM];
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
	void SetPath(const CString &strPath);
	static INT_PTR CALLBACK DlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
	static UINT CALLBACK PropSheetPageProc(HWND hwnd, UINT msg, LPPROPSHEETPAGE ppsp);
private:
	static CString GetText(HWND hwnd, bool bBinary, bool bSelectedOnly);
	void OnColumnClick(HWND hwnd, LPNMLISTVIEW nmlv);
	static int CALLBACK Compare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
};

typedef set<CString> setstr_t; // class members list
typedef vector<setstr_t> vecacc_t; // private, protected, public
typedef map<CString, vecacc_t> mapcls_t; // classes list

struct NoCase {
	inline bool operator()(const CString& s1, const CString& s2) const
	{
		return (s1.CompareNoCase(s2) > 0);
	}
};
typedef map<DWORD, CString> mapname_t; // ordinal, export name
typedef map<CString, mapname_t, NoCase> mapexp_t; // server, <ordinal, export name>

// cxxfilt.cpp
class CCxxFilt
{
public:
	CString	m_strCxxFiltPath;
	HANDLE	m_hInputWrite;
	HANDLE	m_hOutputRead;
//	HANDLE	m_hErrorRead;
	HANDLE	m_hChildProcess;
private:
	bool	m_launchfailed;
	CString	m_buf;

public:
	CCxxFilt();
	virtual ~CCxxFilt();
public:
	bool StartCxxFilt();
	bool StopCxxFilt();
	void SetCxxFiltPath(LPCTSTR lpszPath) { m_strCxxFiltPath = lpszPath; }
	CString Demangle(LPCTSTR lpszName);
//	void ClearError() { m_launchfailed = false; }
private:
	bool LaunchRedirectedChild(HANDLE hChildStdIn, HANDLE hChildStdOut, HANDLE hChildStdErr);
};

// analizer.cpp
class CAnalyzer
{
public:
	bool             m_bOpCast;
	DWORD            m_dwDirAddr;
	DWORD            m_dwDirSize;
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
	enum PtrType {PTR_NONE = -1, PTR_NORMAL, PTR_CONST, PTR_VOLATILE, PTR_CONST_VOLATILE};
	CCxxFilt	m_cxxfilt;
	int			m_logPixelsX;
public:
	CAnalyzer();
	~CAnalyzer();
public:
	void    LoadExpFile(LPCTSTR lpszServer, bool b64bit = false);
	bool    Open(HWND hwnd, LPCTSTR lpszPath, bool bQuiet = false);
	void    Close(void);
	bool    ReadSection(HWND hwnd, int nDirectory, bool bQuiet = false, bool bCheckOnly = false);
	bool    FindSection(HWND hwnd, int nDirectory, bool bQuiet = true);
	void    AnalyzeExeHdrInit(HWND hwndHdrList, HWND hwndDirList, HWND hwndSecList);
	void    AnalyzeExportInit(HWND hwndList);
	void    AnalyzeImportInit(HWND hwndList);
	bool    AnalyzeExeHdr(HWND hwndHdrList, HWND hwndDirList, HWND hwndSecList);
	bool    AnalyzeExport(HWND hwndMsg, HWND hwndList, bool bDecode);
	bool    AnalyzeImport(HWND hwndList, bool bFunc, bool bDecode);
	CString AnalyzeName  (LPCTSTR lpszName, bool bPushCls);
	CString AnalyzeVcName(LPCTSTR *plpszStr, bool bRec, int *pnClsLen);
	CString AnalyzeSpc   (LPCTSTR *plpszStr, bool &bConstDest);
	CString AnalyzeFunc  (LPCTSTR *plpszStr, LPCTSTR lpszName, LPCTSTR lpszPtrStr, PtrType eFuncPtr, bool bFuncRet = false);
	CString AnalyzeDeco  (LPCTSTR *plpszStr);
	CString AnalyzeVarType   (LPCTSTR *plpszStr, LPCTSTR lpszName, bool bRec, bool bFuncRet = false, bool bArg = false);
	CString AnalyzeVarTypePtr(LPCTSTR *plpszStr, LPCTSTR lpszName, bool bRec, PtrType ePtrType, bool bFuncRet = false);
	LONGLONG AnalyzeInt(LPCTSTR *plpszStr);
	ULONGLONG AnalyzeUInt(LPCTSTR *plpszStr);
private:
	void	LoadCxxFiltPath();
	void	GetLogPixels();
	int		GetDpiScaledX(int x) { return x * m_logPixelsX / 96; }
};

#endif
