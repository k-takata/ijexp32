//
// cxxfilt.cpp
// Copyright (C) 2013 K.Takata, All rights reserved.
//

#include "stdafx.h"
#include "ijexp32.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif

template <HANDLE T> inline BOOL SafeCloseHandle(HANDLE &handle)
{
	BOOL ret = TRUE;

	if (handle != T) {
		ret = CloseHandle(handle);
		if (ret) {
			handle = T;
		}
	}
	return ret;
}

CCxxFilt::CCxxFilt()
{
	m_hInputWrite = INVALID_HANDLE_VALUE;
	m_hOutputRead = INVALID_HANDLE_VALUE;
//	m_hErrorRead = INVALID_HANDLE_VALUE;
	m_hChildProcess = NULL;
	m_launchfailed = false;
}

CCxxFilt::~CCxxFilt()
{
	StopCxxFilt();
}

bool CCxxFilt::StartCxxFilt()
{
	HANDLE hInputRead = INVALID_HANDLE_VALUE, hInputWriteTmp = INVALID_HANDLE_VALUE;
	HANDLE hOutputWrite = INVALID_HANDLE_VALUE, hOutputReadTmp = INVALID_HANDLE_VALUE;
	HANDLE hErrorWrite = INVALID_HANDLE_VALUE;
	SECURITY_ATTRIBUTES sa;

	if (m_hChildProcess != NULL) {
		return true;
	}
	if (m_launchfailed) {
		return false;
	}
	if (m_strCxxFiltPath.IsEmpty()) {
		goto error;
	}

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	// Create the child output pipe.
	if (!CreatePipe(&hOutputReadTmp, &hOutputWrite, &sa, 0)) {
		goto error;
	}
	// Duplicate the output write handle for the child stderr write handle.
	if (!DuplicateHandle(GetCurrentProcess(), hOutputWrite,
				GetCurrentProcess(), &hErrorWrite, 0,
				TRUE, DUPLICATE_SAME_ACCESS)) {
		goto error;
	}
	// Create the child input pipe.
	if (!CreatePipe(&hInputRead, &hInputWriteTmp, &sa, 0)) {
		goto error;
	}
	if (!DuplicateHandle(GetCurrentProcess(), hOutputReadTmp,
				GetCurrentProcess(), &m_hOutputRead,
				0, FALSE,  // Make it uninheritable.
				DUPLICATE_SAME_ACCESS)) {
		goto error;
	}
	if (!DuplicateHandle(GetCurrentProcess(), hInputWriteTmp,
				GetCurrentProcess(), &m_hInputWrite,
				0, FALSE,  // Make it uninheritable.
				DUPLICATE_SAME_ACCESS)) {
		goto error;
	}
	// Close inheritable copies of the handles you do not want to be
	// inherited.
	SafeCloseHandle<INVALID_HANDLE_VALUE>(hOutputReadTmp);
	SafeCloseHandle<INVALID_HANDLE_VALUE>(hInputWriteTmp);

	if (!LaunchRedirectedChild(hInputRead, hOutputWrite, hErrorWrite)) {
		goto error;
	}

	SafeCloseHandle<INVALID_HANDLE_VALUE>(hInputRead);
	SafeCloseHandle<INVALID_HANDLE_VALUE>(hOutputWrite);
	SafeCloseHandle<INVALID_HANDLE_VALUE>(hErrorWrite);

	return true;

error:
	SafeCloseHandle<INVALID_HANDLE_VALUE>(hOutputReadTmp);
	SafeCloseHandle<INVALID_HANDLE_VALUE>(hInputWriteTmp);
	SafeCloseHandle<INVALID_HANDLE_VALUE>(hInputRead);
	SafeCloseHandle<INVALID_HANDLE_VALUE>(hOutputWrite);
	SafeCloseHandle<INVALID_HANDLE_VALUE>(hErrorWrite);

	StopCxxFilt();
	m_launchfailed = true;
	return false;
}

bool CCxxFilt::StopCxxFilt()
{
	SafeCloseHandle<INVALID_HANDLE_VALUE>(m_hInputWrite);
	SafeCloseHandle<INVALID_HANDLE_VALUE>(m_hOutputRead);
//	SafeCloseHandle<INVALID_HANDLE_VALUE>(m_hErrorRead);
	SafeCloseHandle<NULL>(m_hChildProcess);
	m_launchfailed = false;
	return true;
}


CString CCxxFilt::Demangle(LPCTSTR lpszName)
{
	DWORD cb;
	BOOL ret = FALSE;

	if (!StartCxxFilt()) {
		return lpszName;
	}

	// send string
#ifdef _UNICODE
	int len = WideCharToMultiByte(CP_ACP, 0, lpszName, -1, NULL, 0, NULL, NULL);
	if (len == 0) {
		return lpszName;
	}
	try {
		char *buf = new char[len];
		if (WideCharToMultiByte(CP_ACP, 0, lpszName, -1, buf, len, NULL, NULL)) {
			ret = WriteFile(m_hInputWrite, buf, len - 1, &cb, NULL);
		}
		delete [] buf;
	} catch (CMemoryException* e) {
		//OutputDebugString(_T("Out of memory\n"));
		e->Delete();
		return lpszName;
	}
#else
	ret = WriteFile(m_hInputWrite, lpszName, strlen(lpszName), &cb, NULL);
#endif
	if (!ret) {
		return lpszName;
	}
	CHAR c = '\n';
	if (!WriteFile(m_hInputWrite, &c, sizeof(c), &cb, NULL)) {
		return lpszName;
	}

	// get the result
	CString str;
	while (true) {
		if (!ReadFile(m_hOutputRead, &c, sizeof(c), &cb, NULL)) {
			return lpszName;
		}
		if (c == '\r') {	// skip CR
			continue;
		}
		if (c == '\n') {
			break;
		}
		str += c;
	}
	return str;
}

bool CCxxFilt::LaunchRedirectedChild(HANDLE hChildStdIn, HANDLE hChildStdOut, HANDLE hChildStdErr)
{
	BOOL ret;
	PROCESS_INFORMATION pi;
	STARTUPINFO si = {0};
	CString cmdline;

	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.hStdInput  = hChildStdIn;
	si.hStdOutput = hChildStdOut;
	si.hStdError  = hChildStdErr;
	si.wShowWindow = SW_HIDE;

	// MFC 7.0 or earlier doesn't have CString::Tokenize().
	CString buf = m_strCxxFiltPath;
	LPCTSTR separator = _T(";");
	LPTSTR tok = _tcstok(buf.GetBuffer(0), separator);
	while (tok != NULL) {
		DWORD attr = GetFileAttributes(tok);
		if ((attr != INVALID_FILE_ATTRIBUTES)
				&& ((attr & FILE_ATTRIBUTE_DIRECTORY) == 0)) {
			// Executable file is found.
			cmdline.Format(_T("\"%s\" -n"), tok);	// -n: Do not ignore a leading underscore
			break;
		}
		tok = _tcstok(NULL, separator);
	}
	if (tok == NULL) {
		return false;
	}

	ret = CreateProcess(NULL, cmdline.GetBuffer(0), NULL, NULL, TRUE,
			CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (!ret) {
		//OutputDebugString(_T("CreateProcess failed"));
		return false;
	}
	m_hChildProcess = pi.hProcess;
	CloseHandle(pi.hThread);
	return true;
}
