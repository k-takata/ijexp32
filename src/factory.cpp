//
// factory.cpp
// Copyright (C) 1999 i.j , All rights reserved.
//

#include "stdafx.h"
#include "ijexp32.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

/////////////////////////////////////////////////////////////////////////////
// CFactory

CFactory::CFactory(DWORD dwID)
{
	m_nRef = 1;
	m_dwID = dwID;
//	::InterlockedIncrement(&g_nComponents);  // IClassFactory はカウントさせない。
}

CFactory::~CFactory()
{
//	::InterlockedDecrement(&g_nComponents);  // IClassFactory はカウントさせない。
}

HRESULT STDMETHODCALLTYPE CFactory::QueryInterface(REFIID riid, LPVOID *ppv)
{
	if (riid == IID_IUnknown) {
		*ppv = static_cast<IClassFactory *>(this);
	} else
	if (riid == IID_IClassFactory) {
		*ppv = static_cast<IClassFactory *>(this);
	} else {
		*ppv = NULL;
		return E_NOINTERFACE;
	}
	static_cast<IUnknown *>(*ppv)->AddRef();
	return S_OK;
}

ULONG STDMETHODCALLTYPE CFactory::AddRef(void)
{
	return ::InterlockedIncrement(&m_nRef);
}

ULONG STDMETHODCALLTYPE CFactory::Release(void)
{
	if (::InterlockedDecrement(&m_nRef) == 0) {
		delete this;
		return 0;
	}
	return m_nRef;
}

HRESULT STDMETHODCALLTYPE CFactory::CreateInstance(IUnknown *pUnknownOuter, REFIID riid, LPVOID *ppv)
{
	if (pUnknownOuter) {
		return CLASS_E_NOAGGREGATION;
	}
	IShellExtInit *pExt;
	switch (m_dwID) {
	case ID_EXEHDR:
		pExt = static_cast<IShellExtInit *>(new CHdrPropSheet);
		break;
	case ID_EXPORT:
		pExt = static_cast<IShellExtInit *>(new CExpPropSheet);
		break;
	case ID_IMPORT:
		pExt = static_cast<IShellExtInit *>(new CImpPropSheet);
		break;
	}
	if (pExt == NULL) {
		return E_OUTOFMEMORY;
	}
	HRESULT hr = pExt->QueryInterface(riid, ppv);
	pExt->Release();
	return hr;
}

HRESULT STDMETHODCALLTYPE CFactory::LockServer(BOOL bLock)
{
	if (bLock) {
		::InterlockedIncrement(&g_nServerLocks);
	} else {
		::InterlockedDecrement(&g_nServerLocks);
	}
	return S_OK;
}
