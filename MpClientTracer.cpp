#pragma once

#include <Windows.h>
#include <stdio.h>
#include <cassert>
#include "MpClient.h"

typedef HRESULT(WINAPI *MpManagerOpen)(
	_In_  DWORD     dwReserved,
	_Out_ PMPHANDLE phMpHandle
);

typedef HRESULT(WINAPI *MpScanStart)(
	_In_     MPHANDLE          hMpHandle,
	_In_     MPSCAN_TYPE       ScanType,
	_In_     DWORD             dwScanOptions,
	_In_opt_ PMPSCAN_RESOURCES pScanResources,
	_In_opt_ PMPCALLBACK_INFO  pCallbackInfo,
	_Out_    PMPHANDLE         phScanHandle
);

typedef HRESULT(WINAPI *MpHandleClose)(
	_In_ MPHANDLE hMpHandle
);

typedef HRESULT(WINAPI *MpErrorMessageFormat)(
	_In_  MPHANDLE hMpHandle,
	_In_  HRESULT  hrError,
	_Out_ LPWSTR* pwszErrorDesc
);

typedef void(WINAPI *MpFreeMemory) (
	_In_ PVOID pMemory
);

void PrintClbnameByValue(DWORD value) {
	switch (value) {
	case 0:
		printf("[!] Callback Type: MPCALLBACK_UNKNOWN\n");
		break;
	case 1:
		printf("[!] Callback Type: MPCALLBACK_STATUS\n");
		break;
	case 2:
		printf("[!] Callback Type: MPCALLBACK_THREAT\n");
		break;
	case 3:
		printf("[!] Callback Type: MPCALLBACK_SCAN\n");
		break;
	case 4:
		printf("[!] Callback Type: MPCALLBACK_CLEAN\n");
		break;
	case 5:
		printf("[!] Callback Type: MPCALLBACK_PRECHECK\n");
		break;
	case 6:
		printf("[!] Callback Type: MPCALLBACK_SIGUPDATE\n");
		break;
	case 7:
		printf("[!] Callback Type: MPCALLBACK_SAMPLE\n");
		break;
	case 8:
		printf("[!] Callback Type: MPCALLBACK_RESERVED\n");
		break;
	case 9:
		printf("[!] Callback Type: MPCALLBACK_CONFIGURATION_NOTIFICATION\n");
		break;
	case 10:
		printf("[!] Callback Type: MPCALLBACK_FASTPATH\n");
		break;
	case 11:
		printf("[!] Callback Type: MPCALLBACK_PRODUCT_EXPIRATION\n");
		break;
	case 12:
		printf("[!] Callback Type: MPCALLBACK_NIS_PRIVATE\n");
		break;
	case 13:
		printf("[!] Callback Type: MPCALLBACK_HEALTH\n");
		break;
	case 14:
		printf("[!] Callback Type: MPCALLBACK_ENDOFLIFE\n");
		break;
	case 15:
		printf("[!] Callback Type: MPCALLBACK_MALWARETOAST\n");
		break;
	default:
		printf("[!] Callback Type: Unhandled Callback Value\n");
		break;
	}
}

void __stdcall CallbackHandler(__int64 v4, MPCALLBACK_DATA* pClbData) {
	printf("\n---------------------------------\n");
	printf("\tCallback Handler\n");
	printf("---------------------------------\n");
	PrintClbnameByValue(pClbData->Type);
	printf("[!] Unkown v4 value: %I64u\n", v4);

	switch (pClbData->Notify) {
	case MPNOTIFY_INTERNAL_FAILURE:
		printf("[!] Callback Notify Type: MPNOTIFY_INTERNAL_FAILURE (File not found)\n");
		break;
	case MPNOTIFY_SCAN_START:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_START\n");
		break;
	case MPNOTIFY_SCAN_PAUSED:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_PAUSED\n");
		break;
	case MPNOTIFY_SCAN_RESUMED:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_RESUMED\n");
		break;
	case MPNOTIFY_SCAN_CANCEL:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_CANCEL\n");
		break;
	case MPNOTIFY_SCAN_COMPLETE:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_COMPLETE\n");
		printf("[!] Total Threat Count: %lu\n", ((PMPSCAN_DATA)pClbData->Data.pScanData)->ThreatStats.ThreatCount);
		printf("[!] Total Suspicious Threat Count: %lu\n", ((PMPSCAN_DATA)pClbData->Data.pScanData)->ThreatStats.SuspiciousThreatCount);
		printf("[!] Timestamp: %lu\n", pClbData->TimeStamp.LowPart);
		break;
	case MPNOTIFY_SCAN_PROGRESS:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_PROGRESS\n");
		break;
	case MPNOTIFY_SCAN_ERROR:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_ERROR\n");
		break;
	case MPNOTIFY_SCAN_INFECTED:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_INFECTED\n");
		break;
	case MPNOTIFY_SCAN_MEMORYSTART:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_MEMORYSTART\n");
		break;
	case MPNOTIFY_SCAN_MEMORYCOMPLETE:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_MEMORYCOMPLETE\n");
		break;
	case MPNOTIFY_SCAN_SFC_BUILD_START:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_SFC_BUILD_START\n");
		break;
	case MPNOTIFY_SCAN_SFC_BUILD_COMPLETE:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_SFC_BUILD_COMPLETE\n");
		break;
	case MPNOTIFY_SCAN_FASTPATH_START:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_FASTPATH_START\n");
		break;
	case MPNOTIFY_SCAN_FASTPATH_COMPLETE:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_FASTPATH_COMPLETE\n");
		break;
	case MPNOTIFY_SCAN_FASTPATH_PROGRESS:
		printf("[!] Callback Notify Type: MPNOTIFY_SCAN_FASTPATH_PROGRESS\n");
		break;
	default:
		printf("[!] Unhandled Notify Type\n");
		break;
	}
	printf("\n");
}

int main(int argc, char* argv[]) {

	LPWSTR* szArglist			 = NULL;
	LPWSTR szScheme				 = NULL;
	LPWSTR szPath				 = NULL;
	HMODULE hModule				 = NULL;
	HRESULT hRes				 = NULL;
	MPHANDLE mpManagerHandle	 = NULL;
	MPHANDLE mpScanHandle		 = NULL;
	MPRESOURCE_INFO mpResInfo	 = { 0 };
	MPSCAN_RESOURCES mpScanRes	 = { 0 };
	MPCALLBACK_INFO mpClbInfo	 = { 0 };
	int nArgs					 = 0;

	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (szArglist != NULL && nArgs > 2) {
		szScheme = szArglist[1];
		szPath = szArglist[2];
	}
	else {
		printf("Usage: MpClientTracer.exe <Scheme: file/folder> <Path>\n");
		return 0;
	}

	hModule = LoadLibrary(L"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2210.6-0\\MpClient.dll");
	if (!hModule || hModule == INVALID_HANDLE_VALUE) {
		printf("[-] Error: LoadLibrary failed. Last error: %d\n", GetLastError());
		return -1;
	}
	else {
		printf("[+] MpClient.dll loaded at 0x%p\n", hModule);
	}

	auto pMpManagerOpen = (MpManagerOpen)GetProcAddress(hModule, "MpManagerOpen");
	auto pMpScanStart = (MpScanStart)GetProcAddress(hModule, "MpScanStart");
	auto pMpHandleClose = (MpHandleClose)GetProcAddress(hModule, "MpHandleClose");
	auto pMpErrorMessageFormat = (MpErrorMessageFormat)GetProcAddress(hModule, "MpErrorMessageFormat");
	auto pMpFreeMemory = (MpFreeMemory)GetProcAddress(hModule, "MpFreeMemory");

	assert(pMpManagerOpen != NULL);
	assert(pMpScanStart != NULL);
	assert(pMpHandleClose != NULL);
	assert(pMpErrorMessageFormat != NULL);

	printf("[+] MpManagerOpen at 0x%p\n", pMpManagerOpen);
	printf("[+] MpScanStart at 0x%p\n", pMpScanStart);
	printf("[+] MpHandleClose at 0x%p\n", pMpHandleClose);
	printf("[+] MpErrorMessageFormat at 0x%p\n", pMpErrorMessageFormat);
	printf("[+] MpFreeMemory at 0x%p\n", pMpFreeMemory);

	hRes = pMpManagerOpen(0, &mpManagerHandle);
	if (FAILED(hRes)) {
		printf("[-] Error: MpManagerOpen failed. Last Error: %d\n", GetLastError());
		goto __exit;
	}
	else {
		printf("[+] MpManagerOpen success.\n");
	}

	mpResInfo.Scheme = szScheme;
	mpResInfo.Class = MP_RESOURCE_CLASS_UNKNOWN;
	mpResInfo.Path = szPath;
	mpScanRes.dwResourceCount = 1;
	mpScanRes.pResourceList = &mpResInfo;
	mpClbInfo.CallbackHandler = &CallbackHandler;

	hRes = pMpScanStart(mpManagerHandle, MPSCAN_TYPE_RESOURCE, 0, &mpScanRes, &mpClbInfo, &mpScanHandle);
	if (FAILED(hRes)) {
		wchar_t* szErrorMsg = NULL;
		pMpErrorMessageFormat(mpManagerHandle, hRes, &szErrorMsg);
		if (szErrorMsg) {
			int bufferSize = WideCharToMultiByte(CP_ACP, 0, szErrorMsg, -1, NULL, 0, NULL, NULL);
			char* m = new char[bufferSize];
			WideCharToMultiByte(CP_ACP, 0, szErrorMsg, -1, m, bufferSize, NULL, NULL);
			wprintf(L"[-] Error. MpScanStart failed: %S\n", m);
		}
		pMpFreeMemory(szErrorMsg);
		goto __exit;
	}

__exit:

	hRes = pMpHandleClose(mpManagerHandle);
	if (FAILED(hRes)) {
		printf("[-] Error: MpHandleClose mpManagerHandle failed. Last Error: %d\n", GetLastError());
		return -1;
	}

	hRes = pMpHandleClose(mpScanHandle);
	if (FAILED(hRes)) {
		printf("[-] Error: MpHandleClose mpScanHandle failed. Last Error: %d\n", GetLastError());
		return -1;
	}

	FreeLibrary(hModule);

	return 0;
}