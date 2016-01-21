// test.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>
#include <string.h>
#include <Tlhelp32.h>
#include <stdio.h>
//#include <Winternl.h>
#include <stdlib.h>
#include <process.h>

#pragma comment(lib, "user32.lib")

HANDLE hProcess;

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	MaxThreadInfoClass
}THREADINFOCLASS,*PTHREADINFOCLASS;
/*函数指针*/
typedef NTSTATUS(WINAPI *NTQUERYINFORMATIONTHREAD)(
	HANDLE ThreadHandle,
	ULONG ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength);

//------------------------声明提权函数--------------------------------
bool EnablePrivilege(LPCTSTR pszPrivName, bool fEnable)
{
	bool fOk = false;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp = { 1 };


		//如果成功查找到特权值
		if (LookupPrivilegeValue(NULL, pszPrivName, &tp.Privileges[0].Luid))
		{
			tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
			AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL);
			fOk = (GetLastError() == ERROR_SUCCESS);
		}
		CloseHandle(hToken);
	}
	return(fOk);
}
//--------------------------声明结束----------------------------------

DWORD GetThreadStartAddr(DWORD dwThreadId)
{
	NTQUERYINFORMATIONTHREAD NtQueryInformationThread = NULL;
	NtQueryInformationThread = (NTQUERYINFORMATIONTHREAD)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQueryInformationThread");

	if (!NtQueryInformationThread)
	{
		printf("NtQueryInformationThread failed! error:%08x\n", GetLastError());
		return 0;
	}

	HANDLE ThreadHandle = NULL;
	ThreadHandle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, dwThreadId);
	if (!ThreadHandle)
	{
		printf("ThreadHandle failed error:%x!\n", GetLastError());
	}

	DWORD dwStaAddr = NULL;
	DWORD dwReturnLength = 0;
	if (NtQueryInformationThread(ThreadHandle, 9, &dwStaAddr, sizeof(dwStaAddr), &dwReturnLength))
	{
		return 0;
	}
	
	//printf("%08x", dwThreadId);
	CloseHandle(ThreadHandle);
	return dwStaAddr;
	
}

void printError(const char *format, ...)
{
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language  
		sysMsg, 256, NULL);

	// Trim the end of the line and terminate it with a null  
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));

	char msg[1024];
	va_list arg;
	va_start(arg, format);
	//int charSize = sprintf(msg, format, arg);
	va_end(arg);

	// Display the message  
	//	printf("/n  WARNING: %s failed with error %d (%s)/n", msg, eNum, sysMsg);
}

VOID check_code(PULONG ThreadAddr)
{
	
	PUCHAR pStart =(PUCHAR) ThreadAddr;

	BOOL x;
	char tmp[17] = { 0 };
	PUCHAR lpBuffer=(PUCHAR)tmp;
	PULONG readByte=NULL;
	if (!(x = ReadProcessMemory(hProcess, pStart, lpBuffer, 16, readByte)))
	{
		printf("ReadProcessMemory failed\t");
		printf("error:%08x\n", GetLastError());
	}

	//printf("%d\n",*lpBuffer);
	
	for (ULONG i = 0; i < 16; i++)
	{
		//printf("11");
		if (*(lpBuffer + i) == 0x56 && *(lpBuffer + i + 1) == 0x8B && *(lpBuffer + i + 2) == 0x35 && *(lpBuffer + i + 7) == 0x57 && *(lpBuffer + i + 8) == 0x8B && *(lpBuffer + i + 9) == 0x3d && *(lpBuffer + i + 14) == 0x8B && *(lpBuffer + i + 15) == 0xFF)
		{
			printf("some one cheating!\n");
			MessageBox(NULL, L"fuck", L"u", MB_OK);
		}
			
	}

	return;
}

BOOL ListProcessThread(ULONG dwOwnerPID)
{
	HANDLE        hThreadSnap = NULL;
	BOOL          bRet = FALSE;
	THREADENTRY32 te32 = { 0 };
	DWORD dwThreadId;

	// Take a snapshot of all threads currently in the system.   

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == (HANDLE)-1)
	{
		printError("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)");
		return (FALSE);
	}

	// Fill in the size of the structure before using it.   
	te32.dwSize = sizeof(THREADENTRY32);
	// Walk the thread snapshot to find all threads of the process.   
	// If the thread belongs to the process, add its information   
	// to the display list.   
	if (Thread32First(hThreadSnap, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == dwOwnerPID)
			{
				
				dwThreadId= GetThreadStartAddr(te32.th32ThreadID);
				printf("TID:  %d Et:%08x\n", te32.th32ThreadID, dwThreadId);
				check_code((PULONG)dwThreadId);
				
				
				//MessageBox(NULL, L"!", L"11", MB_OK);
				bRet = TRUE;
			}
		} while (Thread32Next(hThreadSnap, &te32));
	}
	else
	{
		printError("Thread32First(hThreadSnap)");
		bRet = FALSE;          // could not walk the list of threads   
	}

	// Do not forget to clean up the snapshot object.   
	CloseHandle(hThreadSnap);

	return (bRet);
}

DWORD GetProcessIDFromName(char *name)
{
	int Ret;
	HANDLE snapshot;
	PROCESSENTRY32 processinfo;
	processinfo.dwSize = sizeof(processinfo);
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == NULL)
		return FALSE;

	BOOL status = Process32First(snapshot, &processinfo);
	
	while (status)
	{
		//printf("%s\n", name);
		if ((Ret= _strcmpi(name, processinfo.szExeFile)) == 0)
			return processinfo.th32ProcessID;
		status = Process32Next(snapshot, &processinfo);
	}
	CloseHandle(snapshot);
	return -1;
}

int main()
{
	EnablePrivilege(L"SeDebugPrivilege", true);
	DWORD pid;
	//printf("输下war3 PID:\n");

	//scanf_s("%d", &pid);
	
	char name[] = "war3.exe";
	//printf("%s\n", name);
	pid=GetProcessIDFromName(name);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess)
	{
		printf("OpenProcess failed error:%x!\n", GetLastError());
	}
	ListProcessThread(pid);
	//MessageBox(NULL, L"fuck1", L"u", MB_OK);
	CloseHandle(hProcess);
	system("pause");
	return 0;
}

