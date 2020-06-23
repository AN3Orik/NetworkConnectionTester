#pragma comment( lib, "psapi.lib" )
#pragma comment(lib, "shell32.lib")

#include <iostream>
#include <winsock2.h>
#include <Windows.h>
#include <tlhelp32.h>
#include "NetworkConnectionTester.cpp"

using namespace std;

std::vector<DWORD> FindProcessId(LPCTSTR ProcessName, bool onlyFirst = true) {
	std::vector<DWORD> processes;
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) {
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				processes.push_back(pt.th32ProcessID);
				if (onlyFirst) {
					CloseHandle(hsnap);
					return processes;
				}
			}
		}
		while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap);
	return processes;
}

int main() {
	NetworkConnectionTester* networkConnectionTester;
	
	std::vector<DWORD> processes = FindProcessId(L"steam.exe");
	if (!processes.empty()) {
		DWORD pid = processes.front();
		networkConnectionTester = new NetworkConnectionTester(pid, { 80, 443 });
		networkConnectionTester->Start();
		cout << "Watcher started for PID " << pid << std::endl;
	}
	else {
		cout << "Process with specified name not found." << std::endl;
	}
	system("pause");
	return 0;
}

