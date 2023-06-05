#pragma comment( lib, "psapi.lib" )
#pragma comment(lib, "shell32.lib")

#include <iostream>
#include <winsock2.h>
#include <Windows.h>
#include <tlhelp32.h>
#include "NetworkConnectionTester.hpp"

using namespace std;

std::vector<DWORD> FindProcessId(const LPCTSTR process_name, const bool only_first = true) {
	std::vector<DWORD> processes;
	PROCESSENTRY32 pt;
	const HANDLE snapshot_helper = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(snapshot_helper, &pt)) {
		do {
			if (!lstrcmpi(pt.szExeFile, process_name)) {
				processes.push_back(pt.th32ProcessID);
				if (only_first) {
					CloseHandle(snapshot_helper);
					return processes;
				}
			}
		}
		while (Process32Next(snapshot_helper, &pt));
	}
	CloseHandle(snapshot_helper);
	return processes;
}

int main() {
	const std::vector<DWORD> processes = FindProcessId(L"steam.exe");
	if (!processes.empty()) {
		const DWORD pid = processes.front();
		const auto network_connection_tester = new NetworkConnectionTester(pid, {80, 443});
		network_connection_tester->Start();
		cout << "Watcher started for PID " << pid << std::endl;
	}
	else {
		cout << "Process with specified name not found." << std::endl;
	}
	system("pause");
	return 0;
}