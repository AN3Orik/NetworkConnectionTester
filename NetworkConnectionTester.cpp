#pragma once

#include <atomic>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iostream>
#include <map>
#include <thread>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

class NetworkConnectionTester {
    struct NetworkProcessStatisticRecord {
        long Timestamp;
        TCP_ESTATS_DATA_ROD_v0 Data;
        TCP_ESTATS_PATH_ROD_v0 Path;

    	NetworkProcessStatisticRecord(TCP_ESTATS_DATA_ROD_v0 data, TCP_ESTATS_PATH_ROD_v0 path) {
            Timestamp = time(nullptr);
            Data = data;
            Path = path;
    	}

        double CalculateLost(NetworkProcessStatisticRecord start) {
            if (Timestamp <= start.Timestamp) {
                return 0;
            }

            if (Data.DataBytesOut <= start.Data.DataBytesOut) {
                return 0;
            }

            if (Path.BytesRetrans <= start.Path.BytesRetrans) {
                return 0;
            }
    		
            long sendDelta = Data.DataBytesOut - start.Data.DataBytesOut;
            long retransDelta = Path.BytesRetrans - start.Path.BytesRetrans;

            return max(0, min((retransDelta * 100.0 / sendDelta), 100));
        }
    };
	
    struct NetworkProcess {
        MIB_TCPROW_OWNER_PID TcpRow;
        u_short RemotePort;
        long LastUpdated;
        u_int Ping;
        u_int PacketLossPercent;
    	
    private:
        std::vector<NetworkProcessStatisticRecord> _networkStatisticRecords;
    	
    public:
        void Update(TCP_ESTATS_DATA_ROD_v0 data, TCP_ESTATS_PATH_ROD_v0 path) {
            LastUpdated = time(nullptr);
        	
        	// Cleanup outdated statistic records
            while (!_networkStatisticRecords.empty() && LastUpdated - _networkStatisticRecords.begin()->Timestamp > 20
                || _networkStatisticRecords.size() > 5) {
                _networkStatisticRecords.erase(_networkStatisticRecords.begin());
            }

            NetworkProcessStatisticRecord* statisticRecord = new NetworkProcessStatisticRecord(data, path);

            // Calculate packet loss against last 5 records and current record
            double maxLost = 0;
            for (std::vector<NetworkProcessStatisticRecord>::iterator iterator = _networkStatisticRecords.begin();
                 iterator != _networkStatisticRecords.end(); ++iterator) {
                maxLost = max(statisticRecord->CalculateLost(*iterator), maxLost);
            }
            _networkStatisticRecords.push_back(*statisticRecord);

            PacketLossPercent = maxLost;

            // Record ping
            if (path.SampleRtt < UINT_MAX) {
                // Sometimes metric return very big values
                Ping = path.SampleRtt;
            }

#ifdef _DEBUG
            std::cout << "[PID " << TcpRow.dwOwningPid << "] Ping: " << Ping << "ms Packet loss: " << PacketLossPercent << "%" << std::endl;
#endif
        }
    };
	
private:
    DWORD _processId;
    std::vector<int> _ports;
    std::thread _statisticThread;
    std::atomic<bool> _statisticThreadRunning = false;
	
public:
    std::map<u_short, NetworkProcess*> NetworkProcesses;
	
    ~NetworkConnectionTester() {
        Stop();
    }

	NetworkConnectionTester(DWORD processId, std::vector<int> ports) {
        _processId = processId;
        _ports = ports;
    }

    void Start() {
        if (!_statisticThreadRunning) {
            _statisticThreadRunning = true;
            _statisticThread = std::thread(&NetworkConnectionTester::CollectStatisticThread, this);
        }
    }

    void Stop() {
        if (_statisticThreadRunning) {
            _statisticThreadRunning = false;
            if (_statisticThread.joinable()) {
                _statisticThread.join();
            }
            NetworkProcesses.clear();
        }
    }

    void CollectStatisticThread() {
        while (_statisticThreadRunning == true) {
            CollectProcessTcpConnections();
            for (auto iterator = NetworkProcesses.begin(), next_it = iterator; iterator != NetworkProcesses.end(); iterator = next_it) {
                ++next_it;
            	
                u_short port = iterator->first;
                NetworkProcess* networkProcess = iterator->second;

            	if (networkProcess->LastUpdated > 0 && time(nullptr) - networkProcess->LastUpdated > 5) {
            		// Remove connections without activity (closed connections)
                    NetworkProcesses.erase(iterator);
            		continue;
            	}

                TCP_ESTATS_DATA_ROD_v0 dataRod;
                DWORD dataResult = GetPerTcpConnectionEStats(
                    reinterpret_cast<PMIB_TCPROW>(&networkProcess->TcpRow),
                    TcpConnectionEstatsData,
                    NULL, 0, 0,
                    NULL, 0, 0,
                    (PUCHAR)&dataRod,
                    0,
                    sizeof(dataRod));
            	
                TCP_ESTATS_PATH_ROD_v0 pathRod;
                DWORD pathResult = GetPerTcpConnectionEStats(
                    reinterpret_cast<PMIB_TCPROW>(&networkProcess->TcpRow),
                    TcpConnectionEstatsPath,
                    NULL, 0, 0,
                    NULL, 0, 0,
                    (PUCHAR)&pathRod,
                    0,
                    sizeof(pathRod));

            	if (dataResult == NO_ERROR && pathResult == NO_ERROR) {
                    networkProcess->Update(dataRod, pathRod);
            	}
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }

	/***
	 * Collect all TCP connections related to specified process & ports
	 * and enable TCP extended metric for found connections
	 */
    void CollectProcessTcpConnections() {
        DWORD size;
        GetExtendedTcpTable(NULL, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        MIB_TCPTABLE_OWNER_PID* pTCPInfo = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
        GetExtendedTcpTable(pTCPInfo, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<MIB_TCPROW_OWNER_PID> resultTable;
        for (DWORD dwLoop = 0; dwLoop < pTCPInfo->dwNumEntries; dwLoop++) {
            MIB_TCPROW_OWNER_PID tableRow = pTCPInfo->table[dwLoop];
        	if (tableRow.dwOwningPid == _processId) {
                u_short remotePort = ntohs(tableRow.dwRemotePort);
        		if (std::find(_ports.begin(), _ports.end(), remotePort) != _ports.end()) {
        			if (!NetworkProcesses.count(remotePort)) {
        				// Enable TCP statistics and put to map
                        TCP_ESTATS_DATA_RW_v0 dataRw;
                        dataRw.EnableCollection = 1;
                        DWORD setDataResult = SetPerTcpConnectionEStats(
                            reinterpret_cast<PMIB_TCPROW>(&tableRow),
                            TcpConnectionEstatsData,
                            (PUCHAR)&dataRw,
                            0,
                            sizeof(dataRw),
                            0);

                        TCP_ESTATS_PATH_RW_v0 pathRw;
                        pathRw.EnableCollection = 1;
                        DWORD setPathResult = SetPerTcpConnectionEStats(
                            reinterpret_cast<PMIB_TCPROW>(&tableRow),
                            TcpConnectionEstatsPath,
                            (PUCHAR)&pathRw,
                            0,
                            sizeof(pathRw),
                            0);

                        if (setDataResult == NO_ERROR && setPathResult == NO_ERROR)  {
                            NetworkProcess* networkProcess = new NetworkProcess();
                            networkProcess->RemotePort = remotePort;
                            networkProcess->TcpRow = tableRow;
                            NetworkProcesses.insert({ remotePort, networkProcess });
                        }
        			}
        		}
        	}
        }
    }
};