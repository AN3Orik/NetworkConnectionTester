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
        time_t timestamp;
        TCP_ESTATS_DATA_ROD_v0 data;
        TCP_ESTATS_PATH_ROD_v0 path;

        NetworkProcessStatisticRecord(TCP_ESTATS_DATA_ROD_v0 data, TCP_ESTATS_PATH_ROD_v0 path) {
            this->timestamp = time(nullptr);
            this->data = data;
            this->path = path;
        }

        double CalculateLost(const NetworkProcessStatisticRecord start) {
            if (timestamp <= start.timestamp) {
                return 0;
            }

            if (data.DataBytesOut <= start.data.DataBytesOut) {
                return 0;
            }

            if (path.BytesRetrans <= start.path.BytesRetrans) {
                return 0;
            }

            const ULONG64 send_delta = data.DataBytesOut - start.data.DataBytesOut;
            const ULONG64 retrans_delta = path.BytesRetrans - start.path.BytesRetrans;

            return max(0, min((retrans_delta * 100.0 / send_delta), 100));
        }
    };

    struct NetworkProcess {
        MIB_TCPROW_OWNER_PID tcp_row;
        u_short remote_port;
        time_t last_updated;
        u_int ping;
        u_int packet_loss_percent;

    private:
        std::vector<NetworkProcessStatisticRecord> network_statistic_records_;

    public:
        void Update(const TCP_ESTATS_DATA_ROD_v0& data, const TCP_ESTATS_PATH_ROD_v0& path)
        {
            last_updated = time(nullptr);
            
            // Cleanup outdated statistic records
            while (!network_statistic_records_.empty() && last_updated - network_statistic_records_.begin()->timestamp > 20
                || network_statistic_records_.size() > 5) {
                network_statistic_records_.erase(network_statistic_records_.begin());
            }

            auto* statistic_record = new NetworkProcessStatisticRecord(data, path);

            // Calculate packet loss against last 5 records and current record
            double max_lost = 0;
            for (auto iterator = network_statistic_records_.begin();
                 iterator != network_statistic_records_.end(); ++iterator) {
                max_lost = max(statistic_record->CalculateLost(*iterator), max_lost);
            }

            network_statistic_records_.push_back(*statistic_record);

            packet_loss_percent = static_cast<u_int>(max_lost);

            // Record ping
            if (path.SampleRtt < UINT_MAX) {
                // Sometimes metric return very big values
                ping = path.SampleRtt;
            }

            #ifdef _DEBUG
            std::cout << "[PID " << tcp_row.dwOwningPid << "] " << "Port: " << remote_port << " Ping: " << ping << "ms Packet loss: " << packet_loss_percent << "%" << std::endl;
            #endif
        }
    };
    
    DWORD process_id_;
    std::vector<int> ports_;
    std::thread statistic_thread_;
    std::atomic<bool> statistic_thread_running_ = false;
    
public:
    std::map<u_short, NetworkProcess*> network_processes;
    
    ~NetworkConnectionTester() {
        Stop();
    }

    NetworkConnectionTester(const DWORD process_id, const std::vector<int>& ports) {
        process_id_ = process_id;
        ports_ = ports;
    }

    void Start() {
        if (!statistic_thread_running_) {
            statistic_thread_running_ = true;
            statistic_thread_ = std::thread(&NetworkConnectionTester::CollectStatisticThread, this);
        }
    }

    void Stop() {
        if (statistic_thread_running_) {
            statistic_thread_running_ = false;
            if (statistic_thread_.joinable()) {
                statistic_thread_.join();
            }
            for (const auto network_pair : network_processes) {
                delete network_pair.second;
            }
            network_processes.clear();
        }
    }

    void CollectStatisticThread() {
        while (statistic_thread_running_ == true) {
            CollectProcessTcpConnections();
            for (auto iterator = network_processes.begin(), next_it = iterator; iterator != network_processes.end(); iterator = next_it) {
                ++next_it;
                
                NetworkProcess* network_process = iterator->second;

                if (network_process->last_updated > 0 && time(nullptr) - network_process->last_updated > 5) {
                    // Remove connections without activity (closed connections)
                    network_processes.erase(iterator);
                    delete network_process;
                    continue;
                }

                TCP_ESTATS_DATA_ROD_v0 data_rod;
                const DWORD data_result = GetPerTcpConnectionEStats(
                    reinterpret_cast<PMIB_TCPROW>(&network_process->tcp_row),
                    TcpConnectionEstatsData,
                    nullptr, 0, 0,
                    nullptr, 0, 0,
                    reinterpret_cast<PUCHAR>(&data_rod),
                    0,
                    sizeof(data_rod));
                
                TCP_ESTATS_PATH_ROD_v0 path_rod;
                const DWORD path_result = GetPerTcpConnectionEStats(
                    reinterpret_cast<PMIB_TCPROW>(&network_process->tcp_row),
                    TcpConnectionEstatsPath,
                  nullptr, 0, 0,
                  nullptr, 0, 0,
                    reinterpret_cast<PUCHAR>(&path_rod),
                    0,
                    sizeof(path_rod));

                if (data_result == NO_ERROR && path_result == NO_ERROR) {
                    network_process->Update(data_rod, path_rod);
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
        if (GetExtendedTcpTable(nullptr, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER)
        {
            return;
        }

        auto tcp_table = static_cast<MIB_TCPTABLE_OWNER_PID*>(malloc(size));
        if (tcp_table == nullptr)
        {
            return;
        }

        if (GetExtendedTcpTable(tcp_table, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        {
            free(tcp_table);
            tcp_table = nullptr;
            return;
        }

        for (DWORD dw_loop = 0; dw_loop < tcp_table->dwNumEntries; dw_loop++) {
            MIB_TCPROW_OWNER_PID table_row = tcp_table->table[dw_loop];
            if (table_row.dwState != MIB_TCP_STATE_ESTAB)
            {
                continue;
            }

            if (table_row.dwOwningPid == process_id_) {
                u_short remote_port = ntohs(static_cast<u_short>(table_row.dwRemotePort));
                if (std::find(ports_.begin(), ports_.end(), remote_port) != ports_.end()) {
                    if (!network_processes.count(remote_port)) {
                        // Enable TCP statistics and put to map
                        TCP_ESTATS_DATA_RW_v0 data_rw;
                        data_rw.EnableCollection = 1;
                        const DWORD set_data_result = SetPerTcpConnectionEStats(
                            reinterpret_cast<PMIB_TCPROW>(&table_row),
                            TcpConnectionEstatsData,
                            reinterpret_cast<PUCHAR>(&data_rw),
                            0,
                            sizeof(data_rw),
                            0);

                        TCP_ESTATS_PATH_RW_v0 path_rw;
                        path_rw.EnableCollection = 1;
                        const DWORD set_path_result = SetPerTcpConnectionEStats(
                            reinterpret_cast<PMIB_TCPROW>(&table_row),
                            TcpConnectionEstatsPath,
                            reinterpret_cast<PUCHAR>(&path_rw),
                            0,
                            sizeof(path_rw),
                            0);

                        if (set_data_result == NO_ERROR && set_path_result == NO_ERROR)  {
                            auto network_process = new NetworkProcess();
                            network_process->remote_port = remote_port;
                            network_process->tcp_row = table_row;
                            network_processes.insert({ remote_port, network_process });
                        }
                   }
                }
            }
        }
        
        if (tcp_table != nullptr)
        {
            free(tcp_table);
            tcp_table = nullptr;
        }
    }
};