#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string.h>
#include <unordered_map>
#include <vector>

#include "Headers/Sketch.h"
#include "Headers/Chronus.h"
#include "Headers/Lean.h"
#include "Headers/Params.h"
//#include "Headers/Lean.h"
#define KEY_SIZE 16

using namespace std;

long long get_timestamp_us(const std::string& mstr) {
    size_t dot_pos = mstr.find('.');
    std::string int_part, frac_part;
    if (dot_pos == std::string::npos) {
        int_part = mstr;
        frac_part = "000000";
    } else {
        int_part = mstr.substr(0, dot_pos);
        frac_part = mstr.substr(dot_pos + 1);
        if (frac_part.length() < 6) {
            frac_part.append(6 - frac_part.length(), '0');
        }
    }

    auto is_valid_number = [](const std::string& s) -> bool {
        if (s.empty()) return false;
        for (size_t i = 0; i < s.length(); ++i) {
            if (!std::isdigit(static_cast<unsigned char>(s[i]))) {
                return false;
            }
        }
        return true;
    };

    if (!int_part.empty() && !is_valid_number(int_part)) {
        throw std::invalid_argument("Integer part contains non-digit characters");
    }
    if (!is_valid_number(frac_part)) {
        throw std::invalid_argument("Fractional part contains non-digit characters");
    }

    long long seconds = int_part.empty() ? 0 : std::stoll(int_part);

    long long microseconds = std::stoll(frac_part);

    return seconds * 1000000LL + microseconds;
}

uint32_t convertIPv4ToUint32(char* ipAddress) {
    uint32_t result = 0;
    int octet = 0;
    char ipCopy[KEY_SIZE];
    strncpy(ipCopy, ipAddress, sizeof(ipCopy) - 1);
    ipCopy[sizeof(ipCopy) - 1] = '\0';
    char* token = strtok(ipCopy, ".");
    while (token != nullptr) {
        octet = std::stoi(token);
        result = (result << 8) + octet;
        token = strtok(nullptr, ".");
    }
    return result;
}

// Updating Sketch and testing the processing throughput.
double processPackets(Sketch* skt, vector<pair<Key, pair<uint32_t, pair<uint32_t, uint64_t>>>>& dataset, uint64_t start_time) {
    clock_t start = clock(); // The start time of processing packet stream
    for (int i = 0; i < dataset.size(); i++) {
        skt->insert(dataset[i].first, dataset[i].second.first, dataset[i].second.second.first, dataset[i].second.second.second - start_time);
    }
    clock_t current = clock(); // The end time of processing packet stream
    cout << dataset.size() << " lines: have used " << ((double)current - start) / CLOCKS_PER_SEC << " seconds" << endl;
    double throughput = (dataset.size() / 1000000.0) / (((double)current - start) / CLOCKS_PER_SEC);
    cout << "throughput: " << throughput << "Mpps" << endl;
    return throughput;
}

void getDataSet(string dataDir, vector<pair<Key, pair<uint32_t, pair<uint32_t, uint64_t>>>>& dataset,
                std::unordered_map<Key, uint32_t, HashFunc, Cmp>& realFlowInfo, uint32_t timeout, char* dataFileName)
{
    uint32_t src_ip_int, dst_ip_int, seqno_int, ackno_int;
    uint16_t sport_int, dport_int;
    uint64_t mtime;
    string line, source, destination, sport, dport, ackno, seqno, _time, tag;
    clock_t start = clock();
        //string oneDataFilePath = "../mawi_25_1.txt"; // Organize a complete filename.
        cout << dataFileName << endl;
        fstream fin(dataFileName);
        std::unordered_map<Key, uint32_t, HashFunc, Cmp> flow_ack_dict;
        std::unordered_map<Key, uint64_t, HashFunc, Cmp> flow_time_dict;
        float real_rto = 0, real_rtts = 0, real_rttd = 0;
        bool is_first = true;
        while (fin.is_open() && fin.peek() != EOF) {
            getline(fin, line); // each line of dataset is consist of three fields: source address, destination address and destination port
            stringstream ss(line.c_str());
            // Build a flow element
            // if (is_first) {
            //     is_first = false;
            //     continue;
            // }
            ss >> source >> destination >> sport >> dport >> seqno >> ackno >> tag >> _time;
            //std::cout << source << " " << destination << std::endl;
            src_ip_int = convertIPv4ToUint32((char*) source.c_str());
            dst_ip_int = convertIPv4ToUint32((char*) destination.c_str());
            sport_int = static_cast<uint16_t>(std::atoi((char *) sport.c_str()));
            dport_int = static_cast<uint16_t>(std::atoi((char *) dport.c_str()));
            seqno_int = static_cast<uint32_t>(std::atoi((char *) seqno.c_str()));
            ackno_int = static_cast<uint32_t>(std::atoi((char *) ackno.c_str()));
            mtime = static_cast<uint64_t>(get_timestamp_us(_time));
            Key key = Key(src_ip_int, dst_ip_int, sport_int, dport_int);
            dataset.push_back(make_pair(key, make_pair(seqno_int, make_pair(ackno_int, mtime))));
            if (flow_ack_dict.find(key) == flow_ack_dict.end()) {
                flow_ack_dict[key] = ackno_int;
                flow_time_dict[key] = mtime;
            } else {
                if (flow_ack_dict[key] != seqno_int) {
                    flow_ack_dict[key] = ackno_int;
                    flow_time_dict[key] = mtime;
                } else {
                    int rtt_inc = mtime - flow_time_dict[key];
                    if (rtt_inc <= timeout) {
                        if (rtt_inc > 0) {
                            realFlowInfo[key] += rtt_inc;
                        }
                    }
                    flow_ack_dict[key] = ackno_int;
                    flow_time_dict[key] = mtime;
                }
            }
            if (dataset.size() % 5000000 == 0) {
                clock_t current = clock();
                cout << "have added " << dataset.size() << " packets, have used " << ((double)current - start) / CLOCKS_PER_SEC << " seconds." << endl;
            }
        }
        cout << "real RTO is " << real_rto << std::endl;
        if (!fin.is_open()) {
            cout << "dataset file " << dataFileName << "closed unexpectedlly"<<endl;
            exit(-1);
        }else
            fin.close();

    clock_t current = clock();
    cout << "have added " << dataset.size() << " packets, have used " << ((double)current - start) / CLOCKS_PER_SEC << " seconds" << endl;
}

void saveResults(string outputFilePath, Sketch* skt, unordered_map<Key, uint32_t, HashFunc, Cmp>& realFlowInfo, uint32_t T, string name) {
    ofstream fout;
    //std::unordered_set<Key, HashFunc, Cmp> pred_congestion;
    std::vector<const char*> pred_congestion;
    if (strcmp(name.c_str(), "chronus") == 0) {
        pred_congestion = skt->detect(T);
    }
    //std::unordered_set<Key, HashFunc, Cmp> real_congestion;
    std::vector<const char*> real_congestion;
    std::vector<double> re_vector;
    auto iter = realFlowInfo.begin();
    fout.open(outputFilePath, ios::out);
    while (iter != realFlowInfo.end()) {
        int realrtt = iter->second;
        int estimated_rtt = skt->estimate(iter->first);
        if (strcmp(name.c_str(), "lean") == 0) {
            if (estimated_rtt >= T)
                pred_congestion.push_back(iter->first.full_key);
        }
        if (realrtt >= 0) {
            fout << realrtt << " " << estimated_rtt << "\n";
            //fout << realrtt << "\n";
            real_congestion.push_back(iter->first.full_key);
            re_vector.push_back((1.0 * abs(estimated_rtt - realrtt)) / (1.0 * realrtt));
        }
        iter++;
    }
    // std::unordered_set<Key, HashFunc, Cmp> TP_set;
    // std::unordered_set<Key, HashFunc, Cmp> FP_set;
    // std::unordered_set<Key, HashFunc, Cmp> FN_set;
    // for (auto iter = real_congestion.begin(); iter != real_congestion.end(); iter ++) {
    //     if (pred_congestion.find(*iter) != pred_congestion.end())
    //         TP_set.insert(*iter);
    //     else
    //         FN_set.insert(*iter);
    // }
    // for (auto iter = pred_congestion.begin(); iter != pred_congestion.end(); iter ++) {
    //     if (real_congestion.find(*iter) == real_congestion.end())
    //         FP_set.insert(*iter);
    // }
    // double precision = (1.0 * TP_set.size()) / (1.0 * TP_set.size() + 1.0 * FP_set.size());
    // double recall = ((1.0 * TP_set.size()) / (1.0 * TP_set.size() + 1.0 * FN_set.size()));
    // double F1_score = (2 * precision * recall) / (precision + recall);
    //
    // double _sum = 0.0, _cnt = 0.0;
    // for (auto iter = re_vector.begin(); iter != re_vector.end(); iter ++) {
    //     _sum += *iter;
    //     _cnt ++;
    // }
    //
    // _sum = _sum / _cnt;

    //fout << "Precision: " << precision << ", recall: " << recall << ", F1 score: " << F1_score << ", ARE: " << _sum << "\n";

    // if (!fout.is_open())
    //     cout << outputFilePath << " closed unexpectedlly";
    // else
    //     fout.close();
    // cout << "";
}

double run(uint32_t mem0, uint32_t time0, uint32_t detect0, char *filename, uint64_t start_time) {
    uint32_t timeout = time0;
    uint32_t detection_ratio = detect0;
    //prepare the dataset
    cout << "prepare the dataset" << endl;
    string dataDir = R"(../data/)";
    vector<pair<Key, pair<uint32_t, pair<uint32_t, uint64_t>>>> dataset;
    unordered_map<Key, uint32_t, HashFunc, Cmp> realFlowInfo;
    getDataSet(dataDir, dataset, realFlowInfo, timeout, filename);
    cout << endl;
    string name;
    uint32_t mem = mem0 * 1024;  //KB
    // vector<uint32_t> mem_vt = {64, 128, 256, 512, 1024};
    //  std::unordered_map<uint32_t, vector<uint32_t>> T_vt;
    //  T_vt[2023] = {};
    //  T_vt[2024] = {};
    //  T_vt[2025] = {};
    // name = "chronus";
    // float ratio = 0.7;
    // uint32_t m1 = static_cast<uint32_t>((1.0 * mem * ratio) / 10.0);
    // uint32_t m2 = static_cast<uint32_t>((1.0 * mem * (1 - ratio)) / 16.0);
    // std::cout << m1 << " " << m2 << std::endl;
    // Chronus *skt = new Chronus(m1, m2, 3, timeout);

    name = "lean";
    uint32_t d = 3;
    uint32_t m = (mem / d / 8);
    Lean *skt = new Lean(d, m, timeout);

    cout << endl;
    cout << "Start processing..." << endl;
    double throughput = processPackets(skt, dataset, start_time);
    //save the result in files
    cout << endl;
    cout << "save the result in txt ..." << endl;
    string outputFilePath = "./record/chronus.txt";
    saveResults(outputFilePath, skt, realFlowInfo, detection_ratio, name);
    return throughput;
}

int main() {
    //run(100, 100, 100, "../mawi_25_7.txt", 1735707960158999);
    string srcip = "fd00:7b59:e4db:6f99:94c9:7c28:3001:fd3e";
    string dstip = "2001:379c:b99b:1ff8:9f3:7dd:c3fe:649a";
    convertIPv4ToUint32((char *) dstip.c_str());
    // std::unordered_map<uint32_t, std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint32_t>>> timeoutMap;
    // std::unordered_map<uint32_t, std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint32_t>>> detectMap;
    // std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint64_t>> startTimeMap;
    // initTimeout(timeoutMap, detectMap, startTimeMap);
    // vector<uint32_t> time_vt = {2010, 2024, 2025};
    // vector<uint32_t> mem_vt = {64, 128, 256, 512, 1024};
    // vector<uint32_t> quantiles_vt = {80, 90, 99};
    // std::unordered_map<uint32_t, uint32_t> dat_num_vt;
    // dat_num_vt[2010] = 1;
    // dat_num_vt[2024] = 15;
    // dat_num_vt[2025] = 15;
    // for (auto time_iter = time_vt.begin(); time_iter != time_vt.end(); time_iter ++) {
    //     for (auto qua_iter = quantiles_vt.begin(); qua_iter != quantiles_vt.end(); qua_iter ++) {
    //         ofstream fout;
    //         char outputfilename[32];
    //         if (*time_iter == 2024) {
    //             sprintf(outputfilename, "../exp2/MAWI24_%d.txt", *qua_iter);
    //         } else {
    //             if (*time_iter == 2025) {
    //                 sprintf(outputfilename, "../exp2/MAWI25_%d.txt", *qua_iter);
    //             } else {
    //                 sprintf(outputfilename, "../exp2/IMC10_%d.txt", *qua_iter);
    //             }
    //         }
    //         fout.open(outputfilename, ios::out);
    //         for (auto mem_iter = mem_vt.begin(); mem_iter != mem_vt.end(); mem_iter ++) {
    //             uint32_t num = dat_num_vt[*time_iter];
    //             fout << "mem " << *mem_iter << "\n";
    //             for (int i = 1; i <= num; ++i) {
    //                 uint64_t start_time = startTimeMap[*time_iter][i];
    //                 char filename[32];
    //                 if (*time_iter == 2010) {
    //                     memcpy(filename, "../IMC10/IMC10.txt", 32);
    //                 } else {
    //                     if (*time_iter == 2024) {
    //                         sprintf(filename, "../MAWI24/mawi_24_%d.txt", i);
    //                     } else {
    //                         sprintf(filename, "../MAWI25/mawi_25_%d.txt", i);
    //                     }
    //                 }
    //                 double tmp = run(*mem_iter, timeoutMap[*time_iter][i][*qua_iter], detectMap[*time_iter][i][*qua_iter], filename, start_time);
    //                 fout << "[" << i << "]" << tmp << " ";
    //             }
    //             fout << "\n";
    //         }
    //         fout.close();
    //     }
    // }
    return 0;
}
