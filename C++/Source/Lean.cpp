#include "../Headers/Lean.h"

#include <algorithm>
#include <unordered_set>
#include <ctime>

Lean::Lean(uint32_t d, uint32_t m, uint32_t timeout) {
    this->d = d;
    this->m = m;
    this->hashseeds = new uint32_t[d];
    this->directseeds = new uint32_t[d];
    this->timeout = timeout;
    srand((uint32_t) time(NULL));
    std::unordered_set<uint32_t> mset;
    while (mset.size() != 2 * d) {
        mset.insert(rand() % 10000);
    }
    int temp_i = 0;
    for (auto iter = mset.begin(); iter != mset.end(); iter ++, temp_i) {
        if (temp_i < d) {
            hashseeds[temp_i] = *iter;
        } else {
            directseeds[temp_i - d] = *iter;
        }
    }
    this->rtt_cnt = new int *[d];
    this->mtime = new int *[d];
    for (int i = 0; i < d; ++i) {
        rtt_cnt[i] = new int[m]{0};
        mtime[i] = new int[m]{0};
    }
}

void Lean::insert(Key key, uint32_t seq, uint32_t ack, uint32_t _time) {
    char hash_input_str[5];
    uint32_t hash_value, hash_index, opt_value, opt;
    uint32_t xor_key = key.cal_xor_key();
    memcpy(hash_input_str, &xor_key, 5);
    for (int i = 0; i < d; ++i) {
        MurmurHash3_x86_32(hash_input_str, 4, hashseeds[i], &hash_value);
        hash_index = hash_value % m;
        MurmurHash3_x86_32(hash_input_str, 4, directseeds[i], &opt_value);
        opt = opt_value % 2;
        int inc = 0;
        if (mtime[i][hash_index] == 0) {
            if (key.src_ip < key.dst_ip) {
                mtime[i][hash_index] = -1 * _time;
            } else {
                mtime[i][hash_index] = _time;
            }
        } else {
            if (key.src_ip < key.dst_ip) {
                if (mtime[i][hash_index] > 0) {
                    inc = _time - mtime[i][hash_index];
                }
                mtime[i][hash_index] = - _time;
            } else {
                if (mtime[i][hash_index] < 0) {
                    inc = _time + mtime[i][hash_index];
                }
                mtime[i][hash_index] = _time;
            }
        }
        if (inc <= 0) {
            continue;
        } else {
            if (inc > timeout) {
                continue;
            }
            if (opt == 0) {
                rtt_cnt[i][hash_index] = rtt_cnt[i][hash_index] - inc;
            } else {
                rtt_cnt[i][hash_index] = rtt_cnt[i][hash_index] + inc;
            }
        }
    }
}

int Lean::estimate(Key key) {
    std::vector<uint32_t> est_lst;
    uint32_t hash_index, hash_value, opt;
    uint32_t xor_key = key.cal_xor_key();
    char hash_input_str[5];
    memcpy(hash_input_str, &xor_key, 5);
    for (int i = 0; i < d; ++i) {
        MurmurHash3_x86_32(hash_input_str, 4, hashseeds[i], &hash_value);
        hash_index = hash_value % m;
        MurmurHash3_x86_32(hash_input_str, 4, directseeds[i], &hash_value);
        opt = hash_value % 2;
        if (opt == 0) {
            est_lst.push_back(rtt_cnt[i][hash_index] * -1);
        } else {
            est_lst.push_back(rtt_cnt[i][hash_index]);
        }
    }
    std::sort(est_lst.begin(), est_lst.end());
    if (est_lst[d / 2] < 0) {
        return 1;
    } else {
        return est_lst[d / 2];
    }
}

std::vector<const char*> Lean::detect(uint32_t thr) {
    std::vector<const char*> nullset;
    return nullset;
}
