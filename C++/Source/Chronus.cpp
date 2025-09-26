#include "../Headers/Chronus.h"

#include <iostream>
#include <string.h>

Chronus::Chronus(uint32_t m1, uint32_t m2, uint32_t d, uint32_t timeout) {
    this->m1 = m1;
    this->m2 = m2;
    this->d = d;
    this->timeout = timeout;
    srand((uint32_t)time(NULL));
    hash_seed = rand() % 10000;
    fp_seed = rand() % 10000;
    gen_seqs = new uint32_t[m1];
    gen_time = new uint32_t[m1];
    gen_FPs = new uint32_t[m1];
    rtt_cnt = new uint32_t[m2];
    IDs = new Key[m2];
    gen_IDs = new Key[m1];
    memset(gen_seqs, 0, m1 * sizeof(uint32_t));
    memset(gen_time, 0, m1 * sizeof(uint32_t));
    memset(gen_FPs, 0, m1 * sizeof(uint32_t));
    memset(rtt_cnt, 0, m2 * sizeof(uint32_t));
}

void Chronus::insert(Key key, uint32_t seq, uint32_t ack, uint32_t _time) {
    uint32_t xor_key = key.cal_xor_key();
    char hash_input_str[5];
    memcpy(hash_input_str, &xor_key, 5);
    uint32_t hash_index, hash_value, fp_value;
    MurmurHash3_x86_32(hash_input_str, 4, hash_seed, &hash_value);
    MurmurHash3_x86_32(hash_input_str, 4, fp_seed, &fp_value);
    hash_index = hash_value % m1;
    key.fp = fp_value % ((1<<16)-1);
    int rtt_inc = 0;
    if (key.fp == gen_FPs[hash_index]) { //key.fp == gen_FPs[hash_index]
        if (seq == gen_seqs[hash_index]) {
            rtt_inc = _time - gen_time[hash_index];
            if (rtt_inc > this->timeout || rtt_inc < 0) {
                rtt_inc = 0;
            }
        }
        gen_seqs[hash_index] = ack;
        gen_time[hash_index] = _time;
    } else {
        if (gen_FPs[hash_index] == 0) { //gen_FPs[hash_index] == 0 //gen_IDs[hash_index].src_ip == 0
            gen_FPs[hash_index] = key.fp;
            //gen_IDs[hash_index].set_value(key);
            gen_seqs[hash_index] = ack;
            gen_time[hash_index] = _time;
        } else {
            if (_time - gen_time[hash_index] > this->timeout) {
                gen_FPs[hash_index] = key.fp;
                //gen_IDs[hash_index].set_value(key);
                gen_seqs[hash_index] = ack;
                gen_time[hash_index] = _time;
            }
        }
    }
    if (rtt_inc != 0) {
        int empty = -1, min_idx = -1, min_val = -1;
        for (int i = 0; i < d; ++i) {
            MurmurHash3_x86_32(hash_input_str, 4, hash_seed + i, &hash_value);
            hash_index = hash_value % m2;
            if (IDs[hash_index].src_ip == 0) {
                empty = hash_index;
            } else {
                if (IDs[hash_index].cmp_key(key) == 1) {
                    /*std::cout << IDs[hash_index].src_ip << " " << IDs[hash_index].dst_ip << " " << IDs[hash_index].sport << " " << IDs[hash_index].dport << std::endl;
                    std::cout << rev_key.src_ip << " " << rev_key.dst_ip << " " << rev_key.sport << " " << rev_key.dport << std::endl;
                    std::cout << "RTT is " << rtt_cnt[hash_index] << std::endl;*/
                    rtt_cnt[hash_index] += rtt_inc;
                    return;
                } else {
                    if (min_idx == -1) {
                        min_idx = hash_index;
                        min_val = rtt_cnt[hash_index];
                    } else {
                        if (rtt_cnt[hash_index] < min_val) {
                            min_idx = hash_index;
                            min_val = rtt_cnt[hash_index];
                        }
                    }
                }
            }
        }
        if (empty != -1) {
            IDs[empty].set_value(key);
            rtt_cnt[empty] = rtt_inc;
        } else {
            rtt_cnt[min_idx] += rtt_inc;  //unbiased
            if (rand() % 1000 <= (1000.0 * rtt_inc) / (1.0 * rtt_inc + 1.0 * min_val)) {
                IDs[min_idx].set_value(key);
            }
        }
    }
}

int Chronus::estimate(Key key) {
    uint32_t hash_index, hash_value;
    uint32_t xor_key = key.cal_xor_key();
    char hash_input_str[5];
    memcpy(hash_input_str, &xor_key, 5);
    for (int i = 0; i < d; ++i) {
        MurmurHash3_x86_32(hash_input_str, 4, hash_seed + i, &hash_value);
        hash_index = hash_value % m2;
        if (IDs[hash_index].cmp_key(key) == 1) {
            return static_cast<int>(rtt_cnt[hash_index]);
        }
    }
    return 1;
}

std::vector<const char *> Chronus::detect(uint32_t thr) {
    std::vector<const char*> res;
    for (int i = 0; i < m2; ++i) {
        if (rtt_cnt[i] >= thr) {
            res.push_back(IDs[i].full_key);
        }
    }
    return res;
}


// std::unordered_set<Key, HashFunc, Cmp> Chronus::detect(uint32_t thr) {
//     std::unordered_set<Key, HashFunc, Cmp> res;
//     for (int i = 0; i < m2; ++i) {
//         if (rtt_cnt[i] >= thr) {
//             res.insert(IDs[i]);
//         }
//     }
//     return res;
// }