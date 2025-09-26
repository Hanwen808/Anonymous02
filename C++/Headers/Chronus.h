#ifndef CHRONUS_H
#define CHRONUS_H
#include <vector>

#include "Sketch.h"
#include "MurmurHash3.h"

class Chronus : public Sketch {
public:
    uint32_t m1 ,m2;
    uint32_t d;
    uint32_t *gen_seqs;
    uint32_t *gen_time;
    uint32_t *gen_FPs;

    uint32_t *rtt_cnt;
    Key *IDs;

    Key *gen_IDs;

    uint32_t timeout;

    uint32_t hash_seed;

    uint32_t fp_seed;

    Chronus(uint32_t, uint32_t, uint32_t, uint32_t);
    ~Chronus() {
        delete[] gen_seqs;
        delete[] gen_time;
        delete[] gen_FPs;
        delete[] rtt_cnt;
        delete[] IDs;
        delete[] gen_IDs;
    }
    void insert(Key key, uint32_t seq, uint32_t ack, uint32_t _time);
    int estimate(Key key);
    //std::unordered_set<Key, HashFunc, Cmp> detect(uint32_t thr);
    std::vector<const char *> detect(uint32_t thr);
};

#endif //CHRONUS_H
