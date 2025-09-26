#ifndef SKETCH_H
#define SKETCH_H
#include "Key.h"
#include <cstdint>

#include "MurmurHash3.h"

struct Cmp {
    bool operator()(Key a, Key b) const {
        return a.cmp_key(b) == 1;
    }
};

struct HashFunc {
    unsigned int operator()(Key a) const {
        unsigned int hashValue = 0;
        uint32_t xor_key = a.cal_xor_key();
        char hash_inpur_str[5];
        memcpy(hash_inpur_str, &xor_key, 5);
        MurmurHash3_x86_32(hash_inpur_str, 4, 0, &hashValue);
        return hashValue;
        // unsigned int hashValue1 = 0;
        // if (a.keysignal) {
        //     MurmurHash3_x86_32((const char*) a.full_key, 16, 0, &hashValue1);
        // } else {
        //     MurmurHash3_x86_32((const char*) a.rev_key, 16, 0, &hashValue1);
        // }
        // return hashValue1;
    }
};

class Sketch {
public:
    virtual void insert(Key key, uint32_t seq, uint32_t ack, uint32_t _time) = 0;
    virtual int estimate(Key key) = 0;
    //virtual std::unordered_set<Key, HashFunc, Cmp> detect(uint32_t thr) = 0;
    virtual std::vector<const char*> detect(uint32_t thr) = 0;
};

#endif //SKETCH_H
