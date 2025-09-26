#ifndef KEY_H
#define KEY_H
#include <cstdint>
#include <string.h>
#define mask1 43123
#define mask2 91242

class Key {
public:
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sport;
    uint16_t dport;

    uint32_t fp;

    char *full_key;

    char *rev_key;

    bool keysignal;

    Key(uint32_t src_ip, uint32_t dst_ip, uint16_t sport, uint16_t dport) {
        this->src_ip = src_ip;
        this->dst_ip = dst_ip;
        this->sport = sport;
        this->dport = dport;
        full_key = new char[16];
        rev_key = new char[16];
        memcpy(full_key, &src_ip, 4);
        memcpy(rev_key, &dst_ip, 4);
        memcpy(full_key + 4, &sport, 2);
        memcpy(rev_key + 4, &dport, 2);
        memcpy(full_key + 6, &dst_ip, 4);
        memcpy(rev_key + 6, &src_ip, 4);
        memcpy(full_key + 10, &dport, 2);
        memcpy(rev_key + 10, &sport, 2);
        if (src_ip < dst_ip) {
            keysignal = true;
        } else {
            keysignal = false;
        }
    }

    Key() {
        this->src_ip = 0;
        this->dst_ip = 0;
        this->sport = 0;
        this->dport = 0;
    }
    ~Key() {

    }
    /*uint32_t cal_xor() {
        if (src_ip < dst_ip) {
            return src_ip ^ sport ^ dst_ip ^ dport ^ mask1;
        } else {
            return src_ip ^ sport ^ dst_ip ^ dport ^ mask2;
        }
    }*/
    uint32_t cal_xor_key() {
        return src_ip ^ sport ^ dst_ip ^ dport;
    }

    int cmp_key(Key other_key) {
        if (src_ip == other_key.src_ip && sport == other_key.sport && dst_ip == other_key.dst_ip && dport == other_key.dport) {
            return 1;
        } else {
            if (src_ip == other_key.dst_ip && sport == other_key.dport && dst_ip == other_key.src_ip && dport == other_key.sport) {
               return 1;
            } else {
                return 0;
            }
        }
    }

    int cmp_fp(uint32_t other_fp) {
        if (this->fp == other_fp) {
            return 1;
        } else {
            return 0;
        }
    }

    void set_value(Key other_key) {
        src_ip = other_key.src_ip;
        dst_ip = other_key.dst_ip;
        sport = other_key.sport;
        dport = other_key.dport;
    }
    Key get_rev_key () {
        return Key(dst_ip, src_ip, dport, sport);
    }
};

#endif //KEY_H
