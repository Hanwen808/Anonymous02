#ifndef LEAN_H
#define LEAN_H
#include <vector>
#include "Sketch.h"

class Lean : public Sketch {
public:
    uint32_t d, m;
    int **rtt_cnt, **mtime;
    uint32_t *hashseeds;
    uint32_t *directseeds;
    uint32_t timeout;
    Lean(uint32_t, uint32_t, uint32_t);
    ~Lean() {
        delete[] hashseeds;
        delete[] directseeds;
        for (int i = 0; i < d; ++i) {
            delete[] rtt_cnt[i];
            delete[] mtime[i];
        }
    }
    void insert(Key key, uint32_t seq, uint32_t ack, uint32_t _time);
    int estimate(Key key);
    std::vector<const char *> detect(uint32_t thr);
};

#endif //LEAN_H
