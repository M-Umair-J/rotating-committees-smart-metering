#include "common.h"
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <poll.h>
#include <math.h>
#include <stddef.h>
#include <limits.h>

/* One sequentially scheduled OS process per meter; parent = ESP + router + harness.
 * Controls/oracle data are NOT protocol traffic. Wire packets are end-to-end AEAD.
 */
enum {
    START = 1,
    COMMIT,
    REVEAL,
    SELECT,
    ROUND,
    GENERATE,
    RECEIVE,
    ROUND_END,
    SPATIAL,
    BILL,
    STOP
};
enum { W_COMMIT = 1, W_REVEAL, W_READING, W_SHARE, W_SPATIAL, W_BILL };
enum { F_PACKET = 100, F_DONE = 101 };
typedef struct {
    int op, a, b, c, d, len;
    unsigned char data[CAP];
} Frame;
#define PREFIX ((int)offsetof(Frame, data))
typedef struct {
    int n, c, k, billing, rounds, sample, seed, tariffs[4096], nt, attack_round;
    double interval, duration;
    char out[512], attack[32], csv[512];
} Config;
static Config cfg = {.n = 20,
                     .c = 10,
                     .k = 6,
                     .billing = 12,
                     .rounds = 144,
                     .sample = 300,
                     .seed = 42,
                     .tariffs = {98, 157, 203},
                     .nt = 3,
                     .attack_round = 2,
                     .interval = 0,
                     .duration = 0,
                     .attack = "none"};
static unsigned char private_keys[MAXN + 1][32], public_keys[MAXN + 1][32], runid[32];
static int sockets[MAXN + 1];
static pid_t children[MAXN + 1];
static volatile sig_atomic_t stopping = 0;
static FILE *messages, *results, *committees, *roundtimes;
static uint64_t packets = 0, bytes = 0, local_packets = 0, control_bytes = 0, rejections = 0;
static int attack_used = 0, accepted = 0, failed = 0;
static double phase_wall[STOP + 1], phase_cpu[STOP + 1];
static uint64_t phase_count[STOP + 1];
static const char *phase_names[] = {"none",
                                    "period_reset",
                                    "randomness_commit",
                                    "randomness_reveal",
                                    "committee_selection",
                                    "round_reset",
                                    "reading_commitment_and_shares",
                                    "receive_authenticate_accumulate",
                                    "round_coverage",
                                    "spatial_report",
                                    "billing_report",
                                    "shutdown"};
typedef struct {
    int id, fd, period, round, tariff, members[MAXN], selected;
    unsigned char sendkey[MAXN + 1][32], recvkey[MAXN + 1][32], nonce[32], rc[MAXN + 1][32],
        rv[MAXN + 1][32];
    uint64_t sent[MAXN + 1], received[MAXN + 1];
    int havec[MAXN + 1], havev[MAXN + 1], seen[MAXN + 1], seencommit[MAXN + 1], complete[MAXN + 1];
    mpz_t spatial, bill[MAXN + 1], readingcommit[MAXN + 1], billcommit[MAXN + 1];
    mpz_t spatial_reports[MAXN + 1], billing_reports[MAXN + 1][MAXN + 1];
    int spatial_have[MAXN + 1], spatial_cover[MAXN + 1], billing_have[MAXN + 1][MAXN + 1],
        billing_cover[MAXN + 1][MAXN + 1];
    FILE *log, *timing;
    unsigned long rejected;
    double start_cpu;
} Actor;
static Actor *esp;
static pid_t owner_pid;
static int clean_exit = 0;
static double reconstruct_wall[2], reconstruct_cpu[2];
static unsigned reconstruct_count[2];
static void cleanup_failure(void) {
    if (getpid() != owner_pid || clean_exit)
        return;
    for (int i = 1; i <= cfg.n; i++)
        if (children[i] > 0) {
            kill(children[i], SIGTERM);
        }
    for (int i = 1; i <= cfg.n; i++)
        if (children[i] > 0) {
            waitpid(children[i], NULL, 0);
        }
    if (*cfg.out) {
        char p[1024];
        snprintf(p, sizeof p, "%s/failure.txt", cfg.out);
        FILE *f = fopen(p, "w");
        if (f) {
            fputs("Run did not finish normally. CSV logs and checkpoint.json may contain completed "
                  "work. Do not treat this as a completed experiment. See stderr.\n",
                  f);
            fclose(f);
        }
    }
}
static void path(char *dst, size_t cap, const char *name) {
    CHECK(snprintf(dst, cap, "%s/%s", cfg.out, name) < (int)cap);
}
static FILE *openlog(const char *name, const char *head) {
    char p[1024];
    path(p, sizeof p, name);
    FILE *f = fopen(p, "w");
    CHECK(f);
    setvbuf(f, NULL, _IOLBF, 0);
    if (head)
        fputs(head, f);
    return f;
}
static void event(Actor *a, const char *what, int peer, int type) {
    fprintf(a->log, "%d,%d,%s,%d,%d\n", a->period, a->round, what, peer, type);
}
static void sigstop(int sig) {
    (void)sig;
    stopping = 1;
}
static void sendframe(int fd, const Frame *f) {
    int n = PREFIX + f->len;
    ssize_t r;
    do {
        r = send(fd, f, (size_t)n, MSG_NOSIGNAL);
    } while (r < 0 && errno == EINTR);
    CHECK(r == n);
}
static void recvframe(int fd, Frame *f) {
    struct pollfd p = {fd, POLLIN, 0};
    int r;
    do {
        r = poll(&p, 1, 120000);
    } while (r < 0 && errno == EINTR);
    CHECK(r > 0);
    ssize_t n;
    do {
        n = recv(fd, f, sizeof *f, 0);
    } while (n < 0 && errno == EINTR);
    CHECK(n >= PREFIX && f->len >= 0 && f->len <= CAP && n == PREFIX + f->len);
}
static void receive_packet(Actor *a, const unsigned char *wire, int len);
static void route(const unsigned char *wire, int len);
static void emit(Actor *a, int dst, int type, int item, const unsigned char *plain, int n) {
    unsigned char h[HEADER] = {0};
    put32(h, type);
    put32(h + 4, a->id);
    put32(h + 8, dst);
    put32(h + 12, a->period);
    put32(h + 16, a->round);
    put32(h + 20, item);
    put64(h + 24, ++a->sent[dst]);
    Frame f = {.op = F_PACKET};
    f.len = seal(a->sendkey[dst], h, plain, n, f.data);
    if (a->id == 0)
        route(f.data, f.len);
    else
        sendframe(a->fd, &f);
}
static void broadcast(Actor *a, int type, const unsigned char *data, int n) {
    for (int j = 0; j <= cfg.n; j++)
        emit(a, j, type, 0, data, n);
}
static int member(const Actor *a, int id) {
    for (int j = 0; j < cfg.c; j++)
        if (a->members[j] == id)
            return 1;
    return 0;
}
static void reject(Actor *a, int src, int type, const char *reason) {
    a->rejected++;
    event(a, reason, src, type);
}
static void receive_packet(Actor *a, const unsigned char *w, int len) {
    if (len < HEADER + TAG) {
        reject(a, -1, 0, "short_packet");
        return;
    }
    int type = (int)get32(w), src = (int)get32(w + 4), dst = (int)get32(w + 8),
        b = (int)get32(w + 12), r = (int)get32(w + 16), item = (int)get32(w + 20);
    uint64_t seq = get64(w + 24);
    if (src < 1 || src > cfg.n || dst != a->id || b != a->period || r != a->round) {
        reject(a, src, type, "context_rejected");
        return;
    }
    if (seq <= a->received[src]) {
        reject(a, src, type, "replay_rejected");
        return;
    }
    unsigned char plain[CAP];
    int n = unseal(a->recvkey[src], w, len, plain);
    if (n < 0) {
        reject(a, src, type, "authentication_rejected");
        return;
    }
    a->received[src] = seq;
    if (type == W_COMMIT && n == 32 && !a->havec[src]) {
        memcpy(a->rc[src], plain, 32);
        a->havec[src] = 1;
    } else if (type == W_REVEAL && n == 32 && a->havec[src] && !a->havev[src]) {
        unsigned char input[40], digest[32];
        put32(input, b);
        put32(input + 4, src);
        memcpy(input + 8, plain, 32);
        hash(input, 40, digest);
        if (CRYPTO_memcmp(digest, a->rc[src], 32)) {
            reject(a, src, type, "reveal_mismatch");
            return;
        }
        memcpy(a->rv[src], plain, 32);
        a->havev[src] = 1;
    } else if (type == W_READING && n == B && item == 0 && !a->seencommit[src]) {
        mpz_t z, t;
        mpz_inits(z, t, NULL);
        unpackz(z, plain);
        int ok = mpz_cmp_ui(z, 0) > 0 && mpz_cmp(z, P) < 0;
        if (ok) {
            mpz_powm(t, z, Q, P);
            ok = mpz_cmp_ui(t, 1) == 0;
        }
        if (ok) {
            mpz_set(a->readingcommit[src], z);
            a->seencommit[src] = 1;
        } else
            reject(a, src, type, "invalid_group_element");
        mpz_clears(z, t, NULL);
        if (!ok)
            return;
    } else if (type == W_SHARE && n == B && a->selected && item == src && !a->seen[src]) {
        mpz_t z;
        mpz_init(z);
        unpackz(z, plain);
        if (mpz_cmp(z, Q) >= 0) {
            mpz_clear(z);
            reject(a, src, type, "invalid_scalar");
            return;
        }
        mpz_add(a->spatial, a->spatial, z);
        mpz_mod(a->spatial, a->spatial, Q);
        mpz_addmul_ui(a->bill[src], z, a->tariff);
        mpz_mod(a->bill[src], a->bill[src], Q);
        a->seen[src] = 1;
        mpz_clear(z);
    } else if (type == W_SPATIAL && n == B + 4 && a->id == 0 && member(a, src) && item == 0 &&
               !a->spatial_have[src]) {
        unpackz(a->spatial_reports[src], plain);
        if (mpz_cmp(a->spatial_reports[src], Q) >= 0) {
            reject(a, src, type, "invalid_scalar");
            return;
        }
        a->spatial_have[src] = 1;
        a->spatial_cover[src] = get32(plain + B) == 1;
    } else if (type == W_BILL && n == B + 4 && a->id == 0 && member(a, src) && item >= 1 &&
               item <= cfg.n && !a->billing_have[item][src]) {
        unpackz(a->billing_reports[item][src], plain);
        if (mpz_cmp(a->billing_reports[item][src], Q) >= 0) {
            reject(a, src, type, "invalid_scalar");
            return;
        }
        a->billing_have[item][src] = 1;
        a->billing_cover[item][src] = get32(plain + B) == 1;
    } else {
        reject(a, src, type, "unexpected_message");
        return;
    }
    event(a, "received", src, type);
}
static uint64_t reading(int id, int round) {
    unsigned char b[16], d[32];
    put32(b, cfg.seed);
    put32(b + 4, id);
    put32(b + 8, round);
    put32(b + 12, 1);
    hash(b, 16, d); /* Synthetic integer mWh: average power 100..2099 W. */
    return (uint64_t)(100 + get32(d) % 2000) * (uint64_t)cfg.sample * 1000 / 3600;
}
static void init_actor(Actor *a, int id, int fd) {
    memset(a, 0, sizeof *a);
    a->id = id;
    a->fd = fd;
    a->period = -1;
    a->round = -1;
    a->start_cpu = now(CLOCK_PROCESS_CPUTIME_ID);
    char name[64];
    snprintf(name, sizeof name, "actor-%d-events.csv", id);
    a->log = openlog(name, "period,round,event,peer,message_type\n");
    snprintf(name, sizeof name, "actor-%d-timing.csv", id);
    a->timing = openlog(name, "period,round,phase,wall_seconds,cpu_seconds\n");
    mpz_init(a->spatial);
    for (int i = 0; i <= cfg.n; i++) {
        mpz_inits(a->bill[i], a->readingcommit[i], a->billcommit[i], a->spatial_reports[i], NULL);
        a->complete[i] = 1;
        for (int j = 0; j <= cfg.n; j++)
            mpz_init(a->billing_reports[i][j]);
        derive(private_keys[id], public_keys[i], id, i, runid, a->sendkey[i]);
        derive(private_keys[id], public_keys[i], i, id, runid, a->recvkey[i]);
    }
    /* Every process keeps only its own derived channel keys after trusted provisioning. */
    OPENSSL_cleanse(private_keys, sizeof private_keys);
}
static void handle(Actor *a, const Frame *f) {
    switch (f->op) {
    case START:
        a->period = f->a;
        a->round = f->b;
        memset(a->havec, 0, sizeof a->havec);
        memset(a->havev, 0, sizeof a->havev);
        memset(a->billing_have, 0, sizeof a->billing_have);
        for (int i = 1; i <= cfg.n; i++) {
            mpz_set_ui(a->bill[i], 0);
            mpz_set_ui(a->billcommit[i], 1);
            a->complete[i] = 1;
        }
        break;
    case COMMIT: {
        CHECK(RAND_priv_bytes(a->nonce, 32) == 1);
        unsigned char b[40], d[32];
        put32(b, a->period);
        put32(b + 4, a->id);
        memcpy(b + 8, a->nonce, 32);
        hash(b, 40, d);
        broadcast(a, W_COMMIT, d, 32);
        break;
    }
    case REVEAL:
        broadcast(a, W_REVEAL, a->nonce, 32);
        break;
    case SELECT: {
        unsigned char input[4 + 32 * MAXN], seed[32], score[MAXN + 1][32];
        put32(input, a->period);
        for (int i = 1; i <= cfg.n; i++) {
            CHECK(a->havec[i] && a->havev[i]);
            memcpy(input + 4 + (i - 1) * 32, a->rv[i], 32);
        }
        hash(input, 4 + cfg.n * 32, seed);
        int ids[MAXN];
        for (int i = 1; i <= cfg.n; i++) {
            unsigned char z[36];
            memcpy(z, seed, 32);
            put32(z + 32, i);
            hash(z, 36, score[i]);
            ids[i - 1] = i;
        }
        for (int i = 0; i < cfg.n; i++)
            for (int j = i + 1; j < cfg.n; j++)
                if (memcmp(score[ids[j]], score[ids[i]], 32) < 0) {
                    int t = ids[i];
                    ids[i] = ids[j];
                    ids[j] = t;
                }
        memcpy(a->members, ids, cfg.c * sizeof(int));
        a->selected = member(a, a->id);
        event(a, "committee_selected", a->selected, 0);
        break;
    }
    case ROUND:
        a->round = f->a;
        a->tariff = f->b;
        mpz_set_ui(a->spatial, 0);
        memset(a->seen, 0, sizeof a->seen);
        memset(a->seencommit, 0, sizeof a->seencommit);
        memset(a->spatial_have, 0, sizeof a->spatial_have);
        break;
    case GENERATE: {
        mpz_t co[MAXN], s, c;
        mpz_inits(s, c, NULL);
        for (int d = 0; d < cfg.k; d++)
            mpz_init(co[d]);
        uint64_t val = f->len == 8 ? get64(f->data) : reading(a->id, a->round);
        unsigned char valbuf[8];
        put64(valbuf, val);
        mpz_import(co[0], 8, 1, 1, 1, 0, valbuf);
        for (int d = 1; d < cfg.k; d++) {
            scalar_random(co[d]);
        }
        commitment(c, co[0], co[1]);
        unsigned char plain[B];
        packz(plain, c);
        broadcast(a, W_READING, plain, B);
        for (int j = 0; j < cfg.c; j++) {
            int recipient = a->members[j];
            mpz_set_ui(s, 0);
            for (int d = cfg.k - 1; d >= 0; d--) {
                mpz_mul_ui(s, s, recipient);
                mpz_add(s, s, co[d]);
                mpz_mod(s, s, Q);
            }
            if (!strcmp(cfg.attack, "bad-share") && a->id == 1 && a->round == cfg.attack_round &&
                j == 0) {
                mpz_add_ui(s, s, 1);
                mpz_mod(s, s, Q);
                event(a, "injected_bad_share", recipient, W_SHARE);
            }
            packz(plain, s);
            emit(a, recipient, W_SHARE, a->id, plain, B);
        }
        for (int d = 0; d < cfg.k; d++) {
            mpz_clear(co[d]);
        }
        mpz_clears(s, c, NULL);
        break;
    }
    case RECEIVE:
        receive_packet(a, f->data, f->len);
        break;
    case ROUND_END:
        for (int i = 1; i <= cfg.n; i++) {
            if (a->selected && !a->seen[i])
                a->complete[i] = 0;
            if (a->id == 0) {
                if (!a->seencommit[i])
                    a->complete[i] = 0;
                else {
                    mpz_t t;
                    mpz_init(t);
                    mpz_powm_ui(t, a->readingcommit[i], a->tariff, P);
                    mpz_mul(a->billcommit[i], a->billcommit[i], t);
                    mpz_mod(a->billcommit[i], a->billcommit[i], P);
                    mpz_clear(t);
                }
            }
        }
        break;
    case SPATIAL: {
        if (!a->selected) {
            break;
        }
        unsigned char p[B + 4];
        int cover = 1;
        for (int i = 1; i <= cfg.n; i++)
            if (!a->seen[i])
                cover = 0;
        mpz_t z;
        mpz_init_set(z, a->spatial);
        if (!strcmp(cfg.attack, "bad-aggregate") && a->id == a->members[0] &&
            a->round == cfg.attack_round) {
            mpz_add_ui(z, z, 1);
            mpz_mod(z, z, Q);
        }
        packz(p, z);
        put32(p + B, cover);
        emit(a, 0, W_SPATIAL, 0, p, sizeof p);
        mpz_clear(z);
        break;
    }
    case BILL:
        if (a->selected) {
            for (int i = 1; i <= cfg.n; i++) {
                unsigned char p[B + 4];
                packz(p, a->bill[i]);
                put32(p + B, a->complete[i]);
                emit(a, 0, W_BILL, i, p, sizeof p);
            }
        }
        break;
    case STOP:
        break;
    default:
        CHECK(0);
    }
}
static void run_child(int id, int fd) {
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_DFL);
    signal(SIGHUP, SIG_IGN);
    Actor *a = calloc(1, sizeof *a);
    CHECK(a);
    init_actor(a, id, fd);
    for (;;) {
        Frame f;
        recvframe(fd, &f);
        double w = now(CLOCK_MONOTONIC), c = now(CLOCK_PROCESS_CPUTIME_ID);
        unsigned long before = a->rejected;
        handle(a, &f);
        w = now(CLOCK_MONOTONIC) - w;
        c = now(CLOCK_PROCESS_CPUTIME_ID) - c;
        fprintf(a->timing, "%d,%d,%s,%.9f,%.9f\n", a->period, a->round, phase_names[f.op], w, c);
        Frame done = {.op = F_DONE, .a = (int)(a->rejected - before), .len = 16};
        memcpy(done.data, &w, 8);
        memcpy(done.data + 8, &c, 8);
        sendframe(fd, &done);
        if (f.op == STOP)
            break;
    }
    struct rusage u;
    CHECK(getrusage(RUSAGE_SELF, &u) == 0);
    char name[64];
    snprintf(name, sizeof name, "actor-%d-summary.json", id);
    FILE *sum = openlog(name, NULL);
    fprintf(sum,
            "{\"actor\":%d,\"cpu_seconds_including_key_setup\":%.9f,\"max_rss_kib\":%ld,\"rejected_"
            "messages\":%lu}\n",
            id, now(CLOCK_PROCESS_CPUTIME_ID) - a->start_cpu, u.ru_maxrss, a->rejected);
    fclose(sum);
    fclose(a->log);
    fclose(a->timing);
    close(fd);
    _exit(0);
}
static void command(int id, const Frame *f) {
    double w = 0, c = 0;
    if (id == 0) {
        unsigned long before = esp->rejected;
        w = now(CLOCK_MONOTONIC);
        c = now(CLOCK_PROCESS_CPUTIME_ID);
        handle(esp, f);
        w = now(CLOCK_MONOTONIC) - w;
        c = now(CLOCK_PROCESS_CPUTIME_ID) - c;
        rejections += esp->rejected - before;
        fprintf(esp->timing, "%d,%d,%s,%.9f,%.9f\n", esp->period, esp->round, phase_names[f->op], w,
                c);
    } else {
        sendframe(sockets[id], f);
        control_bytes += PREFIX + f->len;
        /* Drain all outgoing packets before routing: self-delivery cannot deadlock. */
        Frame *queue = calloc((size_t)(cfg.n + cfg.c + 4), sizeof(Frame));
        CHECK(queue);
        int nq = 0;
        Frame out;
        for (;;) {
            recvframe(sockets[id], &out);
            control_bytes += PREFIX + out.len;
            if (out.op == F_DONE) {
                memcpy(&w, out.data, 8);
                memcpy(&c, out.data + 8, 8);
                rejections += (unsigned)out.a;
                break;
            }
            CHECK(out.op == F_PACKET && nq < cfg.n + cfg.c + 4);
            queue[nq++] = out;
        }
        for (int j = 0; j < nq; j++) {
            route(queue[j].data, queue[j].len);
        }
        free(queue);
    }
    phase_wall[f->op] += w;
    phase_cpu[f->op] += c;
    phase_count[f->op]++;
}
static void route(const unsigned char *wire, int len) {
    int src = get32(wire + 4), dst = get32(wire + 8), type = get32(wire), r = get32(wire + 16);
    CHECK(src >= 1 && src <= cfg.n && dst >= 0 && dst <= cfg.n);
    Frame f = {.op = RECEIVE, .len = len};
    memcpy(f.data, wire, len);
    int inject = !attack_used && r == cfg.attack_round && type == W_SHARE && src == 1;
    const char *action = "delivered";
    if (inject && !strcmp(cfg.attack, "tamper")) {
        f.data[HEADER] ^= 1;
        attack_used = 1;
        action = "tampered";
    }
    if (inject && !strcmp(cfg.attack, "drop-share")) {
        attack_used = 1;
        action = "dropped";
    }
    if (src == dst)
        local_packets++;
    else {
        packets++;
        bytes += (unsigned)len;
    }
    fprintf(messages, "%u,%d,%d,%d,%d,%d,%s\n", get32(wire + 12), r, src, dst, type, len, action);
    if (strcmp(action, "dropped"))
        command(dst, &f);
    if (inject && !strcmp(cfg.attack, "replay")) {
        attack_used = 1;
        if (src == dst)
            local_packets++;
        else {
            packets++;
            bytes += (unsigned)len;
        }
        fprintf(messages, "%u,%d,%d,%d,%d,%d,replayed\n", get32(wire + 12), r, src, dst, type, len);
        command(dst, &f);
    }
}
static void all(const Frame *f) {
    command(0, f);
    for (int i = 1; i <= cfg.n; i++)
        command(i, f);
}
static void result(int customer, int start, int end, int partial, uint64_t expected) {
    mpz_t ys[MAXN], v, z, cm, t, expected_z;
    mpz_inits(v, z, cm, t, expected_z, NULL);
    int xs[MAXN], count = 0, cover = 1;
    mpz_set_ui(cm, 1);
    for (int j = 0; j < cfg.c && count < cfg.k; j++) {
        int id = esp->members[j];
        int have = customer ? esp->billing_have[customer][id] : esp->spatial_have[id];
        if (!have)
            continue;
        xs[count] = id;
        mpz_init_set(ys[count],
                     customer ? esp->billing_reports[customer][id] : esp->spatial_reports[id]);
        cover &= customer ? esp->billing_cover[customer][id] : esp->spatial_cover[id];
        count++;
    }
    if (customer) {
        mpz_set(cm, esp->billcommit[customer]);
        cover &= esp->complete[customer];
    } else
        for (int i = 1; i <= cfg.n; i++) {
            cover &= esp->seencommit[i];
            mpz_mul(cm, cm, esp->readingcommit[i]);
            mpz_mod(cm, cm, P);
        }
    double w = now(CLOCK_MONOTONIC), c = now(CLOCK_PROCESS_CPUTIME_ID);
    int verified = 0;
    if (count == cfg.k) {
        interpolate01(v, z, ys, xs, cfg.k);
        commitment(t, v, z);
        verified = mpz_cmp(t, cm) == 0;
    }
    double cw = now(CLOCK_MONOTONIC) - w, cc = now(CLOCK_PROCESS_CPUTIME_ID) - c;
    reconstruct_wall[!!customer] += cw;
    reconstruct_cpu[!!customer] += cc;
    reconstruct_count[!!customer]++;
    fprintf(esp->timing, "%d,%d,%s,%.9f,%.9f\n", esp->period, esp->round,
            customer ? "billing_reconstruction_verify" : "spatial_reconstruction_verify", cw, cc);
    unsigned char ex[8];
    put64(ex, expected);
    mpz_import(expected_z, 8, 1, 1, 1, 0, ex);
    int match = count == cfg.k && mpz_cmp(v, expected_z) == 0;
    int ok = verified && cover && count == cfg.k;
    const char *status = ok ? (partial ? "verified_partial" : "verified_complete")
                            : (count < cfg.k || !cover ? "incomplete" : "rejected");
    fprintf(results, "%s,%d,%d,%d,%d,%s,", customer ? "bill" : "spatial", esp->period, customer,
            start, end, status);
    if (count == cfg.k) {
        mpz_out_str(results, 10, v);
    }
    fprintf(results, ",%s,%d,%d,%llu,%d,%.9f\n", customer ? "nanoCAD" : "mWh", verified, cover,
            (unsigned long long)expected, match, cw);
    if (ok)
        accepted++;
    else
        failed++;
    for (int j = 0; j < count; j++) {
        mpz_clear(ys[j]);
    }
    mpz_clears(v, z, cm, t, expected_z, NULL);
}
static void check_stop(void) {
    struct pollfd p = {STDIN_FILENO, POLLIN, 0};
    if (poll(&p, 1, 0) > 0 && (p.revents & POLLIN)) {
        char b[64];
        ssize_t n = read(STDIN_FILENO, b, sizeof b);
        for (ssize_t i = 0; i < n; i++)
            if (b[i] == 'q' || b[i] == 'Q')
                stopping = 1;
    }
}
static void help(void) {
    puts("Usage: ./meter-sim [options]\n --meters N (20) --committee C (10) --threshold K (6)\n "
         "--rounds R (144; 0=until stopped) --billing-rounds B (12)\n --interval SECONDS (0, "
         "minimum time between round starts)\n --duration SECONDS (0=no wall limit) "
         "--sample-seconds S (300)\n --tariffs 98,157,203 (microCAD/Wh, repeats each reading) "
         "--seed 42\n --csv readings.csv (wide header round,sm1,...,smN; integer mWh)\n --attack "
         "none|tamper|replay|bad-share|bad-aggregate|drop-share\n --attack-round R (2, zero-based) "
         "--out NEW_DIRECTORY\n Ctrl+C or q followed by Enter: finish round, save partial subtotal "
         "and metrics.");
}
static long integer(const char *s, long lo, long hi) {
    char *end;
    errno = 0;
    long n = strtol(s, &end, 10);
    CHECK(!errno && *s && !*end && n >= lo && n <= hi);
    return n;
}
static double realnum(const char *s) {
    char *end;
    errno = 0;
    double v = strtod(s, &end);
    CHECK(!errno && *s && !*end && isfinite(v) && v >= 0 && v <= 1e9);
    return v;
}
static void options(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--help")) {
            help();
            exit(0);
        }
        CHECK(i + 1 < argc);
        const char *v = argv[++i];
#define OPT(name, field, lo, hi)                                                                   \
    if (!strcmp(a, name)) {                                                                        \
        cfg.field = (int)integer(v, lo, hi);                                                       \
        continue;                                                                                  \
    }
        OPT("--meters", n, 2, MAXN)
        OPT("--committee", c, 2, MAXN) OPT("--threshold", k, 2, MAXN)
            OPT("--rounds", rounds, 0, 10000000) OPT("--billing-rounds", billing, 1, 100000)
                OPT("--sample-seconds", sample, 1, 86400) OPT("--seed", seed, 0, INT_MAX)
                    OPT("--attack-round", attack_round, 0, 10000000)
#undef OPT
                        if (!strcmp(a, "--interval")) {
            cfg.interval = realnum(v);
            continue;
        }
        if (!strcmp(a, "--duration")) {
            cfg.duration = realnum(v);
            continue;
        }
        if (!strcmp(a, "--out")) {
            CHECK(strlen(v) < sizeof cfg.out);
            strcpy(cfg.out, v);
            continue;
        }
        if (!strcmp(a, "--csv")) {
            CHECK(strlen(v) < sizeof cfg.csv);
            strcpy(cfg.csv, v);
            continue;
        }
        if (!strcmp(a, "--attack")) {
            CHECK(strlen(v) < sizeof cfg.attack);
            strcpy(cfg.attack, v);
            continue;
        }
        if (!strcmp(a, "--tariffs")) {
            char *copy = strdup(v);
            CHECK(copy);
            cfg.nt = 0;
            for (char *p = strtok(copy, ","); p; p = strtok(NULL, ",")) {
                CHECK(cfg.nt < 4096);
                cfg.tariffs[cfg.nt++] = (int)integer(p, 0, 1000000);
            }
            free(copy);
            CHECK(cfg.nt > 0);
            continue;
        }
        fprintf(stderr, "Unknown option: %s\n", a);
        exit(2);
    }
    CHECK(cfg.k <= cfg.c && cfg.c <= cfg.n);
    CHECK(!strcmp(cfg.attack, "none") || !strcmp(cfg.attack, "tamper") ||
          !strcmp(cfg.attack, "replay") || !strcmp(cfg.attack, "bad-share") ||
          !strcmp(cfg.attack, "bad-aggregate") || !strcmp(cfg.attack, "drop-share"));
    if (!*cfg.out) {
        time_t t = time(NULL);
        struct tm tm;
        localtime_r(&t, &tm);
        char stamp[64];
        strftime(stamp, sizeof stamp, "%Y%m%d-%H%M%S", &tm);
        snprintf(cfg.out, sizeof cfg.out, "runs/%s-%ld", stamp, (long)getpid());
    }
    CHECK(mkdir("runs", 0700) == 0 || errno == EEXIST);
    CHECK(mkdir(cfg.out, 0700) == 0); /* Never overwrite a run. */
}
static void environment(void) {
    FILE *f = openlog("environment.txt", NULL);
    struct utsname u;
    CHECK(uname(&u) == 0);
    fprintf(f,
            "system=%s\nrelease=%s\nmachine=%s\ncompiler=%s\nopenssl=%s\ngmp=%s\nparameter_bits="
            "2048\nscalar_bits=2047\nprocesses=%d\n",
            u.sysname, u.release, u.machine, __VERSION__, OpenSSL_version(OPENSSL_VERSION),
            gmp_version, cfg.n + 1);
    const char *files[] = {"/proc/device-tree/model", "/sys/class/thermal/thermal_zone0/temp",
                           "/proc/meminfo"};
    for (int i = 0; i < 3; i++) {
        FILE *in = fopen(files[i], "r");
        if (in) {
            fprintf(f, "\n%s:\n", files[i]);
            int ch;
            while ((ch = fgetc(in)) != EOF)
                fputc(ch ? ch : ' ', f);
            fclose(in);
            fputc('\n', f);
        }
    }
    fclose(f);
    f = openlog("config.json", NULL);
    fprintf(f,
            "{\"meters\":%d,\"committee_size\":%d,\"threshold\":%d,\"rounds\":%d,\"billing_"
            "rounds\":%d,\"interval_seconds\":%.6f,\"duration_seconds\":%.6f,\"historical_seconds_"
            "per_reading\":%d,\"seed\":%d,\"group_bits\":2048,\"attack\":\"%s\",\"attack_round\":%"
            "d,\"csv_source\":%s,\"tariffs_microCAD_per_Wh\":[",
            cfg.n, cfg.c, cfg.k, cfg.rounds, cfg.billing, cfg.interval, cfg.duration, cfg.sample,
            cfg.seed, cfg.attack, cfg.attack_round, *cfg.csv ? "true" : "false");
    for (int i = 0; i < cfg.nt; i++)
        fprintf(f, "%s%d", i ? "," : "", cfg.tariffs[i]);
    fputs("]}\n", f);
    fclose(f);
    f = openlog("public_parameters.txt", NULL);
    gmp_fprintf(f, "p=%Zx\nq=%Zx\ng=%Zx\nh=%Zx\n", P, Q, G, H);
    fprintf(f, "run_id=");
    for (int i = 0; i < 32; i++)
        fprintf(f, "%02x", runid[i]);
    fputc('\n', f);
    for (int i = 0; i <= cfg.n; i++) {
        fprintf(f, "actor_%d_X25519=", i);
        for (int j = 0; j < 32; j++)
            fprintf(f, "%02x", public_keys[i][j]);
        fputc('\n', f);
    }
    fclose(f);
}
int main(int argc, char **argv) {
    options(argc, argv);
    owner_pid = getpid();
    CHECK(atexit(cleanup_failure) == 0);
    crypto_init();
    CHECK(RAND_bytes(runid, 32) == 1);
    for (int i = 0; i <= cfg.n; i++)
        keygen(private_keys[i], public_keys[i]);
    environment();
    messages = openlog("messages.csv", "period,round,sender,recipient,type,wire_bytes,action\n");
    results = openlog("results.csv",
                      "kind,period,customer,start_round,end_round,status,value,unit,commitment_ok,"
                      "coverage_ok,oracle_expected,oracle_match,reconstruction_verify_seconds\n");
    committees = openlog("committees.csv", "period,position,meter\n");
    roundtimes = openlog("rounds.csv", "round,period,tariff_microCAD_per_Wh,processing_seconds\n");
    FILE *csv = NULL;
    if (*cfg.csv) {
        csv = fopen(cfg.csv, "r");
        CHECK(csv);
        char line[4096];
        CHECK(fgets(line, sizeof line, csv));
        char expected[1024] = "round";
        for (int i = 1; i <= cfg.n; i++) {
            char name[32];
            snprintf(name, sizeof name, ",sm%d", i);
            strcat(expected, name);
        }
        line[strcspn(line, "\r\n")] = 0;
        CHECK(!strcmp(line, expected));
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, sigstop);
    signal(SIGTERM, sigstop);
    signal(SIGHUP, sigstop);
    double setup_start = now(CLOCK_MONOTONIC);
    for (int i = 1; i <= cfg.n; i++) {
        int pair[2];
        CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) == 0);
        pid_t pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            close(pair[0]);
            for (int j = 1; j < i; j++)
                close(sockets[j]);
            fclose(messages);
            fclose(results);
            fclose(committees);
            fclose(roundtimes);
            if (csv)
                fclose(csv);
            run_child(i, pair[1]);
        }
        close(pair[1]);
        sockets[i] = pair[0];
        children[i] = pid;
    }
    FILE *actors = openlog("actors.csv", "actor,pid,role\n");
    fprintf(actors, "0,%ld,esp_router_harness\n", (long)getpid());
    for (int i = 1; i <= cfg.n; i++) {
        fprintf(actors, "%d,%ld,meter\n", i, (long)children[i]);
    }
    fclose(actors);
    esp = calloc(1, sizeof *esp);
    CHECK(esp);
    init_actor(esp, 0, -1);
    double setup_wall = now(CLOCK_MONOTONIC) - setup_start;
    printf("Running %d meters + ESP on this machine. Committee %d, threshold %d.\nOutput: "
           "%s\nCtrl+C or q + Enter stops after the active round.\n",
           cfg.n, cfg.c, cfg.k, cfg.out);
    fflush(stdout);
    double started = now(CLOCK_MONOTONIC), max_round = 0, total_round = 0;
    int completed = 0, period = -1, within = 0, period_start = 0;
    uint64_t expected_bill[MAXN + 1] = {0};
    const char *reason = "round_limit";
    while (!cfg.rounds || completed < cfg.rounds) {
        check_stop();
        if (stopping) {
            reason = "user_stop";
            break;
        }
        if (cfg.duration && now(CLOCK_MONOTONIC) - started >= cfg.duration) {
            reason = "duration_limit";
            break;
        }
        uint64_t vals[MAXN + 1] = {0};
        if (csv) {
            char line[4096];
            if (!fgets(line, sizeof line, csv)) {
                CHECK(feof(csv));
                reason = "dataset_end";
                break;
            }
            char *save = NULL, *p = strtok_r(line, ",\r\n", &save);
            CHECK(p && integer(p, 0, 10000000) == completed);
            for (int i = 1; i <= cfg.n; i++) {
                p = strtok_r(NULL, ",\r\n", &save);
                CHECK(p);
                vals[i] = (uint64_t)integer(p, 0, 1000000000);
            }
            CHECK(!strtok_r(NULL, ",\r\n", &save));
        } else
            for (int i = 1; i <= cfg.n; i++)
                vals[i] = reading(i, completed);
        double rs = now(CLOCK_MONOTONIC);
        if (within == 0) {
            period++;
            period_start = completed;
            memset(expected_bill, 0, sizeof expected_bill);
            Frame f = {.op = START, .a = period, .b = completed};
            all(&f);
            f.op = COMMIT;
            for (int i = 1; i <= cfg.n; i++)
                command(i, &f);
            f.op = REVEAL;
            for (int i = 1; i <= cfg.n; i++)
                command(i, &f);
            f.op = SELECT;
            all(&f);
            for (int j = 0; j < cfg.c; j++)
                fprintf(committees, "%d,%d,%d\n", period, j, esp->members[j]);
        }
        int tariff = cfg.tariffs[completed % cfg.nt];
        Frame f = {.op = ROUND, .a = completed, .b = tariff};
        all(&f);
        uint64_t expected_spatial = 0;
        f.op = GENERATE;
        for (int i = 1; i <= cfg.n; i++) {
            CHECK(vals[i] <= 1000000000ULL);
            expected_spatial += vals[i];
            CHECK(UINT64_MAX - expected_bill[i] >= vals[i] * (uint64_t)tariff);
            expected_bill[i] += vals[i] * (uint64_t)tariff;
            f.len = *cfg.csv ? 8 : 0;
            if (f.len)
                put64(f.data, vals[i]);
            command(i, &f);
        }
        f.len = 0;
        f.op = ROUND_END;
        all(&f);
        f.op = SPATIAL;
        for (int j = 0; j < cfg.c; j++)
            command(esp->members[j], &f);
        result(0, completed, completed, 0, expected_spatial);
        within++;
        completed++;
        if (within == cfg.billing) {
            f.op = BILL;
            for (int j = 0; j < cfg.c; j++)
                command(esp->members[j], &f);
            for (int i = 1; i <= cfg.n; i++)
                result(i, period_start, completed - 1, 0, expected_bill[i]);
            within = 0;
        }
        double elapsed = now(CLOCK_MONOTONIC) - rs;
        total_round += elapsed;
        if (elapsed > max_round)
            max_round = elapsed;
        fprintf(roundtimes, "%d,%d,%d,%.9f\n", completed - 1, period, tariff, elapsed);
        FILE *checkpoint = openlog("checkpoint.tmp", NULL);
        fprintf(checkpoint,
                "{\"completed_rounds\":%d,\"elapsed_seconds\":%.9f,\"protocol_messages_remote\":%"
                "llu,\"protocol_wire_bytes_remote\":%llu,\"accepted_outputs\":%d,\"incomplete_or_"
                "rejected_outputs\":%d}\n",
                completed, now(CLOCK_MONOTONIC) - started, (unsigned long long)packets,
                (unsigned long long)bytes, accepted, failed);
        fclose(checkpoint);
        char cpfrom[1024], cpto[1024];
        path(cpfrom, sizeof cpfrom, "checkpoint.tmp");
        path(cpto, sizeof cpto, "checkpoint.json");
        CHECK(rename(cpfrom, cpto) == 0);
        printf("Round %d complete | period %d | %.3f s | outputs accepted %d, incomplete/rejected "
               "%d\n",
               completed, period, elapsed, accepted, failed);
        fflush(stdout);
        if (cfg.rounds && completed >= cfg.rounds)
            break;
        while (now(CLOCK_MONOTONIC) - rs < cfg.interval && !stopping) {
            check_stop();
            if (cfg.duration && now(CLOCK_MONOTONIC) - started >= cfg.duration)
                break;
            struct timespec t = {0, 50000000};
            nanosleep(&t, NULL);
        }
    }
    /* Explicit experimental truncation: release a prefix subtotal, never a full bill. */
    if (within) {
        Frame f = {.op = BILL};
        for (int j = 0; j < cfg.c; j++)
            command(esp->members[j], &f);
        for (int i = 1; i <= cfg.n; i++)
            result(i, period_start, completed - 1, 1, expected_bill[i]);
    }
    Frame stop = {.op = STOP};
    all(&stop);
    for (int i = 1; i <= cfg.n; i++) {
        int status;
        CHECK(waitpid(children[i], &status, 0) == children[i]);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        close(sockets[i]);
    }
    struct rusage u, ch;
    CHECK(getrusage(RUSAGE_SELF, &u) == 0 && getrusage(RUSAGE_CHILDREN, &ch) == 0);
    FILE *f = openlog("metrics.json", NULL);
    fprintf(
        f,
        "{\n\"stop_reason\":\"%s\",\"completed_rounds\":%d,\"completed_billing_periods\":%d,"
        "\"partial_period_rounds\":%d,\n\"elapsed_seconds_including_shutdown\":%.9f,\"parent_setup_"
        "wall_seconds\":%.9f,\"mean_round_processing_seconds\":%.9f,\"max_round_processing_"
        "seconds\":%.9f,\n\"protocol_messages_remote\":%llu,\"protocol_wire_bytes_remote\":%llu,"
        "\"local_self_messages\":%llu,\"harness_ipc_bytes_including_packet_carriage\":%llu,"
        "\"rejected_messages\":%llu,\n\"accepted_outputs\":%d,\"incomplete_or_rejected_outputs\":%"
        "d,\"parent_max_rss_kib\":%ld,\"largest_child_max_rss_kib\":%ld,\"parent_cpu_seconds\":%."
        "9f,\"children_cpu_seconds\":%.9f,\n\"command_phase_totals\":{",
        reason, completed, completed / cfg.billing, within, now(CLOCK_MONOTONIC) - started,
        setup_wall, completed ? total_round / completed : 0, max_round, (unsigned long long)packets,
        (unsigned long long)bytes, (unsigned long long)local_packets,
        (unsigned long long)control_bytes, (unsigned long long)rejections, accepted, failed,
        u.ru_maxrss, ch.ru_maxrss,
        u.ru_utime.tv_sec + u.ru_utime.tv_usec / 1e6 + u.ru_stime.tv_sec + u.ru_stime.tv_usec / 1e6,
        ch.ru_utime.tv_sec + ch.ru_utime.tv_usec / 1e6 + ch.ru_stime.tv_sec +
            ch.ru_stime.tv_usec / 1e6);
    for (int i = 1; i <= STOP; i++) {
        fprintf(f, "%s\n\"%s\":{\"calls\":%llu,\"wall_seconds_sum\":%.9f,\"cpu_seconds_sum\":%.9f}",
                i > 1 ? "," : "", phase_names[i], (unsigned long long)phase_count[i], phase_wall[i],
                phase_cpu[i]);
    }
    fputs("\n},\n\"reconstruction_totals\":{", f);
    for (int i = 0; i < 2; i++) {
        fprintf(f, "%s\"%s\":{\"calls\":%u,\"wall_seconds\":%.9f,\"cpu_seconds\":%.9f}",
                i ? "," : "", i ? "billing" : "spatial", reconstruct_count[i], reconstruct_wall[i],
                reconstruct_cpu[i]);
    }
    fputs("}}\n", f);
    fclose(f);
    fclose(messages);
    fclose(results);
    fclose(committees);
    fclose(roundtimes);
    fclose(esp->log);
    fclose(esp->timing);
    if (csv)
        fclose(csv);
    printf("Saved %d completed rounds. %d partial billing rounds. Results: %s\n", completed, within,
           cfg.out);
    clean_exit = 1;
    return 0;
}
