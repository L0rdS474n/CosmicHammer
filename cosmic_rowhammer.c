/*
 * CosmicRowhammer - Distributed Cosmic Ray Bit Flip Observer
 * Author: Dr. Antonio Nappa / FuzzSociety
 * Version: 0.2.0
 *
 * Allocates a 512 MB sandboxed memory arena divided into five typed
 * sentinel regions — including a PTE simulation layer — and continuously
 * scans for bit flips induced by cosmic ray Single Event Upsets (SEUs).
 *
 * Each flip is classified by exploitability primitive, accumulated into a
 * 72-hour anonymised report, and optionally POSTed to a remote endpoint.
 *
 * Compile (no curl):  gcc -O2 -Wall -o cosmic_rowhammer cosmic_rowhammer.c -lm
 * Compile (curl):     gcc -O2 -Wall -DWITH_CURL -o cosmic_rowhammer cosmic_rowhammer.c -lm -lcurl
 * Run:                sudo ./cosmic_rowhammer [options]
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <math.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>

#ifdef WITH_CURL
#  include <curl/curl.h>
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * Configuration
 * ═══════════════════════════════════════════════════════════════════════════ */

#define ARENA_SIZE        (512UL * 1024 * 1024)   /* 512 MB total             */
#define REGION_COUNT      5                        /* five typed regions       */
#define REGION_SIZE       (ARENA_SIZE / REGION_COUNT) /* ~102 MB each         */
#define SCAN_INTERVAL_S   5                        /* seconds between scans    */
#define MAX_FLIPS         8192                     /* ring buffer capacity     */
#define REPORT_WINDOW_S   (72 * 3600)              /* 72-hour report window    */
#define VERSION           "0.2.0"

/* ═══════════════════════════════════════════════════════════════════════════
 * x86-64 PTE Bit Definitions  (Intel SDM Vol.3A §4.5)
 *
 *  63      NX   — No-Execute  (1 = non-executable)
 *  51:12   PA   — Physical address bits
 *  11:9    AVL  — Available for OS use
 *  8       G    — Global page
 *  7       PAT  — Page Attribute Table index
 *  6       D    — Dirty
 *  5       A    — Accessed
 *  4       PCD  — Page-level Cache Disable
 *  3       PWT  — Page-level Write-Through
 *  2       U/S  — User(1) / Supervisor(0)
 *  1       R/W  — Read-Write(1) / Read-Only(0)
 *  0       P    — Present
 * ═══════════════════════════════════════════════════════════════════════════ */

#define PTE_BIT_P       0   /* Present              */
#define PTE_BIT_RW      1   /* Read/Write           */
#define PTE_BIT_US      2   /* User/Supervisor      */
#define PTE_BIT_PWT     3   /* Write-Through        */
#define PTE_BIT_PCD     4   /* Cache Disable        */
#define PTE_BIT_A       5   /* Accessed             */
#define PTE_BIT_D       6   /* Dirty                */
#define PTE_BIT_NX      63  /* No-Execute           */
#define PTE_PA_SHIFT    12  /* Physical addr starts at bit 12 */
#define PTE_PA_MASK     UINT64_C(0x000FFFFFFFFF000) /* bits 51:12 */

/*
 * Canonical "safe" PTE value used to fill the PTE_SIM region:
 *   Present=1, RW=1, User=1, Accessed=0, Dirty=0, NX=1
 *   Physical address = 0x000000001A000 (arbitrary, page-aligned)
 *
 *   NX(63)=1 | PA=0x1A000 | U/S(2)=1 | R/W(1)=1 | P(0)=1
 *   = 0x8000000001A000_07
 */
#define FILL_PTE_SAFE   UINT64_C(0x8000000001A00007)

/* ═══════════════════════════════════════════════════════════════════════════
 * Sentinel Patterns
 * ═══════════════════════════════════════════════════════════════════════════ */

#define FILL_POINTER    UINT64_C(0x00007FFF12345678)  /* canonical user-space ptr  */
#define FILL_RETADDR    UINT64_C(0x00007FFF87654321)  /* canonical .text ret addr  */
#define FILL_PERMISSION UINT64_C(0x0000000000000004)  /* permission/capability bit */
#define FILL_DATA_A     UINT64_C(0xAAAAAAAAAAAAAAAA)
#define FILL_DATA_B     UINT64_C(0x5555555555555555)

/* ═══════════════════════════════════════════════════════════════════════════
 * Region & Flip Types
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef enum {
    REGION_POINTER    = 0,
    REGION_RETADDR    = 1,
    REGION_PERMISSION = 2,
    REGION_DATA       = 3,
    REGION_PTE_SIM    = 4,
} RegionType;

static const char *region_names[] = {
    "POINTER", "RETADDR", "PERMISSION", "DATA", "PTE_SIM"
};

typedef enum {
    /* Generic classes */
    FLIP_BENIGN           = 0,
    FLIP_DATA_CORRUPT     = 1,
    FLIP_PTR_HIJACK       = 2,
    FLIP_PRIV_ESC         = 3,
    FLIP_CODE_PAGE        = 4,
    /* PTE-specific classes */
    PTE_PRESENT_CLEAR     = 5,  /* P:  1→0  page fault / DoS            */
    PTE_WRITE_SET         = 6,  /* RW: 0→1  write to read-only mapping  */
    PTE_NX_CLEAR          = 7,  /* NX: 1→0  non-exec becomes executable */
    PTE_PHYS_CORRUPT      = 8,  /* PA: any  arbitrary physical alias     */
    PTE_SUPERVISOR_ESC    = 9,  /* US: 1→0  user page → supervisor only */
    FLIP_CLASS_COUNT      = 10,
} FlipClass;

static const char *flip_class_names[] = {
    "BENIGN", "DATA_CORRUPTION", "PTR_HIJACK", "PRIV_ESC", "CODE_PAGE",
    "PTE_PRESENT_CLEAR", "PTE_WRITE_SET", "PTE_NX_CLEAR",
    "PTE_PHYS_CORRUPT",  "PTE_SUPERVISOR_ESC"
};

/* Human-readable exploit primitive description */
static const char *flip_class_desc[] = {
    "No control-flow impact",
    "Memory corruption, no CFI bypass",
    "Potential control-flow hijack via pointer corruption",
    "Potential privilege escalation via flag corruption",
    "Return address corruption → code execution",
    "PTE Present bit cleared → page fault / DoS",
    "PTE Write bit set → write to read-only mapping",
    "PTE NX bit cleared → heap/stack becomes executable",
    "PTE physical address bits corrupted → arbitrary memory alias",
    "PTE User bit cleared → user page becomes supervisor-only"
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Flip Event
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t   timestamp;      /* unix epoch                           */
    size_t     offset;         /* byte offset within arena             */
    uint8_t    bit_position;   /* 0-63 within the 64-bit word          */
    uint64_t   expected;       /* sentinel value                       */
    uint64_t   observed;       /* actual value read back               */
    int        direction;      /* +1 = 0→1 ,  -1 = 1→0               */
    int        n_bits;         /* number of bits that flipped          */
    RegionType region;
    FlipClass  flip_class;
    uint32_t   dram_row;       /* estimated DRAM row  (offset / 8192)  */
} FlipEvent;

/* ═══════════════════════════════════════════════════════════════════════════
 * 72-hour Report Accumulator
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    time_t     window_start;
    time_t     window_end;
    uint64_t   scan_cycles;
    uint64_t   total_bits;
    uint64_t   zero_to_one;
    uint64_t   one_to_zero;
    uint64_t   multi_bit_events;
    uint64_t   dram_rows_seen;   /* unique rows — approximated          */
    uint64_t   by_class[FLIP_CLASS_COUNT];
    uint64_t   by_region[REGION_COUNT];
} ReportWindow;

/* ═══════════════════════════════════════════════════════════════════════════
 * Global State
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint8_t     *arena           = NULL;
static FlipEvent    flip_ring[MAX_FLIPS];
static size_t       flip_head       = 0;
static size_t       flip_total      = 0;
static volatile int running         = 1;
static char         report_url[512] = {0};
static int          opt_altitude    = -1;   /* metres, -1 = not set  */
static int          opt_interval    = SCAN_INTERVAL_S;
static ReportWindow report_win      = {0};

/* ═══════════════════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void sig_handler(int sig) { (void)sig; running = 0; }

static const char *ts_now(char *buf, size_t n) {
    time_t t = time(NULL);
    strftime(buf, n, "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    return buf;
}

static int count_flipped_bits(uint64_t a, uint64_t b) {
    return __builtin_popcountll(a ^ b);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Arena Allocation
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint8_t *alloc_arena(void) {
    void *p = mmap(NULL, ARENA_SIZE,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                   -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); return NULL; }

#ifdef MADV_HUGEPAGE
    madvise(p, ARENA_SIZE, MADV_HUGEPAGE);
#endif

    if (mlock(p, ARENA_SIZE) != 0)
        fprintf(stderr, "[!] mlock failed (%s) — run as root for reliable results\n",
                strerror(errno));

    return (uint8_t *)p;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PTE Simulation Fill
 *
 * Each 64-bit word in the PTE_SIM region is a structurally valid x86-64
 * 4KB page PTE with a unique-per-word physical address derived from its
 * index, so we can distinguish corruption of the PA field from bit flips
 * in the control bits.
 *
 *   word[i] = NX(63)=1 | phys_pfn(i) << 12 | U/S(2)=1 | R/W(1)=1 | P(0)=1
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Fixed control bits for the canonical safe PTE (NX=1, U=1, RW=1, P=1) */
#define PTE_CTRL_BITS   UINT64_C(0x8000000000000007)
/* Mask covering the physical-address field bits [51:12] */
#define PTE_ADDR_MASK   UINT64_C(0x000FFFFFFFFF000)

static inline uint64_t pte_for_index(size_t i) {
    /* Physical PFN cycles through a 20-bit space — avoids bit collisions
     * with control bits. Shift left 12 to place in PA field.            */
    uint64_t pfn = (uint64_t)(i & 0xFFFFF);       /* 20-bit PFN           */
    return PTE_CTRL_BITS | (pfn << PTE_PA_SHIFT);
}

static void fill_arena(uint8_t *base) {
    size_t words = REGION_SIZE / sizeof(uint64_t);
    uint64_t *r;

    r = (uint64_t *)(base + REGION_POINTER    * REGION_SIZE);
    for (size_t i = 0; i < words; i++) r[i] = FILL_POINTER;

    r = (uint64_t *)(base + REGION_RETADDR    * REGION_SIZE);
    for (size_t i = 0; i < words; i++) r[i] = FILL_RETADDR;

    r = (uint64_t *)(base + REGION_PERMISSION * REGION_SIZE);
    for (size_t i = 0; i < words; i++) r[i] = FILL_PERMISSION;

    r = (uint64_t *)(base + REGION_DATA       * REGION_SIZE);
    for (size_t i = 0; i < words; i++) r[i] = (i & 1) ? FILL_DATA_B : FILL_DATA_A;

    /* PTE_SIM: unique per-word PTE so physical-address flips are detectable */
    r = (uint64_t *)(base + REGION_PTE_SIM    * REGION_SIZE);
    for (size_t i = 0; i < words; i++) r[i] = pte_for_index(i);

    __sync_synchronize();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Expected Value Lookup
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint64_t expected_at(size_t byte_off) {
    RegionType r = (RegionType)(byte_off / REGION_SIZE);
    size_t word_idx = (byte_off - r * REGION_SIZE) / sizeof(uint64_t);
    switch (r) {
        case REGION_POINTER:    return FILL_POINTER;
        case REGION_RETADDR:    return FILL_RETADDR;
        case REGION_PERMISSION: return FILL_PERMISSION;
        case REGION_DATA:       return (word_idx & 1) ? FILL_DATA_B : FILL_DATA_A;
        case REGION_PTE_SIM:    return pte_for_index(word_idx);
        default:                return 0;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PTE Flip Classifier
 *
 * Receives the expected (canonical) PTE and the observed (flipped) PTE.
 * Returns the most severe applicable PTE_* class.
 * ═══════════════════════════════════════════════════════════════════════════ */

static FlipClass classify_pte_flip(uint64_t expected, uint64_t observed) {
    uint64_t diff = expected ^ observed;

    /* NX bit cleared: 1→0 → non-exec page becomes executable */
    if ((diff >> PTE_BIT_NX) & 1) {
        if (!((observed >> PTE_BIT_NX) & 1))   /* was 1, now 0 */
            return PTE_NX_CLEAR;
    }

    /* Physical address bits corrupted → arbitrary memory aliasing */
    if (diff & PTE_ADDR_MASK)
        return PTE_PHYS_CORRUPT;

    /* Present bit cleared: 1→0 → page-fault loop / DoS */
    if ((diff >> PTE_BIT_P) & 1) {
        if (!((observed >> PTE_BIT_P) & 1))
            return PTE_PRESENT_CLEAR;
    }

    /* Write bit set: 0→1 → RO mapping becomes writable */
    if ((diff >> PTE_BIT_RW) & 1) {
        if ((observed >> PTE_BIT_RW) & 1)
            return PTE_WRITE_SET;
    }

    /* User/Supervisor bit cleared: 1→0 → user page locked out */
    if ((diff >> PTE_BIT_US) & 1) {
        if (!((observed >> PTE_BIT_US) & 1))
            return PTE_SUPERVISOR_ESC;
    }

    /* Anything else in a PTE is still a corruption */
    return FLIP_DATA_CORRUPT;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Generic Flip Classifier
 * ═══════════════════════════════════════════════════════════════════════════ */

static FlipClass classify_flip(RegionType region, uint64_t expected,
                                uint64_t observed, int direction, int n_bits) {
    /* Multi-bit single-word flips are statistically improbable for cosmic
     * rays — flag as benign / noise to avoid false positives.            */
    if (n_bits > 2) return FLIP_BENIGN;

    switch (region) {
        case REGION_PTE_SIM:
            return classify_pte_flip(expected, observed);
        case REGION_POINTER:
            return (direction > 0) ? FLIP_PTR_HIJACK : FLIP_DATA_CORRUPT;
        case REGION_RETADDR:
            return FLIP_CODE_PAGE;
        case REGION_PERMISSION:
            return (direction > 0) ? FLIP_PRIV_ESC : FLIP_BENIGN;
        case REGION_DATA:
        default:
            return FLIP_DATA_CORRUPT;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Read Spray  (observation — no writes)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void spray_pass(uint8_t *base) {
    volatile uint64_t *p = (volatile uint64_t *)base;
    size_t stride = 4096 / sizeof(uint64_t);
    size_t total  = ARENA_SIZE / sizeof(uint64_t);
    for (size_t i = 0; i < total; i += stride) (void)p[i];
    __sync_synchronize();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Arena Scan
 * ═══════════════════════════════════════════════════════════════════════════ */

static size_t scan_arena(uint8_t *base) {
    uint64_t *words = (uint64_t *)base;
    size_t total    = ARENA_SIZE / sizeof(uint64_t);
    size_t found    = 0;
    char   ts[32];
    ts_now(ts, sizeof(ts));

    for (size_t i = 0; i < total; i++) {
        size_t   byte_off = i * sizeof(uint64_t);
        uint64_t expected = expected_at(byte_off);
        uint64_t observed = words[i];

        if (__builtin_expect(observed == expected, 1)) continue;

        /* ── Flip detected ──────────────────────────────────────────── */
        uint64_t   diff    = expected ^ observed;
        uint8_t    bit_pos = (uint8_t)__builtin_ctzll(diff);
        int        dir     = ((observed >> bit_pos) & 1) ? +1 : -1;
        int        n_bits  = count_flipped_bits(expected, observed);
        RegionType rtype   = (RegionType)(byte_off / REGION_SIZE);
        FlipClass  fclass  = classify_flip(rtype, expected, observed, dir, n_bits);
        uint32_t   drow    = (uint32_t)(byte_off / 8192);

        FlipEvent ev = {
            .timestamp    = (uint64_t)time(NULL),
            .offset       = byte_off,
            .bit_position = bit_pos,
            .expected     = expected,
            .observed     = observed,
            .direction    = dir,
            .n_bits       = n_bits,
            .region       = rtype,
            .flip_class   = fclass,
            .dram_row     = drow,
        };

        flip_ring[flip_head % MAX_FLIPS] = ev;
        flip_head++;
        flip_total++;
        found++;

        /* ── Update report accumulator ──────────────────────────────── */
        report_win.total_bits += (uint64_t)n_bits;
        if (dir > 0) report_win.zero_to_one++; else report_win.one_to_zero++;
        if (n_bits > 1) report_win.multi_bit_events++;
        report_win.by_class[fclass]++;
        report_win.by_region[rtype]++;
        report_win.dram_rows_seen++;    /* crude; dedup can be added later */

        /* ── Console output ─────────────────────────────────────────── */
        printf("[%s] ══ FLIP DETECTED ══\n"
               "  offset     = 0x%010zx  (DRAM row ~%u)\n"
               "  bit        = %2u  direction = %s  n_bits = %d\n"
               "  expected   = 0x%016llx\n"
               "  observed   = 0x%016llx\n"
               "  region     = %s\n"
               "  class      = %s\n"
               "  primitive  = %s\n\n",
               ts,
               byte_off, drow,
               bit_pos, (dir > 0) ? "0→1" : "1→0", n_bits,
               (unsigned long long)expected,
               (unsigned long long)observed,
               region_names[rtype],
               flip_class_names[fclass],
               flip_class_desc[fclass]);

        /* If this is a PTE flip, add PTE-specific detail */
        if (rtype == REGION_PTE_SIM) {
            printf("  [PTE] P=%llu RW=%llu U/S=%llu NX=%llu  PA=0x%09llx\n"
                   "        flipped_bits: P=%llu RW=%llu U/S=%llu NX=%llu PA_bits=%llu\n\n",
                   (unsigned long long)((observed >> PTE_BIT_P)  & 1),
                   (unsigned long long)((observed >> PTE_BIT_RW) & 1),
                   (unsigned long long)((observed >> PTE_BIT_US) & 1),
                   (unsigned long long)((observed >> PTE_BIT_NX) & 1),
                   (unsigned long long)((observed & PTE_ADDR_MASK) >> PTE_PA_SHIFT),
                   (unsigned long long)((diff >> PTE_BIT_P)  & 1),
                   (unsigned long long)((diff >> PTE_BIT_RW) & 1),
                   (unsigned long long)((diff >> PTE_BIT_US) & 1),
                   (unsigned long long)((diff >> PTE_BIT_NX) & 1),
                   (unsigned long long)(!!(diff & PTE_ADDR_MASK)));
        }

        fflush(stdout);

        /* Restore sentinel */
        words[i] = expected;
    }

    return found;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * JSON Report Builder
 * ═══════════════════════════════════════════════════════════════════════════ */

static void build_report_json(char *buf, size_t bufsz, const ReportWindow *w) {
    struct utsname u; uname(&u);
    struct sysinfo si; sysinfo(&si);
    char wstart[32], wend[32];

    strftime(wstart, sizeof(wstart), "%Y-%m-%dT%H:%M:%SZ", gmtime(&w->window_start));
    strftime(wend,   sizeof(wend),   "%Y-%m-%dT%H:%M:%SZ", gmtime(&w->window_end));

    /* Detect ECC heuristically (sysfs) — best-effort */
    int ecc = 0;
    FILE *f = fopen("/sys/devices/system/edac/mc/mc0/ce_count", "r");
    if (f) { ecc = 1; fclose(f); }

    snprintf(buf, bufsz,
        "{\n"
        "  \"schema_version\": \"1.0\",\n"
        "  \"window_hours\": 72,\n"
        "  \"window_start\": \"%s\",\n"
        "  \"window_end\":   \"%s\",\n"
        "  \"platform\": {\n"
        "    \"arch\":     \"%s\",\n"
        "    \"os\":       \"%s %s\",\n"
        "    \"ram_mb\":   %lu,\n"
        "    \"ecc\":      %s,\n"
        "    \"altitude_m\": %s\n"
        "  },\n"
        "  \"flip_totals\": {\n"
        "    \"total_bits_observed\": %llu,\n"
        "    \"zero_to_one\":         %llu,\n"
        "    \"one_to_zero\":         %llu\n"
        "  },\n"
        "  \"by_class\": {\n"
        "    \"BENIGN\":              %llu,\n"
        "    \"DATA_CORRUPTION\":     %llu,\n"
        "    \"PTR_HIJACK\":          %llu,\n"
        "    \"PRIV_ESC\":            %llu,\n"
        "    \"CODE_PAGE\":           %llu,\n"
        "    \"PTE_PRESENT_CLEAR\":   %llu,\n"
        "    \"PTE_WRITE_SET\":        %llu,\n"
        "    \"PTE_NX_CLEAR\":         %llu,\n"
        "    \"PTE_PHYS_CORRUPT\":     %llu,\n"
        "    \"PTE_SUPERVISOR_ESC\":   %llu\n"
        "  },\n"
        "  \"by_region\": {\n"
        "    \"POINTER\":    %llu,\n"
        "    \"RETADDR\":    %llu,\n"
        "    \"PERMISSION\": %llu,\n"
        "    \"DATA\":       %llu,\n"
        "    \"PTE_SIM\":    %llu\n"
        "  },\n"
        "  \"dram_rows_affected\": %llu,\n"
        "  \"multi_bit_events\":   %llu,\n"
        "  \"scan_cycles\":        %llu\n"
        "}\n",
        wstart, wend,
        u.machine,
        u.sysname, u.release,
        si.totalram / (1024*1024),
        ecc ? "true" : "false",
        (opt_altitude >= 0) ? ({
            static char abuf[16];
            snprintf(abuf, sizeof(abuf), "%d", opt_altitude);
            abuf; }) : "null",
        /* flip_totals */
        (unsigned long long)w->total_bits,
        (unsigned long long)w->zero_to_one,
        (unsigned long long)w->one_to_zero,
        /* by_class */
        (unsigned long long)w->by_class[FLIP_BENIGN],
        (unsigned long long)w->by_class[FLIP_DATA_CORRUPT],
        (unsigned long long)w->by_class[FLIP_PTR_HIJACK],
        (unsigned long long)w->by_class[FLIP_PRIV_ESC],
        (unsigned long long)w->by_class[FLIP_CODE_PAGE],
        (unsigned long long)w->by_class[PTE_PRESENT_CLEAR],
        (unsigned long long)w->by_class[PTE_WRITE_SET],
        (unsigned long long)w->by_class[PTE_NX_CLEAR],
        (unsigned long long)w->by_class[PTE_PHYS_CORRUPT],
        (unsigned long long)w->by_class[PTE_SUPERVISOR_ESC],
        /* by_region */
        (unsigned long long)w->by_region[REGION_POINTER],
        (unsigned long long)w->by_region[REGION_RETADDR],
        (unsigned long long)w->by_region[REGION_PERMISSION],
        (unsigned long long)w->by_region[REGION_DATA],
        (unsigned long long)w->by_region[REGION_PTE_SIM],
        /* misc */
        (unsigned long long)w->dram_rows_seen,
        (unsigned long long)w->multi_bit_events,
        (unsigned long long)w->scan_cycles
    );
}

/* ─── Dump JSON to file ──────────────────────────────────────────────────── */

static void dump_report_to_file(const char *json) {
    char fname[64];
    snprintf(fname, sizeof(fname), "cr_report_%llu.json", (unsigned long long)time(NULL));
    FILE *f = fopen(fname, "w");
    if (!f) { perror("fopen report"); return; }
    fputs(json, f);
    fclose(f);
    printf("[*] Report saved → %s\n", fname);
}

/* ─── POST JSON via libcurl (optional) ──────────────────────────────────── */

#ifdef WITH_CURL
static void post_report(const char *json, const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) return;

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "User-Agent: CosmicRowhammer/" VERSION);

    curl_easy_setopt(curl, CURLOPT_URL,            url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     json);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     hdrs);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        fprintf(stderr, "[!] Report POST failed: %s\n", curl_easy_strerror(res));
    else
        printf("[+] Report POSTed to %s\n", url);

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
}
#else
static void post_report(const char *json, const char *url) {
    (void)json; (void)url;
    printf("[!] Built without curl — remote reporting disabled.\n"
           "    Recompile with: make WITH_CURL=1\n");
}
#endif

/* ─── Emit 72-hour report ────────────────────────────────────────────────── */

static void emit_report(void) {
    static char json[8192];
    report_win.window_end = time(NULL);
    build_report_json(json, sizeof(json), &report_win);

    printf("\n╔══════════════════════════════════════╗\n"
           "║      72-HOUR REPORT  (anonymised)    ║\n"
           "╚══════════════════════════════════════╝\n%s\n", json);

    dump_report_to_file(json);

    if (report_url[0])
        post_report(json, report_url);

    /* Reset window */
    memset(&report_win, 0, sizeof(report_win));
    report_win.window_start = time(NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * System Info Banner
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_banner(void) {
    struct utsname u; uname(&u);
    struct sysinfo si; sysinfo(&si);

    printf("╔═══════════════════════════════════════════════════╗\n"
           "║   ☄  CosmicRowhammer v%-6s  —  FuzzSociety      ║\n"
           "╚═══════════════════════════════════════════════════╝\n"
           "  Host      %s %s %s\n"
           "  RAM       %lu MB\n"
           "  Arena     512 MB  /  5 regions  (~102 MB each)\n"
           "  Regions   POINTER | RETADDR | PERMISSION | DATA | PTE_SIM\n"
           "  Interval  %d s\n"
           "  Reporting every 72 h%s\n"
           "  Curl      %s\n",
           VERSION,
           u.sysname, u.release, u.machine,
           si.totalram / (1024*1024),
           opt_interval,
           report_url[0] ? " → remote POST" : " → local JSON file",
#ifdef WITH_CURL
           "enabled"
#else
           "disabled (recompile with WITH_CURL=1)"
#endif
    );
    if (opt_altitude >= 0)
        printf("  Altitude  %d m\n", opt_altitude);
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Session Stats
 * ═══════════════════════════════════════════════════════════════════════════ */

static void print_stats(time_t start) {
    time_t elapsed = time(NULL) - start;
    size_t counts[FLIP_CLASS_COUNT] = {0};
    size_t n = (flip_total < MAX_FLIPS) ? flip_total : MAX_FLIPS;
    for (size_t i = 0; i < n; i++) counts[flip_ring[i].flip_class]++;

    printf("\n─── Session Stats ───────────────────────────────────\n"
           "  Runtime        %ld s\n"
           "  Total flips    %zu\n", (long)elapsed, flip_total);
    for (int c = 0; c < FLIP_CLASS_COUNT; c++)
        if (counts[c])
            printf("  %-22s %zu\n", flip_class_names[c], counts[c]);
    printf("─────────────────────────────────────────────────────\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Argument Parser
 * ═══════════════════════════════════════════════════════════════════════════ */

static void parse_args(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--report-url") && i+1 < argc)
            snprintf(report_url, sizeof(report_url), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--altitude") && i+1 < argc)
            opt_altitude = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--interval") && i+1 < argc)
            opt_interval = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--help")) {
            printf("Usage: cosmic_rowhammer [OPTIONS]\n"
                   "  --report-url <url>   POST anonymised 72h JSON report\n"
                   "  --altitude   <m>     Your altitude in metres (optional)\n"
                   "  --interval   <s>     Scan interval in seconds (default %d)\n",
                   SCAN_INTERVAL_S);
            exit(0);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[]) {
    parse_args(argc, argv);

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    print_banner();

    printf("[*] Allocating 512 MB arena...\n");
    arena = alloc_arena();
    if (!arena) { fprintf(stderr, "[-] Arena allocation failed.\n"); return 1; }
    printf("[+] Arena @ %p\n", (void *)arena);

    printf("[*] Writing sentinel patterns + PTE simulation region...\n");
    fill_arena(arena);
    printf("[+] Arena ready.\n\n");

    time_t start  = time(NULL);
    time_t last_r = start;
    size_t scans  = 0;
    report_win.window_start = start;

    while (running) {
        spray_pass(arena);
        sleep((unsigned)opt_interval);

        char ts[32]; ts_now(ts, sizeof(ts));
        size_t found = scan_arena(arena);
        scans++;
        report_win.scan_cycles++;

        if (!found) {
            printf("[%s] Scan #%zu — no flips\n", ts, scans);
            fflush(stdout);
        }

        /* 72-hour report window */
        if (time(NULL) - last_r >= REPORT_WINDOW_S) {
            emit_report();
            last_r = time(NULL);
        }
    }

    /* Final partial-window report */
    emit_report();
    print_stats(start);

    munlock(arena, ARENA_SIZE);
    munmap(arena,  ARENA_SIZE);
    printf("[*] Arena released. Goodbye.\n");
    return 0;
}
