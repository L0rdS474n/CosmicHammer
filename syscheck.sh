#!/usr/bin/env bash
# CosmicRowhammer — x86 System Pre-flight Checks
# Run this before starting cosmic_rowhammer to verify the environment.

set -euo pipefail

PASS=0; WARN=0; FAIL=0
RED='\033[1;31m'; YEL='\033[1;33m'; GRN='\033[1;32m'; CYN='\033[1;36m'; RST='\033[0m'

pass() { echo -e "  [${GRN}PASS${RST}] $*"; PASS=$(( PASS + 1 )); }
warn() { echo -e "  [${YEL}WARN${RST}] $*"; WARN=$(( WARN + 1 )); }
fail() { echo -e "  [${RED}FAIL${RST}] $*"; FAIL=$(( FAIL + 1 )); }
info() { echo -e "  [${CYN}INFO${RST}] $*"; }
section() { echo -e "\n── $* ──────────────────────────────────────────────"; }

echo "╔═══════════════════════════════════════════════════╗"
echo "║   ☄  CosmicRowhammer  —  x86 Pre-flight Check    ║"
echo "╚═══════════════════════════════════════════════════╝"

# Detect container environment early — used by multiple checks below
virt="bare metal"
[[ -f /.dockerenv ]] && virt="docker"
grep -qE "docker|lxc|containerd|kubepods" /proc/1/cgroup 2>/dev/null && virt="docker"
if command -v systemd-detect-virt &>/dev/null; then
    sdv=$(systemd-detect-virt --vm 2>/dev/null || true)
    [[ -n "$sdv" && "$sdv" != "none" ]] && virt="vm:$sdv"
fi



# ── 0. Root / privilege ──────────────────────────────────────────────────────
section "Privileges"

if [[ $EUID -eq 0 ]]; then
    pass "Running as root"
else
    fail "Not root — mlock, MSR reads, and EDAC access will fail"
fi

# CAP_IPC_LOCK
if grep -q "CapEff" /proc/self/status 2>/dev/null; then
    capeff=$(awk '/CapEff/{print $2}' /proc/self/status)
    # IPC_LOCK is bit 14
    if (( (0x$capeff >> 14) & 1 )); then
        pass "CAP_IPC_LOCK effective"
    else
        warn "CAP_IPC_LOCK not set — add --cap-add IPC_LOCK to docker run"
    fi
fi

# RLIMIT_MEMLOCK
memlock_kb=$(ulimit -l)
arena_kb=$(( 512 * 1024 ))
if [[ "$memlock_kb" == "unlimited" ]]; then
    pass "RLIMIT_MEMLOCK = unlimited"
elif (( memlock_kb >= arena_kb )); then
    pass "RLIMIT_MEMLOCK = ${memlock_kb} kB (>= 512 MB arena)"
else
    fail "RLIMIT_MEMLOCK = ${memlock_kb} kB — arena needs 524288 kB (512 MB)"
    fail "  Fix: docker run --ulimit memlock=-1  or  ulimit -l unlimited"
fi

# ── 1. CPU identity ──────────────────────────────────────────────────────────
section "CPU Identity"

vendor=$(awk -F: '/vendor_id/{print $2; exit}' /proc/cpuinfo | tr -d ' ')
model=$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo | sed 's/^ //')
family=$(awk -F: '/cpu family/{print $2; exit}' /proc/cpuinfo | tr -d ' ')
stepping=$(awk -F: '/stepping/{print $2; exit}' /proc/cpuinfo | tr -d ' ')
microcode=$(awk -F: '/microcode/{print $2; exit}' /proc/cpuinfo | tr -d ' ')
phys_bits=$(awk -F: '/address sizes/{print $2; exit}' /proc/cpuinfo | awk '{print $1}')
virt_bits=$(awk -F: '/address sizes/{print $2; exit}' /proc/cpuinfo | awk '{print $4}')

info "Vendor:    $vendor"
info "Model:     $model"
info "Family:    $family  Stepping: $stepping"
info "Microcode: ${microcode:-unavailable}"

# Microcode version — informational only, does not affect SEU detection
cpu_model_hex=$(awk -F: '/model\t/{gsub(/ /,"",$2); printf "%02x", $2+0; exit}' /proc/cpuinfo)
if [[ "$family" == "6" && "$cpu_model_hex" == "9e" && -n "$microcode" ]]; then
    ucode_dec=$(printf "%d" "$microcode" 2>/dev/null || echo 0)
    if (( ucode_dec >= 0xf4 )); then
        pass "Microcode ${microcode} — current for Kaby Lake (906E9)"
    else
        warn "Microcode ${microcode} not current for Kaby Lake (latest: 0xf4) — no impact on SEU detection"
        warn "  Update on host when convenient: apt install intel-microcode && update-initramfs -u"
    fi
fi

# Physical address width check.
# PTE_PA_MASK covers bits [51:12].  pte_for_index() uses a 20-bit PFN
# sitting in bits [31:12] — so any CPU with >= 36-bit PA is fully safe.
# Bits above the CPU's actual PA width are reserved-zero in real PTEs;
# a cosmic-ray flip in those bits is still caught as PTE_PHYS_CORRUPT.
if [[ -n "$phys_bits" ]]; then
    if (( phys_bits >= 39 )); then
        pass "Physical addr width: ${phys_bits} bits  (pte_for_index PFN fits in bits [31:12] — fully safe)"
    elif (( phys_bits >= 36 )); then
        warn "Physical addr width: ${phys_bits} bits  (< 39 — unusual, but pte_for_index 20-bit PFN still safe)"
    else
        fail "Physical addr width: ${phys_bits} bits  (< 36 — PFN field may collide with PTE control bits)"
    fi
    info "Virtual addr width:  ${virt_bits} bits"
fi

# ── 2. MSR access ────────────────────────────────────────────────────────────
section "MSR Access (/dev/cpu/*/msr)"

if [[ -c /dev/cpu/0/msr ]]; then
    pass "/dev/cpu/0/msr accessible"

    # MCG_CAP (0x179) — number of MCA banks
    mcg_cap=$(dd if=/dev/cpu/0/msr bs=8 count=1 skip=$(( 0x179 )) 2>/dev/null \
              | od -A n -t u8 | tr -d ' ' || echo "")
    if [[ -n "$mcg_cap" ]]; then
        mca_banks=$(( mcg_cap & 0xFF ))
        info "MCA banks (MCG_CAP[7:0]): $mca_banks"
        (( mca_banks > 0 )) && pass "MCA bank count readable: $mca_banks banks" \
                             || warn "MCA bank count = 0 (virtualised or disabled)"
    fi

    # IA32_MCG_STATUS (0x17A) — check for in-progress MCE
    mcg_status=$(dd if=/dev/cpu/0/msr bs=8 count=1 skip=$(( 0x17A )) 2>/dev/null \
                 | od -A n -t u8 | tr -d ' ' || echo "")
    if [[ -n "$mcg_status" ]] && (( mcg_status != 0 )); then
        warn "MCG_STATUS=0x$(printf '%x' $mcg_status) non-zero — MCE in progress or pending"
    elif [[ -n "$mcg_status" ]]; then
        pass "MCG_STATUS = 0 (no pending MCE)"
    fi

    # SMI counter — MSR_SMI_COUNT (0x34) on Intel
    # SMI interrupts pause all CPUs and can corrupt timing / cause false-positives
    smi_before=$(dd if=/dev/cpu/0/msr bs=8 count=1 skip=$(( 0x34 )) 2>/dev/null \
                 | od -A n -t u8 | tr -d ' ' || echo "")
    if [[ -n "$smi_before" ]]; then
        sleep 1
        smi_after=$(dd if=/dev/cpu/0/msr bs=8 count=1 skip=$(( 0x34 )) 2>/dev/null \
                    | od -A n -t u8 | tr -d ' ' || echo "")
        smi_delta=$(( smi_after - smi_before ))
        info "SMI counter: before=$smi_before  after=$smi_after  delta=$smi_delta"
        if (( smi_delta == 0 )); then
            pass "SMI rate: 0 SMIs/s observed  (good — SMIs pause all CPUs)"
        elif (( smi_delta <= 2 )); then
            warn "SMI rate: ${smi_delta} SMI/s  (low — platform management traffic, usually benign)"
        else
            fail "SMI rate: ${smi_delta} SMI/s  (high — SMIs can cause multi-word transient reads)"
        fi
    else
        info "SMI counter MSR 0x34 not readable (AMD or paravirt)"
    fi
else
    if [[ "$virt" == "docker" ]]; then
        info "/dev/cpu/0/msr not exposed — add to docker run for MCA/SMI checks:"
        info "  --device /dev/cpu/0/msr (and modprobe msr on the host first)"
    else
        warn "/dev/cpu/0/msr not present — load module: modprobe msr"
    fi
fi

# ── 3. ECC / EDAC ────────────────────────────────────────────────────────────
section "ECC / EDAC"

if [[ -d /sys/devices/system/edac/mc/mc0 ]]; then
    ce=$(cat /sys/devices/system/edac/mc/mc0/ce_count  2>/dev/null || echo "?")
    ue=$(cat /sys/devices/system/edac/mc/mc0/ue_count  2>/dev/null || echo "?")
    mc_name=$(cat /sys/devices/system/edac/mc/mc0/mc_name 2>/dev/null || echo "?")
    warn "ECC DIMM detected — EDAC driver loaded (mc: $mc_name)"
    info "  ce_count (corrected errors) = $ce"
    info "  ue_count (uncorrected errors) = $ue"
    warn "  Single-bit SEUs will be silently corrected — flip rate will be UNDER-counted"
    warn "  Only multi-bit (UE) events will be visible to CosmicRowhammer"
else
    if [[ "$virt" == "docker" ]]; then
        info "EDAC sysfs not visible inside container (host kernel sysfs not mounted)"
        info "  Check ECC on host: dmidecode -t 17 | grep -i 'error correction'"
        info "  Or on host: modprobe edac_core && cat /sys/devices/system/edac/mc/mc0/ce_count"
    else
        info "EDAC sysfs absent — ECC status unknown"
        info "  Try: modprobe edac_core && modprobe <platform>_edac"
        info "  Or:  dmidecode -t 17 | grep -i 'error correction'"
    fi
    # Try dmidecode as fallback
    if command -v dmidecode &>/dev/null; then
        ecc_type=$(dmidecode -t 17 2>/dev/null | awk -F: '/Error Correction/{print $2; exit}' | tr -d ' ')
        if [[ -n "$ecc_type" ]]; then
            info "  dmidecode reports ECC type: $ecc_type"
            if [[ "$ecc_type" == *"None"* ]] || [[ "$ecc_type" == *"Unknown"* ]]; then
                pass "No ECC detected via dmidecode — all SEUs visible"
            else
                warn "ECC active ($ecc_type) — single-bit flips will be corrected silently"
            fi
        fi
    fi
fi

# ── 4. MCA bank status (machine check error logs) ────────────────────────────
section "MCA Bank Error Logs"

if command -v mcelog &>/dev/null && [[ -f /dev/mcelog ]]; then
    recent=$(mcelog --client 2>/dev/null | head -5)
    if [[ -n "$recent" ]]; then
        warn "mcelog reports recent machine check errors:"
        echo "$recent" | sed 's/^/         /'
    else
        pass "mcelog: no recent machine check errors"
    fi
elif [[ -f /var/log/mcelog ]]; then
    lines=$(wc -l < /var/log/mcelog)
    if (( lines > 0 )); then
        warn "/var/log/mcelog has $lines lines — hardware errors logged, review before running"
    else
        pass "/var/log/mcelog empty — no prior hardware errors"
    fi
else
    info "mcelog not available — install for hardware error history"
fi

# ── 5. NUMA topology ─────────────────────────────────────────────────────────
section "NUMA Topology"

mapfile -t _node_dirs < <(ls -d /sys/devices/system/node/node[0-9]* 2>/dev/null || true)
numa_nodes=${#_node_dirs[@]}
info "NUMA nodes: $numa_nodes"

if (( numa_nodes <= 1 )); then
    pass "Single NUMA node — arena will be local, consistent access latency"
else
    warn "Multi-NUMA system ($numa_nodes nodes)"
    warn "  Remote NUMA accesses have higher latency and different retention characteristics"
    warn "  Consider: numactl --membind=0 ./cosmic_rowhammer"
    for node_dir in "${_node_dirs[@]}"; do
        n=$(basename "$node_dir")
        free=$(awk '/MemFree/{print $4}' "${node_dir}/meminfo" 2>/dev/null || echo "?")
        info "  $n MemFree: ${free} kB"
    done
fi

# ── 6. THP and KSM ──────────────────────────────────────────────────────────
section "THP / KSM (false-positive sources)"

thp_file=/sys/kernel/mm/transparent_hugepage/enabled
if [[ -f $thp_file ]]; then
    thp=$(cat $thp_file | grep -o '\[.*\]' | tr -d '[]')
    if [[ "$thp" == "never" ]]; then
        pass "THP = never  (optimal)"
    elif [[ "$thp" == "madvise" ]]; then
        pass "THP = madvise  (good — MADV_NOHUGEPAGE will suppress for arena)"
    else
        warn "THP = $thp  (always) — khugepaged may cause transient false flips"
        warn "  Fix: echo madvise > /sys/kernel/mm/transparent_hugepage/enabled"
    fi
else
    info "THP sysfs not available (container or kernel without THP)"
fi

ksm_file=/sys/kernel/mm/ksm/run
if [[ -f $ksm_file ]]; then
    ksm=$(cat $ksm_file)
    if [[ "$ksm" == "0" ]]; then
        pass "KSM = off  (optimal)"
    else
        warn "KSM = $ksm  (active) — large uniform sentinel regions are prime merge targets"
        warn "  Fix: echo 0 > /sys/kernel/mm/ksm/run"
        warn "  Or add --cap-add SYS_ADMIN to docker run (for MADV_UNMERGEABLE)"
    fi
else
    info "KSM sysfs not available"
fi

# ── 7. Memory availability ───────────────────────────────────────────────────
section "Memory"

mem_free_kb=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
arena_kb=$(( 512 * 1024 ))
info "MemAvailable: $(( mem_free_kb / 1024 )) MB"

if (( mem_free_kb >= arena_kb + 256*1024 )); then
    pass "Sufficient free memory for 512 MB arena + 256 MB headroom"
elif (( mem_free_kb >= arena_kb )); then
    warn "Tight: only $(( mem_free_kb/1024 - 512 )) MB headroom above arena — risk of reclaim under pressure"
else
    fail "Insufficient free memory: $(( mem_free_kb/1024 )) MB available, need 512 MB"
fi

# cgroup limit
for cg_path in /sys/fs/cgroup/memory/memory.limit_in_bytes /sys/fs/cgroup/memory.max; do
    if [[ -f "$cg_path" ]]; then
        cg_limit=$(cat "$cg_path" 2>/dev/null)
        if [[ "$cg_limit" == "max" ]] || (( cg_limit > 8*1024*1024*1024*1024 )); then
            pass "cgroup memory limit: unlimited ($cg_path)"
        else
            cg_mb=$(( cg_limit / 1024 / 1024 ))
            if (( cg_mb >= 768 )); then
                pass "cgroup memory limit: ${cg_mb} MB (>= 768 MB recommended)"
            else
                fail "cgroup memory limit: ${cg_mb} MB — too low for 512 MB arena + OS overhead"
                fail "  Fix: docker run --memory 768m (or higher)"
            fi
        fi
        break
    fi
done

# ── 8. Swap ──────────────────────────────────────────────────────────────────
section "Swap"

swap_total=$(awk '/SwapTotal/{print $2}' /proc/meminfo)
if (( swap_total == 0 )); then
    pass "No swap configured — pages cannot be silently evicted"
else
    swap_free=$(awk '/SwapFree/{print $2}' /proc/meminfo)
    warn "Swap present: total=$(( swap_total/1024 )) MB  free=$(( swap_free/1024 )) MB"
    warn "  If mlock fails, arena pages may swap → zero on readback → false positives"
fi

# ── 9. Container / virtualisation detection ──────────────────────────────────
section "Virtualisation"

info "Environment: $virt"
if [[ "$virt" == "bare metal" ]]; then
    pass "Bare metal — direct DRAM access, no hypervisor interference"
elif [[ "$virt" == "docker" ]]; then
    pass "Docker container — host kernel handles DRAM directly, SEU detection valid"
    info "  Ensure: --cap-add IPC_LOCK --ulimit memlock=-1"
else
    warn "Hypervisor: $virt — DRAM access is virtualised"
    warn "  Prefer bare metal or Docker for accurate SEU observation"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════"
printf "  PASS: %d   WARN: %d   FAIL: %d\n" $PASS $WARN $FAIL
echo "═══════════════════════════════════════════════════"

if (( FAIL > 0 )); then
    echo -e "  ${RED}System not ready — fix FAIL items before running.${RST}"
    exit 2
elif (( WARN > 0 )); then
    echo -e "  ${YEL}System ready with caveats — review WARNs above.${RST}"
    exit 1
else
    echo -e "  ${GRN}System ready — good to run CosmicRowhammer.${RST}"
    exit 0
fi
