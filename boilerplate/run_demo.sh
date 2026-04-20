#!/usr/bin/env bash
# =============================================================================
# run_demo.sh — Step-by-step demo for OS-Jackfruit project
#
# Run as:  sudo bash run_demo.sh
#
# Each STEP corresponds to one required screenshot. Read output carefully
# and take a screenshot before pressing Enter to continue.
# =============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

pause() {
    echo
    echo -e "${YELLOW}>>> Take your screenshot now, then press Enter to continue...${NC}"
    read -r _
}

banner() {
    echo
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  $*${NC}"
    echo -e "${GREEN}============================================================${NC}"
}

warn() { echo -e "${RED}[WARN] $*${NC}"; }

# ---- Must be root ----
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run this script with sudo: sudo bash run_demo.sh"
    exit 1
fi

# ---- Build ----
banner "STEP 0: Build all binaries"
make
echo -e "${GREEN}Build successful.${NC}"

# ---- Kernel module ----
banner "STEP 0b: Load kernel module"
if lsmod | grep -q container_monitor 2>/dev/null; then
    warn "Module already loaded — reloading"
    rmmod monitor 2>/dev/null || true
    sleep 1
fi
insmod monitor.ko
echo "Kernel module loaded:"
ls -l /dev/container_monitor
echo "dmesg:"
dmesg | grep container_monitor | tail -3

# ---- Prepare rootfs ----
banner "STEP 0c: Prepare root filesystems"
if [ ! -d rootfs-base ]; then
    echo "Downloading Alpine minirootfs..."
    mkdir rootfs-base
    wget -q --show-progress \
        https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
    tar -xzf alpine-minirootfs-3.20.3-x86_64.tar.gz -C rootfs-base
fi
cp -f memory_hog cpu_hog io_pulse rootfs-base/
for d in rootfs-alpha rootfs-beta rootfs-gamma rootfs-hi rootfs-lo rootfs-mem rootfs-mem2 rootfs-cpu rootfs-io; do
    rm -rf "$d"; cp -a rootfs-base "$d"
done
echo "Root filesystems ready."

# ---- Kill any stale supervisor ----
pkill -f "engine supervisor" 2>/dev/null || true
rm -f /tmp/mini_runtime.sock
sleep 0.5

# ---- Start supervisor in background ----
./engine supervisor ./rootfs-base &
SUPERVISOR_PID=$!
sleep 1
if ! kill -0 "$SUPERVISOR_PID" 2>/dev/null; then
    echo "ERROR: Supervisor failed to start!"
    exit 1
fi
echo "Supervisor running (PID=$SUPERVISOR_PID)"

# ==========================================================================
banner "SCREENSHOT 1: Multi-container supervision"
echo "Starting two containers..."
./engine start alpha ./rootfs-alpha "/cpu_hog 40"
sleep 0.5
./engine start beta  ./rootfs-beta  "/cpu_hog 40"
sleep 1
echo "Both containers started. Supervisor output above shows launch messages."
echo "Show supervisor terminal to demonstrate two containers under one supervisor."
pause

# ==========================================================================
banner "SCREENSHOT 2: Metadata tracking — engine ps"
./engine ps
pause

# ==========================================================================
banner "SCREENSHOT 3: Bounded-buffer logging"
sleep 5
echo "--- Contents of logs/alpha.log ---"
cat logs/alpha.log 2>/dev/null | head -20 || echo "(log not yet written)"
echo
echo "--- Contents of logs/beta.log ---"
cat logs/beta.log 2>/dev/null | head -20 || echo "(log not yet written)"
echo
echo "Using engine logs command:"
./engine logs alpha
pause

# ==========================================================================
banner "SCREENSHOT 4: CLI and IPC — stop a container"
echo "Stopping beta via CLI (UNIX socket IPC)..."
./engine stop beta
sleep 1
echo "--- engine ps after stop ---"
./engine ps
echo "(beta should now show state=stopped)"
pause

# ==========================================================================
banner "SCREENSHOT 5: Soft-limit warning"
echo "Starting memory_hog with soft=20MiB, hard=80MiB..."
./engine run mem ./rootfs-mem "/memory_hog 4 500" --soft-mib 20 --hard-mib 80 &
MEM_PID=$!
sleep 8
echo
echo "--- dmesg (looking for SOFT LIMIT) ---"
dmesg | grep container_monitor | tail -10
wait "$MEM_PID" 2>/dev/null || true
pause

# ==========================================================================
banner "SCREENSHOT 6: Hard-limit enforcement"
echo "Starting memory_hog with soft=20MiB, hard=40MiB (will be killed)..."
./engine run mem2 ./rootfs-mem2 "/memory_hog 4 500" --soft-mib 20 --hard-mib 40 || true
sleep 1
echo
echo "--- engine ps (should show hard_limit_killed) ---"
./engine ps
echo
echo "--- dmesg (SOFT + HARD LIMIT events) ---"
dmesg | grep container_monitor | grep -E "SOFT|HARD" | tail -10
pause

# ==========================================================================
banner "SCREENSHOT 7: Scheduling experiment (nice values)"
echo "Starting cpu_hog at nice=-5 (hi priority) and nice=+15 (lo priority)..."
./engine start hi ./rootfs-hi "/cpu_hog 25" --nice -5
sleep 0.3
./engine start lo ./rootfs-lo "/cpu_hog 25" --nice 15
echo "Running for 27 seconds, please wait..."
sleep 27
echo
echo "--- Logs from 'hi' container (nice=-5, high priority) ---"
tail -5 logs/hi.log 2>/dev/null || echo "(no log yet)"
echo
echo "--- Logs from 'lo' container (nice=+15, low priority) ---"
tail -5 logs/lo.log 2>/dev/null || echo "(no log yet)"
echo
echo "--- Line counts (more lines = more CPU time used) ---"
echo "hi log lines: $(wc -l < logs/hi.log 2>/dev/null || echo 0)"
echo "lo log lines: $(wc -l < logs/lo.log 2>/dev/null || echo 0)"
echo
./engine ps
pause

# ==========================================================================
banner "SCREENSHOT 8: Clean teardown"
echo "Sending SIGTERM to supervisor..."
kill -SIGTERM "$SUPERVISOR_PID" 2>/dev/null || true
wait "$SUPERVISOR_PID" 2>/dev/null || true
sleep 1
echo
echo "--- Checking for zombie processes ---"
ZOMBIES=$(ps aux | grep -E '\bZ\b' | grep -v grep || true)
if [ -z "$ZOMBIES" ]; then
    echo -e "${GREEN}No zombie processes found. Clean!${NC}"
else
    echo "$ZOMBIES"
fi
echo
echo "--- All engine-related processes ---"
ps aux | grep engine | grep -v grep || echo "(none — clean!)"
echo
echo "--- Unloading kernel module ---"
rmmod monitor
echo
echo "--- dmesg (module unload confirmation) ---"
dmesg | grep container_monitor | tail -3
pause

# ==========================================================================
banner "DEMO COMPLETE"
echo -e "${GREEN}All 8 screenshot steps completed successfully!${NC}"
echo
echo "Files to include in your submission:"
echo "  - engine.c, monitor.c, monitor_ioctl.h, Makefile"
echo "  - cpu_hog.c, io_pulse.c, memory_hog.c"
echo "  - README.md (add your screenshots to the screenshot sections)"
