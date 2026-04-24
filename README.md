# OS-Jackfruit Final Submission

This project implements a lightweight multi-container runtime in C with a long-lived supervisor, bounded logging, and a kernel-space memory monitor for soft/hard limit enforcement.

## Team Information

Replace the placeholders below with the final names and SRNs used for submission.

| Member | SRN |
| --- | --- |
| Aditya Sanjay Patil | PES1UG24CS030 |
| Akkineni Akhil | PES1UG24CS041 |

## Build, Load, Run Instructions

All commands below assume a fresh Ubuntu 22.04 or 24.04 VM with Secure Boot disabled. Run them from `boilerplate/`.

### 1. Install prerequisites

```bash
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r) wget
```

### 2. Run the environment check

```bash
cd boilerplate
chmod +x environment-check.sh
sudo ./environment-check.sh
```

### 3. Build the runtime, workloads, and module

```bash
make
```

For the CI-safe smoke build used by GitHub Actions:

```bash
make -C boilerplate ci
```

### 4. Prepare the root filesystems

Create one writable rootfs per live container. Copy the test workloads into the base filesystem before cloning per-container copies.

```bash
mkdir -p rootfs-base
wget -q https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.3-x86_64.tar.gz
tar -xzf alpine-minirootfs-3.20.3-x86_64.tar.gz -C rootfs-base
cp -f memory_hog cpu_hog io_pulse rootfs-base/
cp -a rootfs-base rootfs-alpha
cp -a rootfs-base rootfs-beta
cp -a rootfs-base rootfs-mem
cp -a rootfs-base rootfs-mem2
cp -a rootfs-base rootfs-hi
cp -a rootfs-base rootfs-lo
```

Do not commit `rootfs-base/` or the `rootfs-*` copies.

### 5. Load the kernel module

```bash
sudo insmod monitor.ko
ls -l /dev/container_monitor
dmesg | tail -n 20
```

### 6. Start the supervisor

Use a dedicated terminal for the supervisor. The examples below match the demo flow in `run_demo.sh`.

```bash
sudo ./engine supervisor ./rootfs-base
```

### 7. Start containers and inspect metadata

From another terminal, launch containers through the CLI and inspect them with `ps` and `logs`.

```bash
sudo ./engine start alpha ./rootfs-alpha "/cpu_hog 40"
sudo ./engine start beta ./rootfs-beta "/cpu_hog 40"
sudo ./engine ps
sudo ./engine logs alpha
```

### 8. Run workload and memory-limit experiments

```bash
sudo ./engine run mem ./rootfs-mem "/memory_hog 4 500" --soft-mib 20 --hard-mib 80
sudo ./engine run mem2 ./rootfs-mem2 "/memory_hog 4 500" --soft-mib 20 --hard-mib 40
```

### 9. Run the scheduler experiment

```bash
sudo ./engine start hi ./rootfs-hi "/cpu_hog 20" --nice -5
sudo ./engine start lo ./rootfs-lo "/cpu_hog 20" --nice 15
sudo ./engine logs hi
sudo ./engine logs lo
```

### 10. Stop containers, inspect dmesg, and unload the module

```bash
sudo ./engine stop alpha
sudo ./engine stop beta
sudo ./engine stop hi
sudo ./engine stop lo

kill -SIGTERM "$(pgrep -f 'engine supervisor' | head -n 1)"
dmesg | tail -n 50
sudo rmmod monitor
```

If you keep the supervisor in a foreground terminal instead, `Ctrl+C` performs the same final shutdown step.

## Demo with Screenshots

The screenshots below are stored in `outputs/` and are embedded inline so they render directly in the README.

### Multi-container supervision

![Supervisor managing multiple containers](outputs/01-multi-container-supervision-1.png)

![Supervisor managing multiple containers, alternate view](outputs/01-multi-container-supervision-2.png)

One supervisor manages two live containers at the same time.

### Metadata tracking

![Metadata tracking](outputs/02-metadata-tracking.png)

`ps` shows container IDs, host PIDs, states, limits, nice values, and start times.

### Bounded-buffer logging

![Bounded-buffer logging](outputs/03-bounded-buffer-logging.png)

Container output is captured through the logging pipeline and persisted to per-container log files.

### CLI and IPC

![CLI and IPC](outputs/04-cli-ipc.png)

A CLI command reaches the supervisor over the control channel and returns an explicit response.

### Soft-limit warning

![Soft-limit warning](outputs/05-soft-limit-warning.png)

`dmesg` shows a soft-limit warning without killing the container.

### Hard-limit enforcement

![Hard-limit enforcement](outputs/06-hard-limit-enforcement.png)

`dmesg` and container state show that the hard limit terminated the workload.

### Scheduling experiment

![Scheduling experiment](outputs/07-scheduling-experiment.png)

Two CPU-bound containers are run with different `nice` values for a scheduler comparison.

### Clean teardown

![Clean teardown](outputs/08-clean-teardown.png)

Shutdown completes cleanly with reaping, log flush, and module unload.

## Engineering Analysis

### 1. Isolation Mechanisms

The runtime combines PID, UTS, and mount namespaces with a per-container root filesystem to create isolation at the process and filesystem level. Each container sees its own process tree, hostname view, and mount namespace, while the host kernel still remains shared across all containers. That is the core tradeoff of containerization: isolation is strong enough to separate user-visible state, but the scheduler, memory manager, network stack, and device drivers are still provided by the same kernel.

Mount isolation matters because filesystem view is part of the security and correctness boundary. A `chroot` or `pivot_root` style root change prevents the container from seeing the host filesystem as its root, and remounting `/proc` inside that namespace gives tools like `ps` a process view that matches the isolated PID space. The result is not a virtual machine; it is a constrained process environment built out of kernel primitives.

### 2. Supervisor and Process Lifecycle

A long-running parent supervisor is the right abstraction because process lifecycle in Unix is inherently parent-child based. The supervisor is the persistent authority that creates children, records their metadata, receives termination events, and reaps exited processes so they do not become zombies. Once a container process exits, its identity does not disappear from the system immediately; the parent must collect its exit status and reconcile the runtime state.

This design also makes signal delivery understandable. `start` creates a background child, `run` blocks on completion, and `stop` becomes an explicit lifecycle transition rather than an ad hoc kill. The supervisor becomes the single place where state transitions such as `starting`, `running`, `stopped`, and `hard_limit_killed` can be derived from actual process outcomes.

### 3. IPC, Threads, and Synchronization

The project uses two distinct IPC paths for two different jobs. The control path carries commands from the CLI to the supervisor, while the data path carries container stdout and stderr into the logging pipeline. Separating those paths keeps command handling independent from output volume, which avoids mixing control traffic with the much noisier stream of container output.

The bounded-buffer logger is a classic producer-consumer problem. Without synchronization, a producer thread could overwrite an occupied slot, a consumer could read a partially written record, or a full queue could deadlock the container path. Mutexes and condition variables are the natural fit for the shared logging queue and metadata table because they express mutual exclusion plus wait/wake behavior cleanly. The kernel monitor uses a different rule: its shared list is guarded with a spinlock because the timer callback runs in atomic context and cannot sleep.

### 4. Memory Management and Enforcement

RSS is the resident set size, which measures how much physical memory a process currently occupies in RAM. It is not the same as virtual memory footprint, allocated address space, or page cache usage. That distinction matters because a process can reserve a large address range without immediately consuming the same amount of physical memory.

Soft and hard limits are different policies with different goals. A soft limit is a warning threshold that signals pressure and gives the system a chance to observe behavior before intervention. A hard limit is a protection boundary that stops a process from crossing into unacceptable consumption. Kernel-space enforcement is appropriate here because user-space polling can miss short spikes, can be delayed by scheduling, and should not be trusted to police memory consumption on its own.

### 5. Scheduling Behavior

The scheduler experiment connects the runtime to Linux CPU scheduling rather than to container mechanics. Nice values change the weight the Completely Fair Scheduler assigns to each process, so a lower nice value should receive a larger share of CPU time under contention. CPU-bound workloads make this visible because they stay runnable, while I/O-bound workloads yield the CPU frequently and are typically perceived as more responsive.

The key OS concept is that scheduling is about relative service under contention, not about equal wall-clock progress for every task. When the two containers run the same CPU-bound program with different nice values, the scheduler bias becomes visible in the log stream and in completion behavior. When one workload sleeps frequently, the scheduler can prioritize responsiveness without starving the background CPU consumer.

## Design Decisions and Tradeoffs

| Subsystem | Design choice | Tradeoff | Why it was the right call |
| --- | --- | --- | --- |
| Namespace isolation | Use PID, UTS, and mount namespaces plus a per-container rootfs | Less complete than a full OCI stack, but much simpler to reason about and grade | It provides the core isolation properties the assignment asks for without adding orchestration complexity |
| Supervisor architecture | Keep one long-lived supervisor as the authoritative owner of container state | The supervisor is a single point of failure | It centralizes lifecycle management, reaping, and metadata reconciliation in one process |
| IPC and logging | Use a control channel for commands and a pipe-based logging path with a bounded queue | More moving parts than direct terminal output | It cleanly separates command traffic from container output and prevents blocking on noisy logs |
| Kernel monitor | Track host PIDs in a kernel module and enforce RSS thresholds with periodic checks | Polling adds latency and overhead compared with cgroup-based accounting | It keeps the policy explicit, easy to demonstrate, and aligned with the assignment requirements |
| Scheduling experiments | Compare CPU-bound workloads with different `nice` values | Less precise than CPU quotas or affinity-only microbenchmarks | It maps directly to the Linux scheduler’s fairness model and is easy to reproduce on a VM |

## Scheduler Experiment Results

The submitted screenshot for the scheduler experiment captures a side-by-side run of two CPU-bound containers with different priorities:

| Container | Nice value | Command | Visible output from the screenshot |
| --- | --- | --- | --- |
| hi | `-5` | `/cpu_hog 20` | `cpu_hog alive elapsed=16` through `elapsed=20`, then `cpu_hog done duration=20` |
| lo | `15` | `/cpu_hog 20` | `cpu_hog alive elapsed=16` through `elapsed=20`, then `cpu_hog done duration=20` |

The raw output shows that both tasks made forward progress and completed the same nominal workload duration, while the higher-priority container was used as the control case for the comparison. The point of the experiment is not that one task finishes instantly and the other does not; it is that Linux scheduling biases CPU service according to weight, which becomes visible when the two runnable workloads compete on the same host.

If you repeat the experiment with a longer run or heavier contention, replace the table above with your exact wall-clock timings or line-count measurements from that run.

## Repository Layout

```text
OS-Jackfruit/
├── boilerplate/
│   ├── engine.c
│   ├── monitor.c
│   ├── monitor_ioctl.h
│   ├── Makefile
│   ├── cpu_hog.c
│   ├── io_pulse.c
│   ├── memory_hog.c
│   ├── environment-check.sh
│   └── run_demo.sh
├── outputs/
│   ├── 01-multi-container-supervision-1.png
│   ├── 01-multi-container-supervision-2.png
│   ├── 02-metadata-tracking.png
│   ├── 03-bounded-buffer-logging.png
│   ├── 04-cli-ipc.png
│   ├── 05-soft-limit-warning.png
│   ├── 06-hard-limit-enforcement.png
│   ├── 07-scheduling-experiment.png
│   └── 08-clean-teardown.png
├── project-guide.md
├── README.md
└── .github/workflows/submission-smoke.yml
```

## Notes

- The repository uses `boilerplate/` as the working source tree.
- The full runtime needs an Ubuntu VM with Secure Boot disabled; WSL is not supported.
- `make -C boilerplate ci` is the CI-safe smoke path, but it does not replace VM-based module testing.
- The screenshots referenced above live in `outputs/` and are linked with relative paths so the README stays portable.
- `rootfs-*` directories and runtime logs are generated artifacts and should not be committed.
