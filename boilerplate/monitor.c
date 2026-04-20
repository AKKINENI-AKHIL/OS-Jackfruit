/*
 * monitor.c — Multi-Container Memory Monitor (Linux Kernel Module)
 *
 * Kernel compatibility:
 *   Linux 5.x / 6.0–6.14  : del_timer_sync, class_create(THIS_MODULE,...)
 *   Linux 6.4+             : class_create(name) — no THIS_MODULE
 *   Linux 6.15+            : timer_delete_sync replaces del_timer_sync
 *
 * Synchronisation design:
 *   We use spinlock_t + spin_lock_bh / spin_lock (NOT mutex) because the
 *   timer callback runs in softirq context. mutex_lock() must not be called
 *   from softirq context — it can sleep, which is illegal there. A spinlock
 *   with BH disabled is the correct primitive:
 *     - ioctl (process context)  : spin_lock_bh(&lock)
 *     - timer callback (softirq) : spin_lock(&lock)   [BH already disabled]
 *   This prevents data races between the two call sites on both UP and SMP.
 *
 *   list_for_each_entry_safe is used for all iterations so entries can be
 *   deleted during traversal without use-after-free.
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "monitor_ioctl.h"

#define DEVICE_NAME        "container_monitor"
#define CHECK_INTERVAL_SEC 1

/* ---------------------------------------------------------------
 * Kernel version compatibility
 * --------------------------------------------------------------- */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
#  define COMPAT_del_timer_sync(t)  timer_delete_sync(t)
#else
#  define COMPAT_del_timer_sync(t)  del_timer_sync(t)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#  define COMPAT_class_create(name)  class_create(name)
#else
#  define COMPAT_class_create(name)  class_create(THIS_MODULE, name)
#endif

/* ---------------------------------------------------------------
 * Per-container tracking node
 * --------------------------------------------------------------- */
struct monitored_entry {
    pid_t            pid;
    char             container_id[MONITOR_NAME_LEN];
    unsigned long    soft_limit_bytes;
    unsigned long    hard_limit_bytes;
    int              soft_warned;   /* 1 after first soft-limit warning */
    struct list_head list;
};

/* ---------------------------------------------------------------
 * Global list + spinlock
 *
 * Spinlock rationale:
 *   The list is accessed from two contexts:
 *     1. ioctl  — process context        → spin_lock_bh()
 *     2. timer  — softirq context        → spin_lock()
 *   A mutex would deadlock or cause a "sleeping in atomic" BUG in case 2.
 *   spin_lock_bh in case 1 disables softirqs on the local CPU, preventing
 *   the timer callback from preempting an ongoing ioctl list operation.
 * --------------------------------------------------------------- */
static LIST_HEAD(monitored_list);
static DEFINE_SPINLOCK(monitored_lock);

/* --- Device state --- */
static struct timer_list monitor_timer;
static dev_t             dev_num;
static struct cdev       c_dev;
static struct class     *cl;

/* ---------------------------------------------------------------
 * RSS helper — returns resident bytes for pid, or -1 if gone
 * Must be called WITHOUT the spinlock held (get_task_mm can sleep)
 * --------------------------------------------------------------- */
static long get_rss_bytes(pid_t pid)
{
    struct task_struct *task;
    struct mm_struct   *mm;
    long rss_pages = 0;

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) { rcu_read_unlock(); return -1; }
    get_task_struct(task);
    rcu_read_unlock();

    mm = get_task_mm(task);
    if (mm) {
        rss_pages = get_mm_rss(mm);
        mmput(mm);
    }
    put_task_struct(task);
    return rss_pages * PAGE_SIZE;
}

static void log_soft_limit_event(const char *id, pid_t pid,
                                  unsigned long limit, long rss)
{
    printk(KERN_WARNING
           "[container_monitor] SOFT LIMIT container=%s pid=%d "
           "rss=%ld limit=%lu\n", id, pid, rss, limit);
}

static void kill_process(const char *id, pid_t pid,
                          unsigned long limit, long rss)
{
    struct task_struct *task;
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) send_sig(SIGKILL, task, 1);
    rcu_read_unlock();
    printk(KERN_WARNING
           "[container_monitor] HARD LIMIT container=%s pid=%d "
           "rss=%ld limit=%lu — sent SIGKILL\n", id, pid, rss, limit);
}

/* ---------------------------------------------------------------
 * Timer callback (softirq context) — periodic RSS checks
 *
 * Strategy to avoid sleeping under spinlock:
 *   1. Snapshot PIDs/limits into a local array under the spinlock.
 *   2. Release the spinlock.
 *   3. Do the sleeping work (get_rss_bytes) without the lock.
 *   4. Re-acquire to remove entries as needed.
 * --------------------------------------------------------------- */
#define MAX_TRACKED 64

static void timer_callback(struct timer_list *t)
{
    /* Step 1: snapshot under lock */
    struct {
        pid_t         pid;
        char          id[MONITOR_NAME_LEN];
        unsigned long soft;
        unsigned long hard;
        int           soft_warned;
    } snap[MAX_TRACKED];
    int nsnap = 0;

    spin_lock(&monitored_lock);
    {
        struct monitored_entry *e;
        list_for_each_entry(e, &monitored_list, list) {
            if (nsnap >= MAX_TRACKED) break;
            snap[nsnap].pid         = e->pid;
            snap[nsnap].soft        = e->soft_limit_bytes;
            snap[nsnap].hard        = e->hard_limit_bytes;
            snap[nsnap].soft_warned = e->soft_warned;
            strncpy(snap[nsnap].id, e->container_id, MONITOR_NAME_LEN - 1);
            snap[nsnap].id[MONITOR_NAME_LEN - 1] = '\0';
            nsnap++;
        }
    }
    spin_unlock(&monitored_lock);

    /* Step 2: check RSS outside the lock (get_task_mm may sleep) */
    for (int i = 0; i < nsnap; i++) {
        long rss = get_rss_bytes(snap[i].pid);

        if (rss < 0) {
            /* Process gone — remove entry */
            struct monitored_entry *e, *tmp;
            printk(KERN_INFO "[container_monitor] PID %d exited, removing "
                   "container=%s\n", snap[i].pid, snap[i].id);
            spin_lock(&monitored_lock);
            list_for_each_entry_safe(e, tmp, &monitored_list, list)
                if (e->pid == snap[i].pid) { list_del(&e->list); kfree(e); break; }
            spin_unlock(&monitored_lock);
            continue;
        }

        if ((unsigned long)rss > snap[i].hard) {
            /* Hard limit — kill and remove */
            kill_process(snap[i].id, snap[i].pid, snap[i].hard, rss);
            struct monitored_entry *e, *tmp;
            spin_lock(&monitored_lock);
            list_for_each_entry_safe(e, tmp, &monitored_list, list)
                if (e->pid == snap[i].pid) { list_del(&e->list); kfree(e); break; }
            spin_unlock(&monitored_lock);
            continue;
        }

        if (!snap[i].soft_warned && (unsigned long)rss > snap[i].soft) {
            /* Soft limit — warn once, update flag */
            log_soft_limit_event(snap[i].id, snap[i].pid, snap[i].soft, rss);
            struct monitored_entry *e;
            spin_lock(&monitored_lock);
            list_for_each_entry(e, &monitored_list, list)
                if (e->pid == snap[i].pid) { e->soft_warned = 1; break; }
            spin_unlock(&monitored_lock);
        }
    }

    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);
}

/* ---------------------------------------------------------------
 * ioctl handler (process context — use spin_lock_bh)
 * --------------------------------------------------------------- */
static long monitor_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct monitor_request req;
    (void)f;

    if (cmd != MONITOR_REGISTER && cmd != MONITOR_UNREGISTER)
        return -EINVAL;
    if (copy_from_user(&req, (struct monitor_request __user *)arg, sizeof(req)))
        return -EFAULT;

    if (cmd == MONITOR_REGISTER) {
        struct monitored_entry *entry;

        printk(KERN_INFO
               "[container_monitor] Registering container=%s pid=%d "
               "soft=%lu hard=%lu\n",
               req.container_id, req.pid,
               req.soft_limit_bytes, req.hard_limit_bytes);

        if (req.soft_limit_bytes > req.hard_limit_bytes) {
            printk(KERN_WARNING "[container_monitor] Rejected: soft > hard\n");
            return -EINVAL;
        }

        entry = kzalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry) return -ENOMEM;

        entry->pid              = req.pid;
        entry->soft_limit_bytes = req.soft_limit_bytes;
        entry->hard_limit_bytes = req.hard_limit_bytes;
        entry->soft_warned      = 0;
        strncpy(entry->container_id, req.container_id, MONITOR_NAME_LEN - 1);
        entry->container_id[MONITOR_NAME_LEN - 1] = '\0';
        INIT_LIST_HEAD(&entry->list);

        spin_lock_bh(&monitored_lock);
        list_add_tail(&entry->list, &monitored_list);
        spin_unlock_bh(&monitored_lock);
        return 0;
    }

    /* UNREGISTER */
    {
        struct monitored_entry *entry, *tmp;
        int found = 0;

        printk(KERN_INFO "[container_monitor] Unregistering container=%s pid=%d\n",
               req.container_id, req.pid);

        spin_lock_bh(&monitored_lock);
        list_for_each_entry_safe(entry, tmp, &monitored_list, list) {
            if (entry->pid == req.pid &&
                strncmp(entry->container_id, req.container_id,
                        MONITOR_NAME_LEN) == 0) {
                list_del(&entry->list);
                kfree(entry);
                found = 1;
                break;
            }
        }
        spin_unlock_bh(&monitored_lock);
        return found ? 0 : -ENOENT;
    }
}

static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = monitor_ioctl,
};

static int __init monitor_init(void)
{
    if (alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME) < 0)
        return -1;

    cl = COMPAT_class_create(DEVICE_NAME);
    if (IS_ERR(cl)) {
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(cl);
    }

    if (IS_ERR(device_create(cl, NULL, dev_num, NULL, DEVICE_NAME))) {
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    cdev_init(&c_dev, &fops);
    if (cdev_add(&c_dev, dev_num, 1) < 0) {
        device_destroy(cl, dev_num);
        class_destroy(cl);
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }

    timer_setup(&monitor_timer, timer_callback, 0);
    mod_timer(&monitor_timer, jiffies + CHECK_INTERVAL_SEC * HZ);

    printk(KERN_INFO "[container_monitor] Module loaded. Device: /dev/%s "
           "(kernel %d.%d)\n", DEVICE_NAME,
           (LINUX_VERSION_CODE >> 16) & 0xff,
           (LINUX_VERSION_CODE >>  8) & 0xff);
    return 0;
}

static void __exit monitor_exit(void)
{
    COMPAT_del_timer_sync(&monitor_timer);

    /* Free all remaining entries */
    {
        struct monitored_entry *entry, *tmp;
        spin_lock_bh(&monitored_lock);
        list_for_each_entry_safe(entry, tmp, &monitored_list, list) {
            list_del(&entry->list);
            kfree(entry);
        }
        spin_unlock_bh(&monitored_lock);
    }

    cdev_del(&c_dev);
    device_destroy(cl, dev_num);
    class_destroy(cl);
    unregister_chrdev_region(dev_num, 1);

    printk(KERN_INFO "[container_monitor] Module unloaded.\n");
}

module_init(monitor_init);
module_exit(monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OS-Jackfruit Team");
MODULE_DESCRIPTION("Multi-container memory monitor — kernel 5.x/6.x compatible");
