/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MIS (Modular Intelligence Spaces) - Enhanced eBPF LSM Security Module v2.0.0
 * Copyright (c) 2026 defis
 *
 * Major improvements in v2.0:
 * - BPF task storage for per-process reputation (faster than LRU hash)
 * - DEFCON system (5 levels: normal → slowdown → block → critical → kill)
 * - Cgroup ID tracking instead of PID (container-stable)
 * - Adaptive rate limiting based on threat level
 * - Enhanced audit trail with DEFCON transitions
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MIS_VERSION_MAJOR 2
#define MIS_VERSION_MINOR 0
#define MIS_VERSION_PATCH 0

#define MAX_COMM_LEN        16
#define RINGBUF_SIZE        (512 * 1024)  // Increased for DEFCON events
#define MAX_CACHE_ENTRIES   100000
#define MAX_TTL_ENTRIES     512

// TTL values (in seconds)
#define TTL_READ_OPS        60
#define TTL_WRITE_OPS       60
#define TTL_STAT_OPS        120
#define TTL_OPEN_OPS        180
#define TTL_EXEC_OPS        300
#define TTL_PRIVILEGED      0

// Decision types
#define DECISION_ALLOW      0
#define DECISION_DENY       1
#define DECISION_TRACE      2
#define DECISION_SLOWDOWN   3  // NEW: Rate-limited allow
#define DECISION_KILL       4  // NEW: Terminate process

// Policy layers
#define POLICY_LAYER_CACHE      0
#define POLICY_LAYER_WHITELIST  1
#define POLICY_LAYER_HOTFIX     2
#define POLICY_LAYER_BASE       3
#define POLICY_LAYER_DEFAULT    4

// DEFCON levels (like military alert system)
#define DEFCON_5_NORMAL     5  // Normal operations, full permissions
#define DEFCON_4_WARNING    4  // Minor violations detected, start monitoring
#define DEFCON_3_ELEVATED   3  // Repeated violations, block risky operations
#define DEFCON_2_CRITICAL   2  // Severe violations, block all unverified
#define DEFCON_1_EMERGENCY  1  // Process termination imminent

// Violation thresholds for DEFCON escalation
#define VIOLATIONS_TO_DEFCON4   3
#define VIOLATIONS_TO_DEFCON3   6
#define VIOLATIONS_TO_DEFCON2   10
#define VIOLATIONS_TO_DEFCON1   15

// Slowdown delays (in microseconds) per DEFCON level
#define SLOWDOWN_DEFCON4    100     // 0.1ms delay
#define SLOWDOWN_DEFCON3    1000    // 1ms delay
#define SLOWDOWN_DEFCON2    10000   // 10ms delay

struct inode_key {
    __u64 inode;
    __u32 dev_id;
    __u32 syscall_nr;
} __attribute__((packed));

struct decision_value {
    __u8 allowed;
    __u8 confidence;
    __u16 padding;
    __u32 ttl_expires;
    __u8 syscall_class;
    __u8 policy_version;
    __u16 flags;
} __attribute__((packed));

// NEW: Task reputation stored per-task (faster than hash lookups)
struct task_reputation {
    __u32 violations;           // Total violation count
    __u32 last_violation_ns;    // Timestamp of last violation
    __u8 defcon_level;          // Current DEFCON level (5-1)
    __u8 learning_mode;         // 1 if in learning mode
    __u16 anomaly_score;        // ML-based anomaly score (0-1000)
    __u64 cgroup_id;           // Stable cgroup identifier
    __u32 violation_window_ns;  // Time window for violation counting
    __u32 last_defcon_change;   // When DEFCON level last changed
} __attribute__((packed));

struct access_event {
    __u64 inode;
    __u32 dev_id;
    __u32 syscall_nr;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u32 timestamp;
    __u32 ns_depth;
    __u8 decision_type;
    __u8 event_flags;
    __u8 defcon_level;     // NEW: Current DEFCON level
    __u8 reserved;
    __u64 cgroup_id;       // NEW: Cgroup ID instead of just PID
    char comm[MAX_COMM_LEN];
    char parent_comm[MAX_COMM_LEN];
} __attribute__((packed));

struct audit_event {
    __u64 timestamp_ns;
    __u64 inode;
    __u64 cgroup_id;       // NEW: Cgroup tracking
    __u32 pid;
    __u32 uid;
    __u32 syscall_nr;
    __u32 action;
    __u32 policy_layer;
    __u8 defcon_level;     // NEW: DEFCON level at time of event
    __u8 defcon_changed;   // NEW: 1 if DEFCON level changed
    __u16 violations;      // NEW: Violation count
    char comm[MAX_COMM_LEN];
} __attribute__((packed));

// NEW: DEFCON transition event
struct defcon_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u8 old_level;
    __u8 new_level;
    __u16 violations;
    __u32 trigger_syscall;
    char comm[MAX_COMM_LEN];
    char reason[32];
} __attribute__((packed));

struct ns_info {
    __u32 pid_ns;
    __u32 net_ns;
    __u32 mnt_ns;
    __u32 user_ns;
    __u32 depth;
} __attribute__((packed));

// MAPS

// Inode cache (still useful for file-based decisions)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_CACHE_ENTRIES);
    __type(key, struct inode_key);
    __type(value, struct decision_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} inode_cache SEC(".maps");

// NEW: Per-task storage for reputation (MUCH faster than hash lookup)
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_reputation);
} task_reputation_storage SEC(".maps");

// Ringbuffers
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} access_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE / 2);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} audit_events SEC(".maps");

// NEW: DEFCON transition events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE / 4);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} defcon_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_TTL_ENTRIES);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} syscall_ttl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);  // Changed to cgroup_id
    __type(value, struct ns_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ns_tracking SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 32);  // Increased for new stats
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} stats SEC(".maps");

// NEW: Cgroup → PID mapping for kill operations
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cgroup_to_pid SEC(".maps");

enum stat_index {
    STAT_CACHE_HIT = 0,
    STAT_CACHE_MISS,
    STAT_DENIED,
    STAT_TRACED,
    STAT_ALLOWED,
    STAT_RINGBUF_FULL,
    STAT_INVALID_INODE,
    STAT_NS_ESCAPE_ATTEMPT,
    STAT_PTRACE_BLOCKED,
    STAT_EXEC_BLOCKED,
    STAT_MOUNT_BLOCKED,
    STAT_CAP_BLOCKED,
    STAT_AUDIT_EVENTS,
    STAT_HOTFIX_BLOCKED,
    STAT_BASE_BLOCKED,
    STAT_WHITELIST_HIT,
    STAT_DEFCON_ESCALATIONS,     // NEW
    STAT_DEFCON_DEESCALATIONS,   // NEW
    STAT_SLOWDOWNS_APPLIED,      // NEW
    STAT_PROCESSES_KILLED,       // NEW
    STAT_ANOMALIES_DETECTED,     // NEW
    STAT_LEARNING_MODE_HITS,     // NEW
};

static __always_inline void increment_stat(__u32 stat_id) {
    __u64 *counter;
    __u32 key = stat_id;
    if (stat_id >= 32) return;
    counter = bpf_map_lookup_elem(&stats, &key);
    if (counter) __sync_fetch_and_add(counter, 1);
}

static __always_inline __u32 get_syscall_ttl(__u32 syscall_nr) {
    __u32 *ttl;
    __u32 key = syscall_nr;
    if (syscall_nr >= MAX_TTL_ENTRIES) return TTL_READ_OPS;
    ttl = bpf_map_lookup_elem(&syscall_ttl, &key);
    return ttl ? *ttl : TTL_READ_OPS;
}

static __always_inline bool is_ttl_valid(const struct decision_value *decision) {
    __u32 now;
    if (!decision) return false;
    if (decision->ttl_expires == 0) return false;
    now = bpf_ktime_get_ns() / 1000000000;
    return now < decision->ttl_expires;
}

// NEW: Get or create task reputation
static __always_inline struct task_reputation* get_task_reputation(struct task_struct *task) {
    struct task_reputation *rep;
    __u64 cgroup_id;
    
    if (!task) return NULL;
    
    // Try to get existing reputation from task storage
    rep = bpf_task_storage_get(&task_reputation_storage, task, 0, 0);
    if (rep) return rep;
    
    // Create new reputation entry
    rep = bpf_task_storage_get(&task_reputation_storage, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!rep) return NULL;
    
    // Initialize with defaults
    cgroup_id = bpf_get_current_cgroup_id();
    rep->violations = 0;
    rep->last_violation_ns = 0;
    rep->defcon_level = DEFCON_5_NORMAL;
    rep->learning_mode = 0;
    rep->anomaly_score = 0;
    rep->cgroup_id = cgroup_id;
    rep->violation_window_ns = 60000000000ULL; // 60 seconds
    rep->last_defcon_change = bpf_ktime_get_ns() / 1000000000;
    
    // Store cgroup → PID mapping
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&cgroup_to_pid, &cgroup_id, &pid, BPF_ANY);
    
    return rep;
}

// NEW: Update DEFCON level based on violations
static __always_inline void update_defcon_level(struct task_reputation *rep, __u32 syscall_nr) {
    __u8 old_level, new_level;
    __u32 now_sec;
    struct defcon_event *event;
    
    if (!rep) return;
    
    old_level = rep->defcon_level;
    now_sec = bpf_ktime_get_ns() / 1000000000;
    
    // Age out old violations (60 second window)
    if (now_sec - rep->last_defcon_change > 60) {
        if (rep->violations > 0) rep->violations = rep->violations / 2;
    }
    
    // Determine new DEFCON level based on violation count
    if (rep->violations >= VIOLATIONS_TO_DEFCON1) {
        new_level = DEFCON_1_EMERGENCY;
    } else if (rep->violations >= VIOLATIONS_TO_DEFCON2) {
        new_level = DEFCON_2_CRITICAL;
    } else if (rep->violations >= VIOLATIONS_TO_DEFCON3) {
        new_level = DEFCON_3_ELEVATED;
    } else if (rep->violations >= VIOLATIONS_TO_DEFCON4) {
        new_level = DEFCON_4_WARNING;
    } else {
        new_level = DEFCON_5_NORMAL;
    }
    
    // Update level
    rep->defcon_level = new_level;
    
    // Emit DEFCON transition event if level changed
    if (old_level != new_level) {
        rep->last_defcon_change = now_sec;
        
        event = bpf_ringbuf_reserve(&defcon_events, sizeof(*event), 0);
        if (event) {
            event->timestamp_ns = bpf_ktime_get_ns();
            event->cgroup_id = rep->cgroup_id;
            event->pid = bpf_get_current_pid_tgid() >> 32;
            event->old_level = old_level;
            event->new_level = new_level;
            event->violations = rep->violations;
            event->trigger_syscall = syscall_nr;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            
            // Set reason
            if (new_level < old_level) {
                __builtin_memcpy(event->reason, "ESCALATION", 11);
                increment_stat(STAT_DEFCON_ESCALATIONS);
            } else {
                __builtin_memcpy(event->reason, "DEESCALATION", 13);
                increment_stat(STAT_DEFCON_DEESCALATIONS);
            }
            
            bpf_ringbuf_submit(event, 0);
        }
    }
}

// NEW: Apply slowdown based on DEFCON level
static __always_inline void apply_defcon_slowdown(struct task_reputation *rep) {
    __u64 delay_us;
    
    if (!rep) return;
    
    switch (rep->defcon_level) {
        case DEFCON_4_WARNING:
            delay_us = SLOWDOWN_DEFCON4;
            break;
        case DEFCON_3_ELEVATED:
            delay_us = SLOWDOWN_DEFCON3;
            break;
        case DEFCON_2_CRITICAL:
            delay_us = SLOWDOWN_DEFCON2;
            break;
        default:
            return;  // No slowdown for DEFCON 5 or 1
    }
    
    // Apply delay (busy wait)
    __u64 start = bpf_ktime_get_ns();
    __u64 end = start + (delay_us * 1000);
    
    // Simple busy wait (BPF doesn't have sleep)
    // This creates CPU pressure on misbehaving processes
    while (bpf_ktime_get_ns() < end) {
        // Busy loop
    }
    
    increment_stat(STAT_SLOWDOWNS_APPLIED);
}

static __always_inline void get_parent_comm(char *buf, size_t size) {
    struct task_struct *task;
    struct task_struct *parent;
    buf[0] = '\0';
    task = (struct task_struct *)bpf_get_current_task();
    if (!task) return;
    parent = BPF_CORE_READ(task, real_parent);
    if (!parent) return;
    bpf_probe_read_kernel_str(buf, size, BPF_CORE_READ(parent, comm));
}

static __always_inline int signal_userspace(struct inode_key *key, __u32 pid, __u8 decision_type, struct task_reputation *rep) {
    struct access_event *event;
    struct task_struct *task;
    __u64 pid_tgid;
    __u64 cgroup_id;
    __u32 uid, gid;
    
    event = bpf_ringbuf_reserve(&access_events, sizeof(*event), 0);
    if (!event) {
        increment_stat(STAT_RINGBUF_FULL);
        return -ENOBUFS;
    }
    
    task = (struct task_struct *)bpf_get_current_task();
    pid_tgid = bpf_get_current_pid_tgid();
    cgroup_id = bpf_get_current_cgroup_id();
    
    event->inode = key->inode;
    event->dev_id = key->dev_id;
    event->syscall_nr = key->syscall_nr;
    event->pid = pid;
    event->tid = (__u32)(pid_tgid & 0xFFFFFFFF);
    event->cgroup_id = cgroup_id;
    event->timestamp = bpf_ktime_get_ns() / 1000000;
    event->decision_type = decision_type;
    event->event_flags = 0;
    event->defcon_level = rep ? rep->defcon_level : DEFCON_5_NORMAL;
    event->ns_depth = 0;
    
    uid = BPF_CORE_READ(task, cred, uid.val);
    gid = BPF_CORE_READ(task, cred, gid.val);
    event->uid = uid;
    event->gid = gid;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    get_parent_comm(event->parent_comm, sizeof(event->parent_comm));
    
    {
        struct ns_info *ns = bpf_map_lookup_elem(&ns_tracking, &cgroup_id);
        if (ns) event->ns_depth = ns->depth;
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline void submit_audit(__u64 inode, __u32 syscall_nr, __u32 action, __u32 policy_layer, struct task_reputation *rep) {
    struct audit_event *event;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    
    event = bpf_ringbuf_reserve(&audit_events, sizeof(*event), 0);
    if (!event) return;
    
    event->timestamp_ns = bpf_ktime_get_ns();
    event->inode = inode;
    event->cgroup_id = cgroup_id;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() >> 32;
    event->syscall_nr = syscall_nr;
    event->action = action;
    event->policy_layer = policy_layer;
    event->defcon_level = rep ? rep->defcon_level : DEFCON_5_NORMAL;
    event->defcon_changed = 0;
    event->violations = rep ? rep->violations : 0;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    increment_stat(STAT_AUDIT_EVENTS);
}

static __always_inline int get_inode_from_file(struct file *file, __u64 *inode_out, __u32 *dev_out) {
    struct inode *inode;
    struct super_block *sb;
    dev_t dev;
    
    if (!file || !inode_out || !dev_out) return -EINVAL;
    
    inode = BPF_CORE_READ(file, f_inode);
    if (!inode) {
        increment_stat(STAT_INVALID_INODE);
        return -ENOENT;
    }
    
    *inode_out = BPF_CORE_READ(inode, i_ino);
    sb = BPF_CORE_READ(inode, i_sb);
    if (!sb) return -ENOENT;
    
    dev = BPF_CORE_READ(sb, s_dev);
    *dev_out = ((__u32)(dev >> 20) << 8) | ((__u32)(dev & 0xff));
    return 0;
}

static __always_inline bool is_nested_namespace(__u64 cgroup_id) {
    struct ns_info *ns = bpf_map_lookup_elem(&ns_tracking, &cgroup_id);
    return ns ? (ns->depth > 1) : false;
}

static __always_inline bool is_dangerous_syscall(__u32 nr) {
    return (nr == 101 || nr == 165 || nr == 166);  // ptrace, mount, umount
}

// Main access control logic with DEFCON integration
static __always_inline int mis_access_control(struct file *file, __u32 syscall_nr) {
    struct inode_key key = {};
    struct decision_value *cached;
    struct task_struct *task;
    struct task_reputation *rep;
    __u32 pid, now_sec;
    __u64 cgroup_id;
    int ret;
    
    if (!file) return -EPERM;
    
    // Get inode and device
    ret = get_inode_from_file(file, &key.inode, &key.dev_id);
    if (ret) return ret;
    
    key.syscall_nr = syscall_nr;
    task = (struct task_struct *)bpf_get_current_task();
    pid = bpf_get_current_pid_tgid() >> 32;
    cgroup_id = bpf_get_current_cgroup_id();
    
    // Get task reputation (creates if doesn't exist)
    rep = get_task_reputation(task);
    
    // DEFCON 1 = KILL (Emergency)
    if (rep && rep->defcon_level == DEFCON_1_EMERGENCY) {
        submit_audit(key.inode, syscall_nr, DECISION_KILL, POLICY_LAYER_DEFAULT, rep);
        signal_userspace(&key, pid, DECISION_KILL, rep);
        increment_stat(STAT_PROCESSES_KILLED);
        
        // Signal userspace to kill the process
        // (actual kill happens in userspace via PID from cgroup_to_pid map)
        return -EKEYREVOKED;  // Special error code for kill signal
    }
    
    // DEFCON 2 = Block all unverified operations
    if (rep && rep->defcon_level == DEFCON_2_CRITICAL) {
        // Only allow explicitly whitelisted operations
        cached = bpf_map_lookup_elem(&inode_cache, &key);
        if (!cached || !is_ttl_valid(cached) || !cached->allowed) {
            submit_audit(key.inode, syscall_nr, DECISION_DENY, POLICY_LAYER_DEFAULT, rep);
            signal_userspace(&key, pid, DECISION_DENY, rep);
            increment_stat(STAT_DENIED);
            return -EPERM;
        }
    }
    
    // DEFCON 3 = Block dangerous operations
    if (rep && rep->defcon_level == DEFCON_3_ELEVATED) {
        if (is_dangerous_syscall(syscall_nr)) {
            submit_audit(key.inode, syscall_nr, DECISION_DENY, POLICY_LAYER_DEFAULT, rep);
            signal_userspace(&key, pid, DECISION_DENY, rep);
            increment_stat(STAT_DENIED);
            return -EPERM;
        }
    }
    
    // Check cache
    cached = bpf_map_lookup_elem(&inode_cache, &key);
    if (cached && is_ttl_valid(cached)) {
        increment_stat(STAT_CACHE_HIT);
        
        if (cached->allowed) {
            increment_stat(STAT_ALLOWED);
            
            // Apply slowdown for DEFCON 4/3
            if (rep) apply_defcon_slowdown(rep);
            
            return 0;
        } else {
            increment_stat(STAT_DENIED);
            
            // Record violation
            if (rep) {
                rep->violations++;
                rep->last_violation_ns = bpf_ktime_get_ns();
                update_defcon_level(rep, syscall_nr);
            }
            
            submit_audit(key.inode, syscall_nr, DECISION_DENY, POLICY_LAYER_CACHE, rep);
            return -EPERM;
        }
    }
    
    // Cache miss - signal userspace for policy decision
    increment_stat(STAT_CACHE_MISS);
    signal_userspace(&key, pid, DECISION_TRACE, rep);
    increment_stat(STAT_TRACED);
    
    // Default: Allow but trace (will be logged for learning)
    if (rep && rep->learning_mode) {
        increment_stat(STAT_LEARNING_MODE_HITS);
        apply_defcon_slowdown(rep);
    }
    
    return 0;
}

// LSM hooks
SEC("lsm/file_open")
int BPF_PROG(mis_file_open, struct file *file, int ret) {
    if (ret != 0) return ret;
    return mis_access_control(file, 2);  // sys_open
}

SEC("lsm/file_permission")
int BPF_PROG(mis_file_permission, struct file *file, int mask, int ret) {
    if (ret != 0) return ret;
    __u32 syscall = (mask & 0x1) ? 0 : 1;  // read(0) or write(1)
    return mis_access_control(file, syscall);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(mis_bprm_check, struct linux_binprm *bprm, int ret) {
    if (ret != 0) return ret;
    struct file *file = BPF_CORE_READ(bprm, file);
    return mis_access_control(file, 59);  // sys_execve
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(mis_ptrace, struct task_struct *child, unsigned int mode, int ret) {
    if (ret != 0) return ret;
    increment_stat(STAT_PTRACE_BLOCKED);
    return -EPERM;  // Always block ptrace for safety
}

SEC("lsm/sb_mount")
int BPF_PROG(mis_mount, const char *dev_name, struct path *path,
             const char *type, unsigned long flags, void *data, int ret) {
    if (ret != 0) return ret;
    increment_stat(STAT_MOUNT_BLOCKED);
    return -EPERM;  // Always block mount operations
}

char LICENSE[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
