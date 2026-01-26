// MIS Security Layer: eBPF LSM Hooks
// Production-ready inode-based access control with ringbuffer signaling
// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// ============================================================================
// DATA STRUCTURES
// ============================================================================

struct inode_key {
    __u64 inode;
    __u32 dev_id;
    __u32 syscall_nr;
} __attribute__((packed));

struct decision_value {
    __u8 allowed;        // 0 = DENY, 1 = ALLOW
    __u8 confidence;     // 0-100
    __u16 padding;
    __u32 ttl_expires;   // Unix timestamp (seconds)
    __u8 syscall_class;  // For TTL calculation
} __attribute__((packed));

// Event for userspace via ringbuffer
struct access_event {
    __u64 inode;
    __u32 dev_id;
    __u32 syscall_nr;
    __u32 pid;
    __u32 timestamp;
    char comm[16];       // Process name
} __attribute__((packed));

// ============================================================================
// MAPS
// ============================================================================

// Per-CPU LRU cache for inode decisions
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct inode_key);
    __type(value, struct decision_value);
} inode_cache SEC(".maps");

// Ringbuffer for signaling userspace (replaces bpf_send_signal_thread)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB buffer
} access_events SEC(".maps");

// Syscall TTL configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 512);  // Enough for all syscall numbers
    __type(key, __u32);
    __type(value, __u32);      // TTL in seconds
} syscall_ttl SEC(".maps");

// Statistics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_CACHE_HIT  0
#define STAT_CACHE_MISS 1
#define STAT_DENIED     2
#define STAT_TRACED     3

// ============================================================================
// HELPERS
// ============================================================================

static __always_inline void increment_stat(__u32 stat_id) {
    __u64 *counter = bpf_map_lookup_elem(&stats, &stat_id);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

static __always_inline __u32 get_syscall_ttl(__u32 syscall_nr) {
    __u32 *ttl = bpf_map_lookup_elem(&syscall_ttl, &syscall_nr);
    return ttl ? *ttl : 60;  // Default 60 seconds
}

static __always_inline bool is_ttl_valid(struct decision_value *decision) {
    __u32 now = bpf_ktime_get_ns() / 1000000000;  // seconds
    return now < decision->ttl_expires;
}

static __always_inline int signal_userspace(struct inode_key *key, __u32 pid) {
    struct access_event *event;
    
    event = bpf_ringbuf_reserve(&access_events, sizeof(*event), 0);
    if (!event) {
        return -1;  // Ringbuffer full
    }
    
    event->inode = key->inode;
    event->dev_id = key->dev_id;
    event->syscall_nr = key->syscall_nr;
    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns() / 1000000;  // milliseconds
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// ============================================================================
// LSM HOOKS
// ============================================================================

SEC("lsm/file_open")
int BPF_PROG(file_open_check, struct file *file, int ret) {
    if (ret != 0) {
        return ret;  // Already denied by other LSM
    }
    
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) {
        return 0;  // Should not happen
    }
    
    __u64 ino = BPF_CORE_READ(inode, i_ino);
    __u32 dev = new_encode_dev(BPF_CORE_READ(inode, i_sb, s_dev));
    
    struct inode_key key = {
        .inode = ino,
        .dev_id = dev,
        .syscall_nr = __NR_openat  // Approximate, real syscall from context
    };
    
    // Check cache
    struct decision_value *cached = bpf_map_lookup_elem(&inode_cache, &key);
    
    if (cached && is_ttl_valid(cached)) {
        increment_stat(STAT_CACHE_HIT);
        
        if (cached->allowed) {
            return 0;
        } else {
            increment_stat(STAT_DENIED);
            return -EPERM;
        }
    }
    
    increment_stat(STAT_CACHE_MISS);
    
    // Signal userspace for decision
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    signal_userspace(&key, pid);
    
    increment_stat(STAT_TRACED);
    
    // Default: deny while waiting for userspace decision
    // Userspace will update cache, and next access will be fast
    return -EAGAIN;
}

SEC("lsm/task_kill")
int BPF_PROG(task_kill_check, struct task_struct *p, struct kernel_siginfo *info, 
             int sig, const struct cred *cred, int ret) {
    if (ret != 0) {
        return ret;
    }
    
    // Block ptrace-like operations
    if (sig == SIGSTOP || sig == SIGCONT) {
        __u32 current_pid = bpf_get_current_pid_tgid() >> 32;
        __u32 target_pid = BPF_CORE_READ(p, tgid);
        
        // Only allow self-signaling
        if (current_pid != target_pid) {
            increment_stat(STAT_DENIED);
            return -EPERM;
        }
    }
    
    return 0;
}

// ============================================================================
// TRACEPOINTS FOR MONITORING
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
    // ptrace always requires explicit approval, never cache
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct inode_key key = {
        .inode = 0,  // Not inode-based
        .dev_id = 0,
        .syscall_nr = __NR_ptrace
    };
    
    signal_userspace(&key, pid);
    increment_stat(STAT_TRACED);
    
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int trace_process_vm(struct trace_event_raw_sys_enter *ctx) {
    // process_vm_readv: memory reading across processes
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct inode_key key = {
        .inode = 0,
        .dev_id = 0,
        .syscall_nr = __NR_process_vm_readv
    };
    
    signal_userspace(&key, pid);
    increment_stat(STAT_TRACED);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;
