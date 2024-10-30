#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
  u32 pid;
  u8 name[64];
};

struct event *unused __attribute__((unused));

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1<<24);
} ring_buffer SEC(".maps");

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
  struct event *event = 0;
  event = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct event), 0);
  if (!event) {
    return 0;
  }

  bpf_probe_read_str(&event->name, sizeof(event->name), (void *) name->name);
  event->pid = bpf_get_current_pid_tgid()>>32;

  bpf_ringbuf_submit(event, 0);

  return 0;
}
