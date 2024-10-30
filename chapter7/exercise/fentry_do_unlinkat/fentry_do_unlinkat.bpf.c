#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;

  // TODO: use a data structure to pass it to the user program
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);

  return 0;
}
