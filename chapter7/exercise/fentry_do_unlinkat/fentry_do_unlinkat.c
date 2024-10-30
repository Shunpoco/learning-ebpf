#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "fentry_do_unlinkat.skel.h"

volatile sig_atomic_t stop;

void inthand(int signum)
{
  stop = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  if (level >= LIBBPF_DEBUG) {
    return 0;
  }

  return vfprintf(stderr, format, args);
}


int main()
{
  signal(SIGINT, inthand);
  struct fentry_do_unlinkat_bpf *skel;
  int err;

  libbpf_set_print(libbpf_print_fn);

  skel = fentry_do_unlinkat_bpf__open();
  if (!skel) {
    printf("Failed to open BPF object\n");
    return 1;
  }

  err = fentry_do_unlinkat_bpf__load(skel);
  if (err) {
    printf("Failed to load BPF object\n");
    fentry_do_unlinkat_bpf__destroy(skel);
    return 1;
  }

  err = fentry_do_unlinkat_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    fentry_do_unlinkat_bpf__destroy(skel);
    return 1;
  }

  
  while (!stop) {}

  fentry_do_unlinkat_bpf__destroy(skel);
  return 0;
}
