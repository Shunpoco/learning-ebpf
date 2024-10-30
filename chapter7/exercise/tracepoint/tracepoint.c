#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "tracepoint.skel.h"

struct event {
  int pid;
  char command[64];
  char path[64];
};

int handle_event(void *ctx, void *data, size_t size) {
  struct event *event = data;

  printf("%d, %s\n", event->pid, event->command);

  return 0;
}

volatile sig_atomic_t stop;

void inthand(int signum) {
  stop = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  if (level >= LIBBPF_DEBUG) {
    return 0;
  }

  return vfprintf(stderr, format, args);
}

int main() {
  signal(SIGINT, inthand);

  struct tracepoint_bpf *skel;
  int err;

  libbpf_set_print(libbpf_print_fn);

  skel = tracepoint_bpf__open();
  if (!skel) {
    printf("Failed to open BPF object\n");

    return 1;
  }

  err = tracepoint_bpf__load(skel);
  if (err) {
    printf("Failed to load BPF object\n");
    tracepoint_bpf__destroy(skel);

    return 1;
  }

  err = tracepoint_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d", err);
    tracepoint_bpf__destroy(skel);

    return 1;
  }

  struct ring_buffer *rb = NULL;
  rb = ring_buffer__new(bpf_map__fd(skel->maps.ring_buffer), handle_event, NULL, NULL);
  if (!rb) {
    printf("Failed to initialize ring buffer\n");
    tracepoint_bpf__destroy(skel);

    return 1;
  }

  while (!stop) {
    err = ring_buffer__poll(rb, 100);
    if (!err) {
      fprintf(stderr, "Failed to get data from ring buffer: %d", err);
      break;
    }
    sleep(1);
  }

  tracepoint_bpf__destroy(skel);

  return 0;
}