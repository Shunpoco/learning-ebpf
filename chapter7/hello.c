#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>
#include "hello.h"
#include "hello.skel.h"

enum Program {
	KPROBE_SYS_EXECVE,
	KPROBE_DO_EXECVE,
	TP_SYS_ENTER_EXECVE,
	TP_BTF_EXEC,
	RAW_TP_EXEC,
};

// Choose program choses a specific program.
static int choose_program(struct hello_bpf *obj, int idx)
{
	struct bpf_prog_skeleton *progs;

	progs = (struct bpf_prog_skeleton *)calloc(1, sizeof(*progs));
	if (!progs) {
		return -ENOMEM;
	}

	progs[0].name = obj->skeleton->progs[idx].name;
	progs[0].prog = obj->skeleton->progs[idx].prog;
	progs[0].link = obj->skeleton->progs[idx].link;

	obj->skeleton->prog_cnt = 1;
	obj->skeleton->progs = progs;

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct data_t *m = data;

	printf("%-6d %-6d %-16s %-16s %s\n", m->pid, m->uid, m->command, m->path, m->message);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

int main()
{
    struct hello_bpf *skel;
	// struct bpf_object_open_opts *o;
    int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	char log_buf[64 * 1024];
	LIBBPF_OPTS(bpf_object_open_opts, opts,
		.kernel_log_buf = log_buf,
		.kernel_log_size = sizeof(log_buf),
		.kernel_log_level = 1,
	);

	skel = hello_bpf__open_opts(&opts);
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = choose_program(skel, KPROBE_SYS_EXECVE);
	if (err) {
		printf("Failed to choose program\n");
		hello_bpf__destroy(skel);

		return 1;
	}

	err = hello_bpf__load(skel);
	// Print the verifier log
	for (int i=0; i < sizeof(log_buf); i++) {
		if (log_buf[i] == 0 && log_buf[i+1] == 0) {
			break;
		}
		printf("%c", log_buf[i]);
	}
	
	if (err) {
		printf("Failed to load BPF object\n");
		hello_bpf__destroy(skel);
		return 1;
	}

	// Attach the progams to the events
	err = hello_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		hello_bpf__destroy(skel);
        return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		hello_bpf__destroy(skel);
        return 1;
	}

	while (true) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	perf_buffer__free(pb);
	hello_bpf__destroy(skel);
	return -err;
}
