tracepoint:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	cp ../../../libbpf/src/bpf_core_read.h ./
	cp ../../../libbpf/src/bpf_tracing.h ./
	clang -target bpf -D __BPF_TRACING__ -Wall -O2 -g -o tracepoint.bpf.o -c tracepoint.bpf.c
	llvm-strip -g tracepoint.bpf.o
	bpftool gen skeleton tracepoint.bpf.o  > tracepoint.skel.h
	gcc -Wall -o tracepoint tracepoint.c -L../../../libbpf/src -l:libbpf.a -lelf -lz

clean:
	- rm tracepoint.bpf.o
	- rm tracepoint
	- rm tracepoint.skel.h
	- rm vmlinux.h
	- rm bpf_core_read.h
	- rm bpf_tracing.h
