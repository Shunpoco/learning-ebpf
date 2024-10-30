fentry_do_unlinkat:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	clang -target bpf -D __BPF_TRACING__ -Wall -O2 -g -o fentry_do_unlinkat.bpf.o -c fentry_do_unlinkat.bpf.c
	llvm-strip -g fentry_do_unlinkat.bpf.o
	bpftool gen skeleton fentry_do_unlinkat.bpf.o  > fentry_do_unlinkat.skel.h
	gcc -Wall -o fentry_do_unlinkat fentry_do_unlinkat.c -L../../../libbpf/src -l:libbpf.a -lelf -lz

clean:
	- rm fentry_do_unlinkat.bpf.o
	- rm fentry_do_unlinkat
	- rm fentry_do_unlinkat.skel.h
	- rm vmlinux.h
