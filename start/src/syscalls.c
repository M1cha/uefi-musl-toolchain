#include <common.h>

#define MAX_SYSCALL 2048
#define register_syscall(name) sys_call_table[SYS_##name] = sys_##name;

static void* sys_call_table[MAX_SYSCALL] = {0};
static int __user* clear_child_tid = NULL;
static int tid = 1;
static int pid = 1;
static int ppid = 0;
static list_node_t fds;
static int process_dumpable = 1;
static long tls = 0;

struct fd_handler;

typedef ssize_t (*io_fn_t)(struct fd_handler*, char __user *, size_t);

struct fd_handler {
    list_node_t node;

    unsigned long fd;
    io_fn_t read;
    io_fn_t write;
};
typedef struct fd_handler fd_handler_t;

static ssize_t do_loop_readv_writev(fd_handler_t *fdhandler, struct iovec *iov,
		unsigned long nr_segs, io_fn_t fn)
{
	struct iovec *vector = iov;
	ssize_t ret = 0;

	while (nr_segs > 0) {
		void __user *base;
		size_t len;
		ssize_t nr;

		base = vector->iov_base;
		len = vector->iov_len;
		vector++;
		nr_segs--;

		nr = fn(fdhandler, base, len);

		if (nr < 0) {
			if (!ret)
				ret = nr;
			break;
		}
		ret += nr;
		if ((size_t)nr != len)
			break;
	}

	return ret;
}

static ssize_t stdout_write(fd_handler_t* fdhandler, char __user * buf, size_t len) {
    size_t i;
    uint8_t c[4] = {0};

    for(i=0; i<len; i++) {
        c[0] = buf[i];

        if(fdhandler->fd==1)
            gST->ConOut->OutputString(gST->ConOut, (uint16_t*)c);
        else if(fdhandler->fd==2)
            gST->StdErr->OutputString(gST->StdErr, (uint16_t*)c);
    }

    return (ssize_t)len;
}

SYSCALL_DEFINE1(settls, long, val) {
    tls = val;
    return 0;
}

SYSCALL_DEFINE0(gettls) {
    return tls;
}

SYSCALL_DEFINE1(exit, int, status) {
    __exit_code = status;
    longjmp (__exit_jmpbuf, 1);
    return -1;
}

SYSCALL_DEFINE1(exit_group, int, status) {
    return sys_exit(status);
}

SYSCALL_DEFINE1(set_tid_address, int __user *, tidptr) {
	clear_child_tid = tidptr;
	return tid;
}

SYSCALL_DEFINE3(ioctl, unused unsigned int, fd, unused unsigned int, cmd, unused unsigned long, arg) {
	return -1;
}

SYSCALL_DEFINE3(writev, unsigned long, fd, struct iovec __user *, vec,
		unsigned long, vlen)
{
    fd_handler_t *fdhandler = NULL;

    // get fd handler
    fd_handler_t *entry;
    list_for_every_entry(&fds, entry, fd_handler_t, node) {
        if(entry->fd==fd) {
            fdhandler = entry;
            break;
        }
    }
    if(!fdhandler) {
        return -EBADF;
    }
    if(!fdhandler->write) {
        return -EIO;
    }
    
	return do_loop_readv_writev(fdhandler, vec, vlen, fdhandler->write);
}

SYSCALL_DEFINE0(getpid) {
	return pid;
}

SYSCALL_DEFINE0(getppid) {
	return ppid;
}

SYSCALL_DEFINE0(getuid) {
	return 0;
}

SYSCALL_DEFINE0(geteuid) {
	return 0;
}

SYSCALL_DEFINE0(getgid) {
	return 0;
}

SYSCALL_DEFINE0(getegid) {
	return 0;
}

SYSCALL_DEFINE0(getuid32) {
	return 0;
}

SYSCALL_DEFINE0(geteuid32) {
	return 0;
}

SYSCALL_DEFINE0(getgid32) {
	return 0;
}

SYSCALL_DEFINE0(getegid32) {
	return 0;
}


SYSCALL_DEFINE1(brk, unused unsigned long, brk) {
    return -1;
}

SYSCALL_DEFINE6(mmap2, unsigned long, addr, unsigned long, len,
		unsigned long, prot, unsigned long, flags,
		unsigned long, fd, unsigned long, off_4k)
{
    // addr is just a 'hint' so we can ignore it
    // flags can be ignored since we don't have processes

    if((int)fd!=-1) {
        uefi_printf("invalid mmap2(%lu, %lu, %lu, %lu, %lu, %lu)\n", addr, len, prot, flags, fd, off_4k);
        return -1;
    }

    // since we dont' support files(yet) we can safely ignore the offset too
 
    void* memory = AllocatePool(len);
    if(!memory) return -1;

    // we should apply the protection flags now

    return (long)memory;
}

SYSCALL_DEFINE2(munmap, unsigned long, addr, unused size_t, len)
{
	EFI_STATUS Status = gBS->FreePool((void*)addr);
    if(EFI_ERROR(Status))
        return -1;

    return 0;
}

SYSCALL_DEFINE2(clock_gettime, unused const clockid_t, which_clock,
		unused struct timespec __user *,tp)
{
    return 0;
}

SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unused unsigned long, arg3,
		unused unsigned long, arg4, unused unsigned long, arg5)
{
    long error;

	error = 0;
	switch (option) {
		case PR_GET_DUMPABLE:
			error = process_dumpable;
			break;
		case PR_SET_DUMPABLE:
			if (arg2 != 0 && arg2 != 1) {
				error = -EINVAL;
				break;
			}
			process_dumpable = arg2;
			error = 0;
			break;

		default:
			error = -EINVAL;
			break;
	}
	return error;
}

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, mode_t, mode)
{
    uefi_printf("open(%s, %d, %d)\n", filename, flags, mode);
	return -1;
}

void __syscall_init(void) {
    register_syscall(exit);
    register_syscall(exit_group);
    register_syscall(set_tid_address);
    register_syscall(ioctl);
    register_syscall(writev);
    register_syscall(getpid);
    register_syscall(getppid);
    register_syscall(getuid);
    register_syscall(geteuid);
    register_syscall(getgid);
    register_syscall(getegid);
    register_syscall(getuid32);
    register_syscall(geteuid32);
    register_syscall(getgid32);
    register_syscall(getegid32);
    register_syscall(brk);
    register_syscall(mmap2);
    register_syscall(munmap);
    register_syscall(clock_gettime);
    register_syscall(prctl);
    register_syscall(open);

    list_initialize(&fds);

    fd_handler_t* fdstdin = AllocateZeroPool(sizeof(fd_handler_t));
    fdstdin->fd = 0;
    list_add_tail(&fds, &fdstdin->node);

    fd_handler_t* fdstdout = AllocateZeroPool(sizeof(fd_handler_t));
    fdstdout->fd = 1;
    fdstdout->write = stdout_write;
    list_add_tail(&fds, &fdstdout->node);

    fd_handler_t* fdstderr = AllocateZeroPool(sizeof(fd_handler_t));
    fdstderr->fd = 2;
    fdstderr->write = stdout_write;
    list_add_tail(&fds, &fdstderr->node);
}

long __syscall(long n, ...) {
    int i;
    long (*fn)(long,...);

    // get handler
    if(n==__ARM_NR_set_tls) {
        fn = (void*)sys_settls;
    }
    // get tls
    else if(n==0xf0010) {
        fn = (void*)sys_gettls;
    }
    else {
        if(n>MAX_SYSCALL || !sys_call_table[n]) {
            uefi_printf("invalid syscall %d(%x)\n", n, n);
            sys_exit(-1);
            return -1;
        }
        fn = sys_call_table[n];
    }

    // get arguments
    long args[6];
    va_list ap;
    va_start(ap, n);
    for(i=0; i<6; i++) {
        long arg = va_arg(ap, long);

        args[i] = arg;
    }
    va_end(ap);

    // call handler
    return fn(args[0], args[1], args[2], args[3], args[4], args[5]);
}
