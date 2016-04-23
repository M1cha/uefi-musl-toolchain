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
static char cwd[PATH_MAX+1] = "/";

// fork
static jmp_buf vfork_jmpbuf;
static int in_vfork = 0;
static int has_vfork_status = 0;
static int vfork_status;

static struct utsname utsname = {
	.sysname = "UEFI",
	.nodename = "localhost",
	.release = "",
	.version = "",
	.machine = "armv7l",
#ifdef _GNU_SOURCE
	.domainname = "domain",
#else
	.__domainname = "domain",
#endif
};

struct fd_handler;

typedef ssize_t (*io_fn_t)(struct fd_handler*, char __user *, size_t);
typedef long (*ioctl_fn_t)(struct fd_handler*, unsigned int, unsigned long);
typedef void (*close_fn_t)(struct fd_handler*);
typedef int (*copy_fn_t)(struct fd_handler*,struct fd_handler*);

struct fd_handler {
    list_node_t node;

    unsigned long fd;
    io_fn_t read;
    io_fn_t write;
    ioctl_fn_t ioctl;

    close_fn_t close;
    copy_fn_t copy;

    void* private;
};
typedef struct fd_handler fd_handler_t;

typedef struct {
    int real_type;

    struct winsize winsz;
} fd_tty_pdata_t;

long sys_close(unsigned int fd);
static int init_tty(fd_handler_t* fdhandler, int realfd);

int get_unused_fd(void) {
    unsigned int fd = 0;

    // get fd handler
    fd_handler_t *entry;
    list_for_every_entry(&fds, entry, fd_handler_t, node) {
        if(entry->fd>=fd) {
            fd = entry->fd+1;
        }
    }

    return fd;
}

static fd_handler_t* get_file(unsigned int fd) {
    fd_handler_t *entry;
    list_for_every_entry(&fds, entry, fd_handler_t, node) {
        if(entry->fd==fd) {
            return entry;
        }
    }

    //uefi_printf("FD %d not found\n", fd);
    return NULL;
}


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

static ssize_t tty_write(fd_handler_t* fdhandler, char __user * buf, size_t len) {
    size_t i;
    uint8_t c[4] = {0};
    fd_tty_pdata_t* pdata = fdhandler->private;

    if(len==0)
        return 0;

    // check if this is stdin
    if(pdata->real_type==0)
        return -EIO;

    for(i=0; i<len; i++) {
        c[0] = buf[i];

        if(pdata->real_type==2)
            gST->StdErr->OutputString(gST->StdErr, (uint16_t*)c);
        else
            gST->ConOut->OutputString(gST->ConOut, (uint16_t*)c);
    }

    return (ssize_t)len;
}

static ssize_t tty_read(unused fd_handler_t* fdhandler, char __user * buf, unused size_t len) {
    fd_tty_pdata_t* pdata = fdhandler->private;
    UINTN           WaitIndex;
    EFI_INPUT_KEY   Key;

    if(len==0)
        return 0;

    // check if this is stdin
    if(pdata->real_type!=0)
        return -EIO;

    // wait for key
    EFI_STATUS Status = gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &WaitIndex);
    if(EFI_ERROR (Status))
        return -1;

    // read key
    Status = gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
    if(EFI_ERROR(Status) || Key.ScanCode!=SCAN_NULL) {
        return 0;
    }


    buf[0] = Key.UnicodeChar;
    if (buf[0] == '\r')
        buf[0] = '\n';

    return 1;
}

static long tty_ioctl(fd_handler_t* fdhandler, unsigned int cmd, unsigned long arg) {
    fd_tty_pdata_t* pdata = fdhandler->private;

    switch(cmd) {
        case TIOCGWINSZ:
            memcpy((void*)arg, &pdata->winsz, sizeof(struct winsize));
            return 0;

        case TIOCSWINSZ:
            memcpy(&pdata->winsz, (void*)arg, sizeof(struct winsize));
            return 0;

        case TCGETS:
        case TCSETS:
            return 0;

        default:
            return -EINVAL;
    }
}

static void tty_close(fd_handler_t* fdhandler) {
    gBS->FreePool(fdhandler->private);
}

static int tty_copy(fd_handler_t* dst, fd_handler_t* src) {
    init_tty(dst, 0);
    memcpy(dst->private, src->private, sizeof(fd_tty_pdata_t));
    return 0;
}

SYSCALL_DEFINE1(settls, long, val) {
    tls = val;
    return 0;
}

SYSCALL_DEFINE0(gettls) {
    return tls;
}

#define	__W_EXITCODE(ret, sig)	((ret) << 8 | (sig))
SYSCALL_DEFINE1(exit, int, status) {
    __exit_code = status;
    if(in_vfork) {
        has_vfork_status = 1;
        vfork_status = __W_EXITCODE(__exit_code, SIGCHLD);

        longjmp_stack (vfork_jmpbuf, 1);
    } else
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
    long rc = -EIO;
    fd_handler_t *fdhandler = get_file(fd);

    if(!fdhandler) {
        return -EBADF;
    }
    if(fdhandler->ioctl) {
	    rc = fdhandler->ioctl(fdhandler, cmd, arg);
    }

    if(rc)   
        uefi_printf("invalid ioctl %x on %d\n", cmd, fdhandler->fd);

    return rc;
}

SYSCALL_DEFINE3(writev, unsigned long, fd, struct iovec __user *, vec,
		unsigned long, vlen)
{
	fd_handler_t *fdhandler = get_file(fd);

    if(!fdhandler) {
        return -EBADF;
    }
    if(!fdhandler->write) {
        return -EIO;
    }
    
	return do_loop_readv_writev(fdhandler, (void*)vec, vlen, fdhandler->write);
}

SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
	fd_handler_t *fdhandler = get_file(fd);

    if(!fdhandler) {
        return -EBADF;
    }
    if(!fdhandler->write) {
        return -EIO;
    }

	return fdhandler->write(fdhandler, (void*)buf, count);
}

SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
    fd_handler_t *fdhandler = get_file(fd);

    if(!fdhandler) {
        return -EBADF;
    }
    if(!fdhandler->read) {
        return -EIO;
    }
    
	return do_loop_readv_writev(fdhandler, (void*)vec, vlen, fdhandler->read);
}

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	fd_handler_t *fdhandler = get_file(fd);

    if(!fdhandler) {
        return -EBADF;
    }
    if(!fdhandler->read) {
        return -EIO;
    }

	return fdhandler->read(fdhandler, (void*)buf, count);
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
    return -ENOSYS;
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

SYSCALL_DEFINE3(open, unused const char __user *, filename, unused int, flags, unused mode_t, mode)
{
    //uefi_printf("open(%s, %d, %d)\n", filename, flags, mode);
	return -1;
}

SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
{
	fd_handler_t *fdhandler_old = get_file(oldfd);
	fd_handler_t *fdhandler_new = get_file(newfd);

    if(!fdhandler_old) {
        return -EBADF;
    }

    // allocate
    fd_handler_t* nfd = AllocateZeroPool(sizeof(fd_handler_t));
    if(!nfd) return -EIO;

    // copy all data
    memcpy(nfd, fdhandler_old, sizeof(*nfd));
    // set new fd
    nfd->fd = newfd;

    // call dup handler
    if(nfd->copy) {
        if(nfd->copy(nfd, fdhandler_new)) {
            gBS->FreePool(nfd);
            return -EIO;
        }
    }

    // close old 'newfd' in case it does already exist
    if(fdhandler_new) {
        if(sys_close(newfd)) {
            // XXX: private data leak
            gBS->FreePool(nfd);
            return -EIO;
        }
    }

    // add new fd to list
    list_add_tail(&fds, &nfd->node);

    return nfd->fd;
}

SYSCALL_DEFINE2(getgroups32, int, gidsetsize, unused gid_t __user *, grouplist)
{
	if (gidsetsize < 0)
		return -EINVAL;

	return 0;
}

SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
{
    if(size<strlen(cwd)+1)
        return -1;

    strncpy(buf, cwd, size);
    return 0;
}

SYSCALL_DEFINE1(chdir, const char __user *, filename) {
    if(strlen(filename)>PATH_MAX)
        return -ENAMETOOLONG;

    strncpy(cwd, filename, PATH_MAX);
    return 0;
}

SYSCALL_DEFINE1(uname, struct utsname __user *, name)
{
	int error = 0;

	if (!name)
		return -EFAULT;

    memcpy(name, &utsname, sizeof(*name));

    return error;
}

SYSCALL_DEFINE1(close, unsigned int, fd) {
    fd_handler_t *fdhandler = get_file(fd);

    if(!fdhandler) {
        return -EBADF;
    }
    
    if(fdhandler->close)
        fdhandler->close(fdhandler);

    list_remove_tail(&fdhandler->node);
    gBS->FreePool(fdhandler);

    return 0;
}

static int init_tty(fd_handler_t* fdhandler, int realfd) {
    fd_tty_pdata_t* pdata = AllocateZeroPool(sizeof(fd_tty_pdata_t));
    fdhandler->private = pdata;

    pdata->real_type = realfd;
    pdata->winsz.ws_row = 25;
    pdata->winsz.ws_col = 80;

    fdhandler->ioctl = tty_ioctl;
    fdhandler->close = tty_close;
    fdhandler->copy = tty_copy;
    fdhandler->read = tty_read;
    fdhandler->write = tty_write;

    return 0;
}

SYSCALL_DEFINE3(fcntl64, unsigned int, fd, unsigned int, cmd,
		unused unsigned long, arg)
{
    fd_handler_t *fdhandler = get_file(fd);

    if(!fdhandler) {
        return -EBADF;
    }

    switch(cmd) {
        case F_DUPFD:
            return sys_dup2(fd, get_unused_fd());

        default:
            return -EINVAL;
    }
}

SYSCALL_DEFINE0(vfork) {
    int rc;

    // set exit handler
    rc = setjmp_stack (vfork_jmpbuf);
    if (rc) {
        // parent
        in_vfork = 0;
        return 2; // PID:2
    }

    // child
    in_vfork = 1;
    return 0;
}

SYSCALL_DEFINE4(wait4, unused pid_t, upid, unused int __user *, stat_addr,
		unused int, options, unused struct rusage __user *, ru)
{
    // XXX: we're ignoring rusage here

    if(has_vfork_status) {
        has_vfork_status = 0;
        *stat_addr = vfork_status;
        return 2; // PID:2
    }

    return -ECHILD;
}

SYSCALL_DEFINE3(poll, unused struct pollfd __user *, ufds, unused unsigned int, nfds,
		unused int, timeout_msecs)
{
    return 1;
}

SYSCALL_DEFINE3(execve, const char __user *, path,
		unused const char __user *const __user *, argv,
		unused const char __user *const __user *, envp)
{
    uefi_printf("%s(%s)\n", __func__, path);
    return 0;
}

void __syscall_init(void) {
    register_syscall(exit);
    register_syscall(exit_group);
    register_syscall(set_tid_address);
    register_syscall(ioctl);
    register_syscall(writev);
    register_syscall(write);
    register_syscall(readv);
    register_syscall(read);
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
    register_syscall(dup2);
    register_syscall(getgroups32);
    register_syscall(getcwd);
    register_syscall(chdir);
    register_syscall(uname);
    register_syscall(close);
    register_syscall(fcntl64);
    register_syscall(vfork);
    register_syscall(wait4);
    register_syscall(poll);
    register_syscall(execve);

    list_initialize(&fds);

    fd_handler_t* fdstdin = AllocateZeroPool(sizeof(fd_handler_t));
    init_tty(fdstdin, 0);
    fdstdin->fd = 0;
    list_add_tail(&fds, &fdstdin->node);

    fd_handler_t* fdstdout = AllocateZeroPool(sizeof(fd_handler_t));
    init_tty(fdstdout, 1);
    fdstdout->fd = 1;
    list_add_tail(&fds, &fdstdout->node);

    fd_handler_t* fdstderr = AllocateZeroPool(sizeof(fd_handler_t));
    init_tty(fdstderr, 2);
    fdstderr->fd = 2;
    list_add_tail(&fds, &fdstderr->node);

    snprintf(utsname.release, 65, "v%d.%02d", (gST->Hdr.Revision&0xffff0000)>>16, (gST->Hdr.Revision&0x0000ffff));
    snprintf(utsname.version, 65, "EDK II-0x%08x"/*, gST->FirmwareVendor*/, gST->FirmwareRevision);
}

long __syscall(long n, ...) {
    int i;
    long (*fn)(long,...);

    uefi_printf("syscall %d(%x)\n", n, n);

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
            //sys_exit(-1);
            return -ENOSYS;
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
