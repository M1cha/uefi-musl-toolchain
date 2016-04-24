#include <common.h>

#define MAX_SYSCALL 2048
#define register_syscall(name) sys_call_table[SYS_##name] = sys_##name;

static void* sys_call_table[MAX_SYSCALL] = {0};
static list_node_t processes;
static process_t* current_process = NULL;

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
static process_t* create_process(process_t* parent, int pid);
static void remove_process(process_t* p);

int get_unused_fd(void) {
    unsigned int fd = 0;

    UEFI_ASSERT(current_process);

    // get fd handler
    fd_handler_t *entry;
    list_for_every_entry(&(current_process->fds), entry, fd_handler_t, node) {
        if(entry->fd>=fd) {
            fd = entry->fd+1;
        }
    }

    return fd;
}

int get_unused_pid(void) {
    unsigned int pid = 0;

    // get fd handler
    process_t *entry;
    list_for_every_entry(&processes, entry, process_t, node) {
        if(entry->pid>=(int)pid) {
            pid = entry->pid+1;
        }
    }

    return pid;
}

static fd_handler_t* get_file(unsigned int fd) {
    UEFI_ASSERT(current_process);

    fd_handler_t *entry;
    list_for_every_entry(&(current_process->fds), entry, fd_handler_t, node) {
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

    UEFI_ASSERT(pdata);

    if(len==0)
        return 0;

    if(!buf)
        return -EFAULT;

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

    UEFI_ASSERT(pdata);

    if(len==0)
        return 0;

    if(!buf)
        return -EFAULT;

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

    UEFI_ASSERT(pdata);

    switch(cmd) {
        case TIOCGWINSZ:
            if(!arg) return -1;
            memcpy((void*)arg, &pdata->winsz, sizeof(struct winsize));
            return 0;

        case TIOCSWINSZ:
            if(!arg) return -1;
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
    UEFI_ASSERT(fdhandler->private);

    gBS->FreePool(fdhandler->private);
}

static int tty_copy(fd_handler_t* dst, fd_handler_t* src) {
    UEFI_ASSERT(dst);
    UEFI_ASSERT(src);

    init_tty(dst, 0);

    UEFI_ASSERT(dst->private);
    UEFI_ASSERT(src->private);

    memcpy(dst->private, src->private, sizeof(fd_tty_pdata_t));
    return 0;
}

SYSCALL_DEFINE1(settls, long, val) {
    current_process->tls = val;
    return 0;
}

SYSCALL_DEFINE0(gettls) {
    return current_process->tls;
}

#define	__W_EXITCODE(ret, sig)	((ret) << 8 | (sig))
SYSCALL_DEFINE1(exit, int, status) {
    UEFI_ASSERT(current_process);

    current_process->exit_code = status;

    if(current_process->stack_backup) {
        longjmp_stack (current_process->return_jmpbuf, 1, current_process->stack_backup);
    } else {
        longjmp (current_process->return_jmpbuf, 1);
    }
    return -1;
}

SYSCALL_DEFINE1(exit_group, int, status) {
    return sys_exit(status);
}

SYSCALL_DEFINE1(set_tid_address, int __user *, tidptr) {
    UEFI_ASSERT(current_process);

	current_process->clear_child_tid = tidptr;
	return current_process->tid;
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

    if(!vec)
        return -EFAULT;
    
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

    if(!buf)
        return -EFAULT;

    //uefi_printf("%s(%ld, 0x%x, %ld)\n", __func__, fd, buf, count);
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

    if(!vec)
        return -EFAULT;
    
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
	return current_process->pid;
}

SYSCALL_DEFINE0(getppid) {
	return current_process->ppid;
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
    if(!addr)
        return -EFAULT;

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

    UEFI_ASSERT(current_process);

	error = 0;
	switch (option) {
		case PR_GET_DUMPABLE:
			error = current_process->process_dumpable;
			break;
		case PR_SET_DUMPABLE:
			if (arg2 != 0 && arg2 != 1) {
				error = -EINVAL;
				break;
			}
			current_process->process_dumpable = arg2;
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
	return -ENOENT;
}

SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd)
{
    UEFI_ASSERT(current_process);

	fd_handler_t *fdhandler_old = get_file(oldfd);
	fd_handler_t *fdhandler_new = get_file(newfd);

    if(!fdhandler_old) {
        return -EBADF;
    }

    // allocate
    fd_handler_t* nfd = AllocateZeroPool(sizeof(fd_handler_t));
    if(!nfd) return -ENOMEM;

    // copy all data
    memcpy(nfd, fdhandler_old, sizeof(*nfd));
    nfd->node.magic = 0;
    nfd->node.next = 0;
    nfd->node.prev = 0;

    // set new fd
    nfd->fd = newfd;

    // call dup handler
    if(nfd->copy) {
        if(nfd->copy(nfd, fdhandler_old)) {
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
    list_add_tail(&(current_process->fds), &(nfd->node));

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
    UEFI_ASSERT(current_process);

    if(!buf)
        return -EFAULT;

    if(size<strlen(current_process->cwd)+1)
        return -1;

    strncpy(buf, current_process->cwd, size);
    return 0;
}

SYSCALL_DEFINE1(chdir, const char __user *, filename) {
    UEFI_ASSERT(current_process);

    if(!filename)
        return -EFAULT;

    if(strlen(filename)>PATH_MAX)
        return -ENAMETOOLONG;

    strncpy(current_process->cwd, filename, PATH_MAX);
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

    list_delete(&(fdhandler->node));
    gBS->FreePool(fdhandler);

    return 0;
}

static int init_tty(fd_handler_t* fdhandler, int realfd) {
    UEFI_ASSERT(fdhandler);

    fd_tty_pdata_t* pdata = AllocateZeroPool(sizeof(fd_tty_pdata_t));
    UEFI_ASSERT(pdata);
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

    process_t* parent = current_process;
    UEFI_ASSERT(parent);

    // allocate new process
    process_t* child = create_process(parent, get_unused_pid());
    if(!child) {
        return -ENOMEM;
    }

    // allocate stack backup
    child->stack_backup = AllocateZeroPool(stack_size);
    if(!child->stack_backup) {
        return -ENOMEM;
    }

    // set exit handler
    rc = setjmp_stack (child->return_jmpbuf, child->stack_backup);

    if (rc) {
        UEFI_ASSERT(child);
        UEFI_ASSERT(parent);
        UEFI_ASSERT(child!=parent);

        // free stack backup
        gBS->FreePool(child->stack_backup);
        child->stack_backup = NULL;

        // remove process
        remove_process(child);

        // parent
        current_process = parent;
        return child->pid;
    }

    // child
    current_process = child;
    return 0;
}

SYSCALL_DEFINE4(wait4, unused pid_t, upid, unused int __user *, stat_addr,
		unused int, options, unused struct rusage __user *, ru)
{
    // XXX: we're ignoring rusage here

    /*if(has_vfork_status) {
        has_vfork_status = 0;
        *stat_addr = vfork_status;
        return 2; // PID:2
    }*/

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

SYSCALL_DEFINE4(rt_sigaction, unused int, sig,
		unused const struct sigaction __user *, act,
		unused struct sigaction __user *, oact,
		unused size_t, sigsetsize)
{
    return -1;
}

SYSCALL_DEFINE4(rt_sigprocmask, unused int, how, unused sigset_t __user *, nset,
		unused sigset_t __user *, oset, unused size_t, sigsetsize)
{
    return -1;
}

static process_t* create_process(process_t* parent, int pid) {
    process_t* p = AllocateZeroPool(sizeof(process_t));
    UEFI_ASSERT(p);

    p->pid = pid;
    p->tid = pid;
    p->ppid = parent?parent->pid:0;
    list_initialize(&(p->fds));
    p->process_dumpable = 1;
    snprintf(p->cwd, PATH_MAX, "/");

    if(parent==NULL) {
        fd_handler_t* fdstdin = AllocateZeroPool(sizeof(fd_handler_t));
        UEFI_ASSERT(fdstdin);
        init_tty(fdstdin, 0);
        fdstdin->fd = 0;
        list_add_tail(&(p->fds), &(fdstdin->node));

        fd_handler_t* fdstdout = AllocateZeroPool(sizeof(fd_handler_t));
        UEFI_ASSERT(fdstdout);
        init_tty(fdstdout, 1);
        fdstdout->fd = 1;
        list_add_tail(&(p->fds), &(fdstdout->node));

        fd_handler_t* fdstderr = AllocateZeroPool(sizeof(fd_handler_t));
        UEFI_ASSERT(fdstderr);
        init_tty(fdstderr, 2);
        fdstderr->fd = 2;
        list_add_tail(&(p->fds), &(fdstderr->node));
    }

    else {
        fd_handler_t *entry;
        list_for_every_entry(&(parent->fds), entry, fd_handler_t, node) {

            // allocate
            fd_handler_t* nfd = AllocateZeroPool(sizeof(fd_handler_t));
            UEFI_ASSERT(nfd);

            // copy all data
            memcpy(nfd, entry, sizeof(*nfd));
            nfd->node.magic = 0;
            nfd->node.next = 0;
            nfd->node.prev = 0;

            // call dup handler
            if(nfd->copy) {
                if(nfd->copy(nfd, entry)) {
                    gBS->FreePool(nfd);
                    return NULL;
                }
            }

            // add new fd to list
            list_add_tail(&(p->fds), &(nfd->node));
        }
    }

    list_add_tail(&processes, &(p->node));

    return p;
}

static void remove_process(process_t* p) {
    UEFI_ASSERT(p);

    while(!list_is_empty(&(p->fds))) {
        fd_handler_t* fdhandler = list_remove_tail_type(&(p->fds), fd_handler_t, node);
        UEFI_ASSERT(fdhandler);

        if(fdhandler->close) {
            fdhandler->close(fdhandler);
        }
        gBS->FreePool(fdhandler);
    }

    list_delete(&(p->node));
    gBS->FreePool(p);
}

process_t* __syscall_init(void) {
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
    register_syscall(rt_sigaction);
    register_syscall(rt_sigprocmask);

    snprintf(utsname.release, 65, "v%d.%02d", (gST->Hdr.Revision&0xffff0000)>>16, (gST->Hdr.Revision&0x0000ffff));
    snprintf(utsname.version, 65, "EDK II-0x%08x"/*, gST->FirmwareVendor*/, gST->FirmwareRevision);

    list_initialize(&processes);

    process_t* p = create_process(NULL, 1);
    current_process = p;
    return p;
}

long __syscall(long n, ...) {
    int i;
    long (*fn)(long,...);

    //uefi_printf("[%d] syscall %d(%x)\n", current_process->pid, n, n);

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
