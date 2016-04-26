#include <common.h>

#define MAX_SYSCALL 2048
#define register_syscall(name) sys_call_table[SYS_##name] = sys_##name;

struct std_fd;
struct std_file;

static void* sys_call_table[MAX_SYSCALL] = {0};
static list_node_t processes;
static process_t* current_process = NULL;
static struct std_file* filesystem;

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

// file functions
typedef ssize_t (*io_fn_t)(struct std_file*, char __user *, size_t);
typedef long (*ioctl_fn_t)(struct std_file*, unsigned int, unsigned long);
typedef void (*destroy_fn_t)(struct std_file*);

struct std_file {
    // node info
    list_node_t node;
    char* name;
    list_node_t children;
    struct stat stat;
    struct std_file* parentfile;

    // operations
    io_fn_t read;
    io_fn_t write;
    ioctl_fn_t ioctl;

    // private data
    destroy_fn_t destroy;
    void* private;
};
typedef struct std_file std_file_t;

struct std_fd {
    list_node_t node;
    unsigned long fd;
    unsigned long flags;
    unsigned long pos;
    std_file_t* file;
};
typedef struct std_fd std_fd_t;

typedef struct {
    int real_type;

    int seqcnt;
    char escseq[10];

    struct winsize winsz;
} fd_tty_pdata_t;

long sys_close(unsigned int fd);
static int init_tty(std_file_t* file, int realfd);
static process_t* create_process(process_t* parent, int pid);
static void remove_process(process_t* p);

static std_file_t* get_file_by_path(const char* path, ssize_t maxlen) {
    uint32_t pos;
    uint32_t pos_start;
    char buf[PATH_MAX+1];

    if(!path || path[0]=='\0')
        return filesystem;

    if(path[0]=='/')
        path++;

    if(path[0]=='\0')
        return filesystem;

    // we have a path relative to root now
    
    std_file_t* file = filesystem;
    pos_start = 0;
    uint32_t len = maxlen>=0?(size_t)maxlen:strlen(path);
    for(pos=0; pos<len; pos++) {
        bool is_end = pos==len-1;
        char c = path[pos];

        if(c=='\0' || c=='/' || is_end) {
            uint32_t part_len = pos-pos_start;
            if(is_end && c!='\0' && c!='/') part_len++;

            memcpy(buf, &path[pos_start], part_len);
            buf[part_len] = '\0';

            if(buf[0]!='\0' && strcmp(buf, ".")) {
                if(!strcmp(buf, "..")) {
                    if(!file->parentfile || !S_ISDIR(file->parentfile->stat.st_mode)) return NULL;
                    file = file->parentfile;
                }

                else {
                    bool found_file = false;
                    std_file_t *entry;
                    list_for_every_entry(&file->children, entry, std_file_t, node) {
                        if(!strcmp(buf, entry->name)) {
                            file = entry;
                            found_file = true;
                            break;
                        }
                    }

                    if(!found_file) return NULL;

                    if(!is_end && !S_ISDIR(file->stat.st_mode))
                        return NULL;
                }
            }

            pos_start = pos+1;
        }
    }

    return file;
}

static std_file_t* new_node(const char* path, mode_t mode) {
    std_file_t* parentfile = NULL;
    char* name = NULL;

    if(path!=NULL) {
        // make path relative to root
        UEFI_ASSERT(path[0]!='\0');
        if(path[0]=='/')
            path++;
        UEFI_ASSERT(path[0]!='\0');

        uint32_t last_slash = 0;
        //uint32_t pathlen = strlen(path);
        uint32_t pos;

        for(pos=0; pos<strlen(path); pos++) {
            if(path[pos]=='/')
                last_slash = pos;
        }

        if(last_slash==0)
            parentfile=filesystem;
        else
            parentfile = get_file_by_path(path, last_slash);

        if(!parentfile) return NULL;

        name = strdup(&path[last_slash?last_slash+1:0]);
    }

    // allocate
    std_file_t* file = AllocateZeroPool(sizeof(std_file_t));
    UEFI_ASSERT(file);

    // set info
    list_initialize(&file->children);

    // this is the root node
    if(path==NULL) {
        filesystem = file;
    }

    else {
        file->name = name;
        file->parentfile = parentfile;

        // add file to parent's children
        list_add_tail(&parentfile->children, &(file->node));
    }

    file->stat.st_mode = mode;

    return file;
}

int get_unused_fd(void) {
    unsigned int fd = 0;

    UEFI_ASSERT(current_process);

    // get fd handler
    std_fd_t *entry;
    list_for_every_entry(&(current_process->fds), entry, std_fd_t, node) {
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

static std_fd_t* get_stdfd(unsigned int fd) {
    UEFI_ASSERT(current_process);

    std_fd_t *entry;
    list_for_every_entry(&(current_process->fds), entry, std_fd_t, node) {
        if(entry->fd==fd) {
            return entry;
        }
    }

    return NULL;
}


static ssize_t do_loop_readv_writev(std_file_t *file, struct iovec *iov,
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

		nr = fn(file, base, len);

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

#define TTY_PRINT_CHAR(c) do { \
    cu[0] = c; \
    if(pdata->real_type==2) \
        gST->StdErr->OutputString(gST->StdErr, (uint16_t*)cu); \
    else \
        gST->ConOut->OutputString(gST->ConOut, (uint16_t*)cu); \
} while(0)
static ssize_t tty_write(std_file_t* file, char __user * buf, size_t len) {
    size_t i;
    int j;
    uint8_t cu[4] = {0};
    fd_tty_pdata_t* pdata = file->private;

    UEFI_ASSERT(pdata);

    if(len==0)
        return 0;

    if(!buf)
        return -EFAULT;

    // check if this is stdin
    if(pdata->real_type==0)
        return -EIO;

    for(i=0; i<len; i++) {
        char c = buf[i];

        // start esc sequence
        if(c=='\e') {
            pdata->seqcnt = 0;
            continue;
        }

        if(pdata->seqcnt>=0) {
            // end of sequence
            if(c=='m') {
                pdata->escseq[pdata->seqcnt] = 0;
                char* seq = pdata->escseq+1;
                int seqlen = pdata->seqcnt-1;

                // get current attributes
                uint32_t attribute = (uint32_t)gST->ConOut->Mode->Attribute;
                uint8_t foreground = attribute & 0x07;
                uint8_t background = ((attribute >> 4) & 0x07);
                uint8_t brightness = (uint8_t) ((attribute >> 3) & 1);

                // reset
                if(seqlen==1 && seq[0]=='0') {
                    foreground = EFI_LIGHTGRAY;
                    background = EFI_BLACK;
                    brightness = 0;
                }

                // background
                else if(seqlen==2 && seq[0]=='4') {
                    uint8_t color = seq[1] - '\0';
                    switch(color) {
                        case '0':
                            background = EFI_BLACK;
                            break;
                        case '1':
                            background = EFI_RED;
                            break;
                        case '2':
                            background = EFI_GREEN;
                            break;
                        case '3':
                            background = EFI_BROWN;
                            break;
                        case '4':
                            background = EFI_BLUE;
                            break;
                        case '5':
                            background = EFI_MAGENTA;
                            break;
                        case '6':
                            background = EFI_CYAN;
                            break;
                        case '7':
                            background = EFI_LIGHTGRAY;
                            break;
                    }
                }

                // foreground
                else if(seqlen==4 && seq[1]==';' && seq[2]=='3') {
                    char cbrightness = seq[0];
                    char color = seq[3];

                    // bold
                    if(cbrightness=='1')
                        brightness = 1;
                    // regular
                    else
                        brightness = 0;

                    switch(color) {
                        case '0':
                            foreground = EFI_BLACK;
                            break;
                        case '1':
                            foreground = EFI_RED;
                            break;
                        case '2':
                            foreground = EFI_GREEN;
                            break;
                        case '3':
                            foreground = EFI_BROWN;
                            break;
                        case '4':
                            foreground = EFI_BLUE;
                            break;
                        case '5':
                            foreground = EFI_MAGENTA;
                            break;
                        case '6':
                            foreground = EFI_CYAN;
                            break;
                        case '7':
                            foreground = EFI_LIGHTGRAY;
                            break;
                    }
                }

                // set new attributes
                uint32_t nattribute = 0;
                nattribute |= foreground;
                nattribute |= background<<4;
                if(brightness)
                    nattribute |= 1<<3;

                gST->ConOut->SetAttribute(gST->ConOut, nattribute);
                pdata->seqcnt = -1;
                continue;
            }

            // invalid sequence - print out the buffer
            if(pdata->seqcnt+1>(int)sizeof(pdata->escseq)-1 || (pdata->seqcnt==0 && c!='[')) {

                TTY_PRINT_CHAR('\e');
                for(j=0; j<pdata->seqcnt; j++) {
                    TTY_PRINT_CHAR(pdata->escseq[j]);
                }
                TTY_PRINT_CHAR(c);

                pdata->seqcnt = -1;
                continue;
            }

            // write sequence character to buffer
            pdata->escseq[pdata->seqcnt++] = c;

            continue;
        }

        if(c=='\n')
            TTY_PRINT_CHAR('\r');

        TTY_PRINT_CHAR(c);
    }

    return (ssize_t)len;
}

static ssize_t tty_read(std_file_t* file, char __user * buf, size_t len) {
    fd_tty_pdata_t* pdata = file->private;
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

    for(;;) {
        // wait for key
        EFI_STATUS Status = gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &WaitIndex);
        if(EFI_ERROR (Status))
            return -EIO;

        // read key
        Status = gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
        if(EFI_ERROR(Status)) {
            return -EIO;
        }

        if(Key.ScanCode==SCAN_NULL) {
            buf[0] = Key.UnicodeChar;
            if (buf[0] == '\r')
                buf[0] = '\n';
            break;
        }
    }

    return 1;
}

static long tty_ioctl(std_file_t* file, unsigned int cmd, unsigned long arg) {
    fd_tty_pdata_t* pdata = file->private;

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

static void tty_destroy(std_file_t* file) {
    UEFI_ASSERT(file->private);

    gBS->FreePool(file->private);
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

    std_fd_t *stdfd = get_stdfd(fd);
    if(!stdfd) {
        return -EBADF;
    }
    std_file_t* file = stdfd->file;

    if(file->ioctl) {
	    rc = stdfd->file->ioctl(file, cmd, arg);
    }

    if(rc)   
        uefi_printf("invalid ioctl %x on %d\n", cmd, stdfd->fd);

    return rc;
}

SYSCALL_DEFINE3(writev, unsigned long, fd, struct iovec __user *, vec,
		unsigned long, vlen)
{
    std_fd_t *stdfd = get_stdfd(fd);
    if(!stdfd) {
        return -EBADF;
    }
    std_file_t* file = stdfd->file;

    if(!file->write) {
        return -EIO;
    }

    if(!vec)
        return -EFAULT;
    
	return do_loop_readv_writev(file, (void*)vec, vlen, file->write);
}

SYSCALL_DEFINE3(write, unsigned int, fd, const char __user *, buf,
		size_t, count)
{
    std_fd_t *stdfd = get_stdfd(fd);
    if(!stdfd) {
        return -EBADF;
    }
    std_file_t* file = stdfd->file;

    if(!file->write) {
        return -EIO;
    }

    if(!buf)
        return -EFAULT;

	return file->write(file, (void*)buf, count);
}

SYSCALL_DEFINE3(readv, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen)
{
    std_fd_t *stdfd = get_stdfd(fd);
    if(!stdfd) {
        return -EBADF;
    }
    std_file_t* file = stdfd->file;

    if(!file->read) {
        return -EIO;
    }

    if(!vec)
        return -EFAULT;
    
	return do_loop_readv_writev(file, (void*)vec, vlen, file->read);
}

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
    std_fd_t *stdfd = get_stdfd(fd);
    if(!stdfd) {
        return -EBADF;
    }
    std_file_t* file = stdfd->file;

    if(!file->read) {
        return -EIO;
    }

	return file->read(file, (void*)buf, count);
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
    UEFI_ASSERT(current_process);

    //uefi_printf("open(%s, %d, %d)\n", filename, flags, mode);
    // get file
    std_file_t* file = get_file_by_path(filename, -1);
    if(!file)
        return -ENOENT;

    // allocate
    std_fd_t* nfd = AllocateZeroPool(sizeof(std_fd_t));
    if(!nfd) return -ENOMEM;

    // set data
    nfd->fd = get_unused_fd();
    nfd->flags = flags;
    nfd->file = file;

    // add new fd to list
    list_add_tail(&(current_process->fds), &(nfd->node));

	return nfd->fd;
}

SYSCALL_DEFINE3(dup3, unsigned int, oldfd, unsigned int, newfd, int, flags) {
    UEFI_ASSERT(current_process);

	std_fd_t *stdfd_old = get_stdfd(oldfd);
	std_fd_t *stdfd_new = get_stdfd(newfd);

    if(!stdfd_old) {
        return -EBADF;
    }

    // allocate
    std_fd_t* nfd = AllocateZeroPool(sizeof(std_fd_t));
    if(!nfd) return -ENOMEM;

    // copy all data
    nfd->fd = newfd;
    nfd->flags = flags;
    nfd->file = stdfd_old->file;

    // close old 'newfd' in case it does already exist
    if(stdfd_new) {
        if(sys_close(newfd)) {
            gBS->FreePool(nfd);
            return -EIO;
        }
    }

    // add new fd to list
    list_add_tail(&(current_process->fds), &(nfd->node));

    return nfd->fd;
}

SYSCALL_DEFINE2(dup2, unsigned int, oldfd, unsigned int, newfd) {
	std_fd_t *stdfd_old = get_stdfd(oldfd);
    return sys_dup3(oldfd, newfd, stdfd_old->flags);
}

SYSCALL_DEFINE1(dup, unsigned int, fildes) {
    return sys_dup2(fildes, get_unused_fd());
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
    std_fd_t *stdfd = get_stdfd(fd);
    if(!stdfd) {
        return -EBADF;
    }
    //std_file_t* file = stdfd->file;
    // XXX: do a flush?

    list_delete(&(stdfd->node));
    gBS->FreePool(stdfd);

    return 0;
}

static int init_tty(std_file_t* file, int realfd) {
    UEFI_ASSERT(file);

    fd_tty_pdata_t* pdata = AllocateZeroPool(sizeof(fd_tty_pdata_t));
    UEFI_ASSERT(pdata);
    file->private = pdata;

    pdata->real_type = realfd;
    pdata->seqcnt = -1;
    pdata->winsz.ws_row = 25;
    pdata->winsz.ws_col = 80;

    file->ioctl = tty_ioctl;
    file->read = tty_read;
    file->write = tty_write;
    file->destroy = tty_destroy;

    return 0;
}

SYSCALL_DEFINE3(fcntl64, unsigned int, fd, unsigned int, cmd,
		unused unsigned long, arg)
{
    std_fd_t *stdfd = get_stdfd(fd);
    if(!stdfd) {
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

    if(parent!=NULL) {
        std_fd_t *entry;
        list_for_every_entry(&(parent->fds), entry, std_fd_t, node) {

            // allocate
            std_fd_t* nfd = AllocateZeroPool(sizeof(std_fd_t));
            UEFI_ASSERT(nfd);

            // copy all data
            nfd->fd = entry->fd;
            nfd->flags = entry->flags;
            nfd->file = entry->file;

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
        std_fd_t* stdfd = list_peek_tail_type(&(p->fds), std_fd_t, node);
        UEFI_ASSERT(stdfd);

        // close
        sys_close(stdfd->fd);
    }

    list_delete(&(p->node));
    gBS->FreePool(p);
}

static ssize_t null_write(unused std_file_t* file, unused char __user * buf, size_t len) {
    return len;
}

static ssize_t null_read(unused std_file_t* file, unused char __user * buf, unused size_t len) {
    return 0;
}

SYSCALL_DEFINE2(stat64, const char __user *, filename,
		struct stat __user *, statbuf)
{
	UEFI_ASSERT(current_process);

    if(!filename || !statbuf)
        return -EFAULT;

    // get file
    std_file_t* file = get_file_by_path(filename, -1);
    if(!file)
        return -ENOENT;

    // copy struct data
    memcpy(statbuf, &file->stat, sizeof(*statbuf));

    // calculate directory size
    if(S_ISDIR(file->stat.st_mode)) {
        unsigned int curpos = 0;
        std_file_t *entry;
        list_for_every_entry(&file->children, entry, std_file_t, node) {
            size_t namelen = strlen(entry->name);
            size_t reclen = ROUNDUP(sizeof(struct linux_dirent64) + namelen+1, sizeof(UINTN));

            curpos += reclen;
        }

        statbuf->st_size = curpos;
    }

	return 0;
}

SYSCALL_DEFINE2(lstat64, const char __user *, filename,
		struct stat __user *, statbuf)
{
	return sys_stat64(filename, statbuf);
}

SYSCALL_DEFINE3(getdents64, unsigned int, fd,
		struct linux_dirent64 __user *, dirent, unsigned int, count)
{
    std_fd_t *stdfd = get_stdfd(fd);
    if(!stdfd) {
        return -EBADF;
    }
    std_file_t* file = stdfd->file;

    if(!dirent)
        return -EFAULT;

    char* buf = (char*)dirent;
    long bytes_read = -EINVAL;
    unsigned int curpos = 0;
    std_file_t *entry;
    list_for_every_entry(&file->children, entry, std_file_t, node) {
        size_t namelen = strlen(entry->name);
        size_t reclen = ROUNDUP(sizeof(*dirent) + namelen+1, sizeof(UINTN));

        // skip entries we've already read/seeked past
        if(stdfd->pos>=curpos+reclen) {
            curpos += reclen;
            continue;
        }

        // buffer size check
        if(count<reclen)
            goto done;

        // write dirent
        struct linux_dirent64* curdirent = (void*)buf;
        curdirent->d_ino = 0;
        curdirent->d_off = bytes_read + reclen;
        curdirent->d_reclen = reclen;
        curdirent->d_type = 0;
        strcpy(curdirent->d_name, entry->name);
        buf += reclen;
        count-=reclen;

        // update return value
        if(bytes_read<0) bytes_read = 0;
        bytes_read += reclen;

        // advance file position
        curpos += reclen;
        stdfd->pos = curpos;
    }

    if(buf==(char*)dirent)
        bytes_read = 0;

done:
    return bytes_read;
}

SYSCALL_DEFINE5(mremap, unsigned long, addr, unsigned long, old_len,
		unsigned long, new_len, unsigned long, flags,
		unsigned long, new_addr)
{
	/* insanity checks first */
	old_len = PAGE_ALIGN(old_len);
	new_len = PAGE_ALIGN(new_len);
	if (old_len == 0 || new_len == 0)
		return (unsigned long) -EINVAL;

	if (addr & ~PAGE_MASK)
		return -EINVAL;

	if (flags & MREMAP_FIXED && new_addr != addr)
		return (unsigned long) -EINVAL;

    long rc = sys_mmap2(addr, new_len, 0, 0, -1, 0);
    if(rc>=0) {
        memcpy((void*)rc, (void*)addr, old_len);
        sys_munmap(addr, old_len);
    }

    return rc;
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
    register_syscall(dup3);
    register_syscall(dup2);
    register_syscall(dup);
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
    register_syscall(stat64);
    register_syscall(lstat64);
    register_syscall(getdents64);
    register_syscall(mremap);

    snprintf(utsname.release, 65, "v%d.%02d", (gST->Hdr.Revision&0xffff0000)>>16, (gST->Hdr.Revision&0x0000ffff));
    snprintf(utsname.version, 65, "EDK II-0x%08x"/*, gST->FirmwareVendor*/, gST->FirmwareRevision);

    list_initialize(&processes);
    filesystem = new_node(NULL, S_IFDIR|S_IRWXU);
    strcpy(filesystem->name, "/");

    std_file_t* file = new_node("/dev", S_IFDIR|S_IRWXU);
    UEFI_ASSERT(file);

    file = new_node("/proc", S_IFDIR|S_IRWXU);
    UEFI_ASSERT(file);
    file = new_node("/sys", S_IFDIR|S_IRWXU);
    UEFI_ASSERT(file);
    file = new_node("/mnt", S_IFDIR|S_IRWXU);
    UEFI_ASSERT(file);
    file = new_node("/root", S_IFDIR|S_IRWXU);
    UEFI_ASSERT(file);
    file = new_node("/usr", S_IFDIR|S_IRWXU);
    UEFI_ASSERT(file);

    file = new_node("/dev/null", S_IFCHR|S_IRWXU);
    UEFI_ASSERT(file);
    file->read = null_read;
    file->write = null_write;

    std_file_t* fstdin = new_node("/dev/stdin", S_IFCHR|S_IRWXU);
    UEFI_ASSERT(fstdin);
    init_tty(fstdin, 0);

    std_file_t* fstdout = new_node("/dev/stdout", S_IFCHR|S_IRWXU);
    UEFI_ASSERT(fstdout);
    init_tty(fstdout, 1);

    std_file_t* fstderr = new_node("/dev/stderr", S_IFCHR|S_IRWXU);
    UEFI_ASSERT(fstderr);
    init_tty(fstderr, 2);

    process_t* p = create_process(NULL, 1);
    current_process = p;

    sys_open("/dev/stdin", 0, 0);
    sys_open("/dev/stdout", 0, 0);
    sys_open("/dev/stderr", 0, 0);

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
