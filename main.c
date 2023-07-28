#include <linux/fdtable.h>
#include <linux/utsname.h>
#include <net/inet_sock.h>

#define AF_INET 2
#define AF_INET6 10

const char* NOPATH = "NOPATH";

MODULE_LICENSE("GPL");

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs*);

static sys_call_ptr_t *sys_call_table;

static sys_call_ptr_t old_execve;
static sys_call_ptr_t old_exit;
static sys_call_ptr_t old_kill;

static sys_call_ptr_t old_open;
static sys_call_ptr_t old_openat;
static sys_call_ptr_t old_creat;
static sys_call_ptr_t old_mkdir;
static sys_call_ptr_t old_rename;
static sys_call_ptr_t old_rmdir;
static sys_call_ptr_t old_link;
static sys_call_ptr_t old_linkat;
static sys_call_ptr_t old_unlink;
static sys_call_ptr_t old_unlinkat;
static sys_call_ptr_t old_symlink;
static sys_call_ptr_t old_symlinkat;
static sys_call_ptr_t old_chmod;
static sys_call_ptr_t old_fchmod;
static sys_call_ptr_t old_fchmodat;
static sys_call_ptr_t old_chown;
static sys_call_ptr_t old_fchown;
static sys_call_ptr_t old_lchown;
static sys_call_ptr_t old_fchownat;
static sys_call_ptr_t old_umask;
static sys_call_ptr_t old_capset;
static sys_call_ptr_t old_mount;
static sys_call_ptr_t old_umount2;

static sys_call_ptr_t old_uselib;

static sys_call_ptr_t old_setuid;
static sys_call_ptr_t old_setgid;
static sys_call_ptr_t old_setreuid;
static sys_call_ptr_t old_setregid;
static sys_call_ptr_t old_setresuid;
static sys_call_ptr_t old_setresgid;

static sys_call_ptr_t old_sethostname;
static sys_call_ptr_t old_setdomainname;
static sys_call_ptr_t old_connect;
static sys_call_ptr_t old_accept;
static sys_call_ptr_t old_accept4;

static char* get_fd_path(long unsigned int fd, char *tmp) {

        char *pathname;

        if (fd != 4294967196) {
                struct file *file;
                struct path *path;
                struct files_struct *files;

                files = current->files;

                spin_lock(&files->file_lock);
                file = fcheck_files(files, (int)fd);
                if (!file) {
                        spin_unlock(&files->file_lock);
                        return "ERROR";
                }

                path = &file->f_path;
                path_get(path);
                spin_unlock(&files->file_lock);

                tmp = (char *)__get_free_page(GFP_KERNEL);
                if (!tmp) {
                        path_put(path);
                        return "ERROR";
                }

                pathname = d_path(path, tmp, PAGE_SIZE);
                path_put(path);

                if (IS_ERR(pathname)) {
                        free_page((unsigned long)tmp);
                        return "ERROR";
                }


                return pathname;
        } else {
                return NOPATH;
        }
}


static asmlinkage long new_open(const struct pt_regs *regs) {

        int result;
        result = old_open(regs);

        if (__builtin_types_compatible_p(typeof(regs->dx), mode_t)) {
                // open_file, process_id, epoch, result, target_fiename, flags, mode
                printk("open,%lld-%llo,%lu,%d,%s,%d,%o", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, (int)regs->si, (mode_t)regs->dx);
        } else {
                // open_file, process_id, epoch, result, target_fiename, flags
                printk("open,%lld-%llo,%lu,%d,%s,%d", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, (int)regs->si);
        }


        return result;
}

static asmlinkage long new_openat(const struct pt_regs *regs) {

        int result;
        result = old_openat(regs);

        char *pathname;
        char *tmp;
        pathname = get_fd_path(regs->di, tmp);


        if (__builtin_types_compatible_p(typeof(regs->cx), mode_t)) {
                // open_file, process_id, epoch, rseult, target_fiename, pathname, flags, mode
                printk("openat,%lld-%llo,%lu,%d,%s,%s,%d,%o", current->self_exec_id, current->start_time, get_seconds(), result, pathname, (char*)regs->si, (int)regs->dx, (mode_t)regs->cx);
        } else {
                // open_file, process_id, epoch, result, target_fiename, pathname, flags
                printk("openat,%lld-%llo,%lu,%d,%s,%s,%d", current->self_exec_id, current->start_time, get_seconds(), result, pathname, (char*)regs->si, (int)regs->dx);
        }

        if (strcmp(pathname, NOPATH) != 0) {
                free_page((unsigned long)tmp);
        }

        return result;
}

static asmlinkage long new_creat(const struct pt_regs *regs) {
        int result;
        result = old_creat(regs);

        // creat, process_id, epoch, rseult, pathname, flags
        printk("creat,%lld-%llo,%lu,%d,%s,%o", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, (mode_t)regs->si);

        return result;
}

static asmlinkage long new_mkdir(const struct pt_regs *regs) {
        int result;
        result = old_mkdir(regs);

        // mkdir, process_id, epoch, result, pathname, mode
        printk("mkdir,%lld-%llo,%lu,%d,%s,%o", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, (mode_t)regs->si);

        return result;
}

static asmlinkage long new_rename(const struct pt_regs *regs) {
        int result;
        result = old_rename(regs);

        // rename, process_id, epoch, result, oldpath, newpath
        printk("rename,%lld-%llo,%lu,%d,%s,%s", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, (char*)regs->si);

        return result;
}

static asmlinkage long new_rmdir(const struct pt_regs *regs) {
        int result;
        result = old_rmdir(regs);

        // rmdir, process_id, epoch, rseult, pathname
        printk("rmdir,%lld-%llo,%lu,%d,%s", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di);

        return result;
}

static asmlinkage long new_link(const struct pt_regs *regs) {
        int result;
        result = old_link(regs);

        // link, process_id, epoch, oldpath, newpath
        printk("link,%lld-%llo,%lu,%d,%s,%s", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, (char*)regs->si);

        return result;
}

static asmlinkage long new_linkat(const struct pt_regs *regs) {
        int result;
        result = old_linkat(regs);

        char *old_dirpath;
        char *new_dirpath;
        char *old_tmp;
        char *new_tmp;

        old_dirpath = get_fd_path(regs->di, old_tmp);
        new_dirpath = get_fd_path(regs->dx, new_tmp);


        // linkat, process_id, epoch, result, old_dirpath, new_dirpath, oldpath, newpath
        printk("linkat,%lld-%llo,%lu,%d,%s,%s,%s,%s,%d", current->self_exec_id, current->start_time, get_seconds(), result, old_dirpath, new_dirpath, (char*)regs->dx, (char*)regs->cx, (int)regs->r8);


        if (strcmp(old_dirpath, NOPATH) != 0) {
                free_page((unsigned long)old_tmp);
        }

        if (strcmp(new_dirpath, NOPATH) != 0) {
                free_page((unsigned long)new_tmp);
        }

        return result;
}

static asmlinkage long new_unlink(const struct pt_regs *regs) {
        int result;
        result = old_unlink(regs);

        // unlink, process_id, epoch, result, pathname
        printk("unlink,%lld-%llo,%lu,%d,%s", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di);

        return result;
}


static asmlinkage long new_unlinkat(const struct pt_regs *regs) {
        int result;
        result = old_unlinkat(regs);

        char *dirpath;
        char *tmp;
        dirpath = get_fd_path(regs->di, tmp);


        // unlinkat, process_id, epoch, result, dirpath, pathname
        printk("unlinkat,%lld-%llo,%lu,%d,%s,%s", current->self_exec_id, current->start_time, get_seconds(), result, dirpath, (char*)regs->si);

        if (strcmp(dirpath, NOPATH) != 0) {
                free_page((unsigned long)tmp);
        }


        return result;
}

static asmlinkage long new_symlink(const struct pt_regs *regs) {
        int result;
        result = old_symlink(regs);

        // symlink, process_id, epoch, result, target, linkpath
        printk("symlink,%lld-%llo,%lu,%d,%s,%s", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, (char*)regs->si);

        return result;
}

static asmlinkage long new_symlinkat(const struct pt_regs *regs) {
        int result;
        result = old_symlinkat(regs);

        char *dirpath;
        char *tmp;
        dirpath = get_fd_path(regs->di, tmp);


        // symlinkat, process_id, epoch, result, target, newdir_path, linkpath
        printk("symlink,%lld-%llo,%lu,%d,%s,%s,%s", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, dirpath, (char*)regs->dx);

        if (strcmp(dirpath, NOPATH) != 0) {
                free_page((unsigned long)tmp);
        }

        return result;
}

static asmlinkage long new_chmod(const struct pt_regs *regs) {
        int result;
        result = old_chmod(regs);

        // chmod, process_id, epoch, rseult, pathname, mode
        printk("chmod,%lld-%llo,%lu,%d,%s,%o", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, (mode_t)regs->si);

        return result;
}

static asmlinkage long new_fchmod(const struct pt_regs *regs) {
        int result;
        result = old_fchmod(regs);

        char *pathname;
        char *tmp;
        pathname = get_fd_path(regs->di, tmp);


        // fchmod, process_id, epoch, result, pathname, mode
        printk("fchmod,%lld-%llo,%lu,%d,%s,%o", current->self_exec_id, current->start_time, get_seconds(), result, pathname, (mode_t)regs->si);

        if (strcmp(pathname, NOPATH) != 0) {
                free_page((unsigned long)tmp);
        }

        return result;
}

static asmlinkage long new_fchmodat(const struct pt_regs *regs) {
        int result;
        result = old_fchmodat(regs);

        char *dirpath;
        char *tmp;
        dirpath = get_fd_path(regs->di, tmp);


        // fchmodat, process_id, epoch, result, dirpath, pathname, mode, flags
        printk("fchmodat,%lld-%llo,%lu,%d,%s,%s,%o,%d", current->self_exec_id, current->start_time, get_seconds(), result, dirpath, (char*)regs->si, (mode_t)regs->dx, (int)regs->cx);

        if (strcmp(dirpath, NOPATH) != 0) {
                free_page((unsigned long)tmp);
        }

        return result;
}


static asmlinkage long new_chown(const struct pt_regs *regs) {
        int result;
        result = old_chown(regs);

        // chown, process_id, epoch, rseult, pathname, owner, group
        printk("chown,%lld-%llo,%lu,%d,%s,%d,%d", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, (uid_t)regs->si, (gid_t)regs->dx);

        return result;
}

static asmlinkage long new_fchown(const struct pt_regs *regs) {
        int result;
        result = old_fchown(regs);

        char *pathname;
        char *tmp;
        pathname = get_fd_path(regs->di, tmp);

        // fchown, process_id, epoch, result, pathname, owner, group
        printk("chown,%lld-%llo,%lu,%d,%s,%d,%d", current->self_exec_id, current->start_time, get_seconds(), result, pathname, (uid_t)regs->si, (gid_t)regs->dx);

        if (strcmp(pathname, NOPATH) != 0) {
                free_page((unsigned long)tmp);
        }

        return result;
}

static asmlinkage long new_lchown(const struct pt_regs *regs) {
        int result;
        result = old_lchown(regs);

        // lchown, process_id, epoch, result, pathname, owner, group
        printk("lchown,%lld-%llo,%lu,%d,%s,%d,%d", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, (uid_t)regs->si, (gid_t)regs->dx);

        return result;
}

static asmlinkage long new_fchownat(const struct pt_regs *regs) {
        int result;
        result = old_fchownat(regs);

        char *dirpath;
        char *tmp;
        dirpath = get_fd_path(regs->di, tmp);

        // fchownat, process_id, epoch, result, dirpath, owner, group
        printk("fchownat,%lld-%llo,%lu,%d,%s,%s,%d,%d", current->self_exec_id, current->start_time, get_seconds(), result, dirpath, (char*)regs->si, (uid_t)regs->dx, (gid_t)regs->cx);

        if (strcmp(dirpath, NOPATH) != 0) {
                free_page((unsigned long)tmp);
        }

        return result;
}

static asmlinkage long new_umask(const struct pt_regs *regs) {
        int result;
        result = old_umask(regs);

        // umask, process_id, epoch, result, dirpath, owner, group
        printk("umask,%lld-%llo,%lu,%d,%o", current->self_exec_id, current->start_time, get_seconds(), result, (mode_t)regs->di);

        return result;
}

static asmlinkage long new_capset(const struct pt_regs *regs) {
        int result;
        result = old_capset(regs);

        cap_user_data_t datap;
        datap = (cap_user_data_t)regs->si;

        // capset, process_id, epoch, result, effective, permitted, inheritable
        printk("capset,%lld-%llo,%lu,%d,%o,%o,%o", current->self_exec_id, current->start_time, get_seconds(), result, datap->effective, datap->permitted, datap->inheritable);

        return old_capset(regs);
}

static asmlinkage long new_mount(const struct pt_regs *regs) {
        int result;
        result = old_mount(regs);

        // mount, process_id, epoch, result, source, target, filesystemtype, mountflags
        printk("mount,%lld-%llo,%lu,%d,%s,%s,%s,%ld", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, (char*)regs->si, (char*)regs->dx, (unsigned long)regs->cx);

        return result;
}

static asmlinkage long new_umount2(const struct pt_regs *regs) {
        int result;
        result = old_umount2(regs);

        // umount2, process_id, epoch, result, target, flags
        printk("umount2,%lld-%llo,%lu,%d,%s,%d", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di, (int)regs->si);

        return result;
}

static asmlinkage long new_uselib(const struct pt_regs *regs) {
        int result;
        result = old_uselib(regs);

        // uselib, process_id, epoch, result, library
        printk("uselib,%lld-%llo,%lu,%d,%s", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di);

        return result;
}

static asmlinkage long new_setuid(const struct pt_regs *regs) {

        int result;
        result = old_setuid(regs);

        // fchownat, process_id, epoch, result, uid
        printk("setuid,%lld-%llo,%lu,%d,%d", current->self_exec_id, current->start_time, get_seconds(), result, (uid_t)regs->di);

        return result;
}

static asmlinkage long new_setgid(const struct pt_regs *regs) {

        int result;
        result = old_setgid(regs);

        // fchownat, process_id, epoch, result, gid
        printk("setgid,%lld-%llo,%lu,%d,%d", current->self_exec_id, current->start_time, get_seconds(), result, (gid_t)regs->di);

        return result;
}

static asmlinkage long new_setreuid(const struct pt_regs *regs) {

        int result;
        result = old_setreuid(regs);

        // fchownat, process_id, epoch, result, ruid, euid
        printk("setreuid,%lld-%llo,%lu,%d,%d,%d", current->self_exec_id, current->start_time, get_seconds(), result, (uid_t)regs->di, (uid_t)regs->si);

        return result;
}

static asmlinkage long new_setregid(const struct pt_regs *regs) {

        int result;
        result = old_setregid(regs);

        // fchownat, process_id, epoch, result, rgid, egid
        printk("setregid,%lld-%llo,%lu,%d,%d,%d", current->self_exec_id, current->start_time, get_seconds(), result, (gid_t)regs->di, (gid_t)regs->si);

        return result;
}

static asmlinkage long new_setresuid(const struct pt_regs *regs) {

        int result;
        result = old_setresuid(regs);

        // fchownat, process_id, epoch, result, ruid, euid, suid
        printk("setresuid,%lld-%llo,%lu,%d,%d,%d,%d", current->self_exec_id, current->start_time, get_seconds(), result, (uid_t)regs->di, (uid_t)regs->si, (uid_t)regs->dx);

        return result;
}

static asmlinkage long new_setresgid(const struct pt_regs *regs) {

        int result;
        result = old_setresgid(regs);

        // fchownat, process_id, epoch, result, rgid, egid, sgid
        printk("setresgid,%lld-%llo,%lu,%d,%d,%d,%d", current->self_exec_id, current->start_time, get_seconds(), result, (gid_t)regs->di, (gid_t)regs->si, (uid_t)regs->dx);

        return result;
}

static asmlinkage long new_sethostname(const struct pt_regs *regs) {

        int result;
        result = old_sethostname(regs);

        // fchownat, process_id, epoch, result, hostname
        printk("sethostname,%lld-%llo,%lu,%d,%s", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di);

        return result;
}

static asmlinkage long new_setdomainname(const struct pt_regs *regs) {

        int result;
        result = old_setdomainname(regs);

        // fchownat, process_id, epoch, result, hostname
        printk("setdomainname,%lld-%llo,%lu,%d,%s", current->self_exec_id, current->start_time, get_seconds(), result, (char*)regs->di);

        return result;
}

static asmlinkage long new_connect(const struct pt_regs *regs) {

        int result;
        result = old_connect(regs);

        struct sockaddr_in *sin = (struct sockaddr_in*)regs->si;
        struct in_addr *addr = &sin->sin_addr;

        int family = sin->sin_family;

        // connect, process_id, epoch, result, address family, ip address, port
        if (family == AF_INET) {
                printk("connect,%lld-%llo,%lu,%d,%d,%pI4,%d", current->self_exec_id, current->start_time, get_seconds(), result, family, &addr->s_addr, ntohs(sin->sin_port));
        } else {
                printk("connect,%lld-%llo,%lu,%d,%d,%pI6,%d", current->self_exec_id, current->start_time, get_seconds(), result, family, &addr->s_addr, ntohs(sin->sin_port));
        }

        return result;
}

static asmlinkage long new_accept(const struct pt_regs *regs) {
        struct sockaddr_in *sin = (struct sockaddr_in*)regs->si;
        struct in_addr *addr = &sin->sin_addr;

        int family = sin->sin_family;

        // accept, process_id, epoch, address family, ip address, port
        if (family == AF_INET) {
                printk("accept,%lld-%llo,%lu,%d,%pI4,%d", current->self_exec_id, current->start_time, get_seconds(), family, &addr->s_addr, ntohs(sin->sin_port));
        } else {
                printk("accept,%lld-%llo,%lu,%d,%pI6,%d", current->self_exec_id, current->start_time, get_seconds(), family, &addr->s_addr, ntohs(sin->sin_port));
        }

        return old_accept(regs);
}

static asmlinkage long new_accept4(const struct pt_regs *regs) {
        struct sockaddr_in *sin = (struct sockaddr_in*)regs->si;
        struct in_addr *addr = &sin->sin_addr;

        int family = sin->sin_family;

        if (family == AF_INET) {
                printk("accept4,%lld-%llo,%lu,%d,%pI4,%d,%d", current->self_exec_id, current->start_time, get_seconds(), family, &addr->s_addr, ntohs(sin->sin_port), (int)regs->cx);
        } else {
                printk("accept4,%lld-%llo,%lu,%d,%pI6,%d,%d", current->self_exec_id, current->start_time, get_seconds(), family, &addr->s_addr, ntohs(sin->sin_port), (int)regs->cx);
        }

        return old_accept4(regs);
}

static asmlinkage long new_execve(const struct pt_regs *regs) {
        char** args = (char**)regs->si;
        int i;
        size_t total_length;

        for (i = 0; args[i] != NULL; i++) {
                total_length += strlen(args[i]) + 2;
        }

        char command_line[total_length];
        int offset = 0;

        for (i = 0; args[i] != NULL; i++) {
                int len = strlen(args[i]);
                memcpy(command_line + offset, args[i], len);
                offset += len;

                if (args[i + 1] != NULL) {
                        command_line[offset] = ' ';
                        offset++;
                }
        }
        command_line[offset] = '\0';

        // process_create, process_id, epoch, parent_id, my_name, command_line, my_pid, hostname, username, start_time + env?
        printk("execve,%lld-%llo,%lu,%lld-%llo,%s,%s,%lld,%d", current->self_exec_id, current->start_time, get_seconds(), current->parent->self_exec_id, current->parent->start_time, (char*)regs->di, command_line, current->self_exec_id, current_uid().val);

        return old_execve(regs);
}


static asmlinkage long new_exit(const struct pt_regs *regs) {
        // exit, process_id, epoch
        printk("exit,%lld-%llu,%lu", current->self_exec_id, current->start_time, get_seconds());

        return old_exit(regs);
}

static asmlinkage long new_kill(const struct pt_regs *regs) {
        // kill, process_id, epoch, pid, sig
        printk("kill,%lld-%llo,%lu,%d,%d", current->self_exec_id, current->start_time, get_seconds(), (int)regs->di, (int)regs->si);

        return old_kill(regs);
}


inline void mywrite_cr0(unsigned long val) {
        unsigned long __force_order;

        asm volatile("mov %0,%%cr0": "+r" (val), "+m" (__force_order));
}

static void enable_write_protection(void) {
        unsigned long cr0 = read_cr0();
        set_bit(16, &cr0);
        mywrite_cr0(cr0);
}

static void disable_write_protection(void) {
        unsigned long cr0 = read_cr0();
        clear_bit(16, &cr0);
        mywrite_cr0(cr0);
}

static int __init syscall_edrhook_init(void) {
        sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");
        old_execve = sys_call_table[__NR_execve];
        old_exit = sys_call_table[__NR_exit];
        old_kill = sys_call_table[__NR_kill];

        old_open = sys_call_table[__NR_open];
        old_openat = sys_call_table[__NR_openat];
        old_creat = sys_call_table[__NR_creat];
        old_mkdir = sys_call_table[__NR_mkdir];
        old_rename = sys_call_table[__NR_rename];
        old_rmdir = sys_call_table[__NR_rmdir];
        old_link = sys_call_table[__NR_link];
        old_linkat = sys_call_table[__NR_linkat];
        old_unlink = sys_call_table[__NR_unlink];
        old_unlinkat = sys_call_table[__NR_unlinkat];
        old_symlink = sys_call_table[__NR_symlink];
        old_symlinkat = sys_call_table[__NR_symlinkat];
        old_chmod = sys_call_table[__NR_chmod];
        old_fchmod = sys_call_table[__NR_fchmod];
        old_fchmodat = sys_call_table[__NR_fchmodat];
        old_chown = sys_call_table[__NR_chown];
        old_fchown = sys_call_table[__NR_fchown];
        old_lchown = sys_call_table[__NR_lchown];
        old_fchownat = sys_call_table[__NR_fchownat];
        old_umask = sys_call_table[__NR_umask];
        old_capset = sys_call_table[__NR_capset];
        old_mount = sys_call_table[__NR_mount];
        old_umount2 = sys_call_table[__NR_umount2];

        old_uselib = sys_call_table[__NR_uselib];

        old_setuid = sys_call_table[__NR_setuid];
        old_setgid = sys_call_table[__NR_setgid];
        old_setreuid = sys_call_table[__NR_setreuid];
        old_setregid = sys_call_table[__NR_setregid];
        old_setresuid = sys_call_table[__NR_setresuid];
        old_setresgid = sys_call_table[__NR_setresgid];

        old_sethostname = sys_call_table[__NR_sethostname];
        old_setdomainname = sys_call_table[__NR_setdomainname];
        old_connect = sys_call_table[__NR_connect];
        old_accept = sys_call_table[__NR_accept];
        old_accept4 = sys_call_table[__NR_accept4];


        disable_write_protection();
        sys_call_table[__NR_execve] = new_execve;
        sys_call_table[__NR_exit] = new_exit;
        sys_call_table[__NR_kill] = new_kill;

        sys_call_table[__NR_open] = new_open;
        sys_call_table[__NR_openat] = new_openat;
        sys_call_table[__NR_creat] = new_creat;
        sys_call_table[__NR_mkdir] = new_mkdir;
        sys_call_table[__NR_rename] = new_rename;
        sys_call_table[__NR_rmdir] = new_rmdir;
        sys_call_table[__NR_link] = new_link;
        sys_call_table[__NR_linkat] = new_linkat;
        sys_call_table[__NR_unlink] = new_unlink;
        sys_call_table[__NR_unlinkat] = new_unlinkat;
        sys_call_table[__NR_symlink] = new_symlink;
        sys_call_table[__NR_symlinkat] = new_symlinkat;
        sys_call_table[__NR_chmod] = new_chmod;
        sys_call_table[__NR_fchmod] = new_fchmod;
        sys_call_table[__NR_fchmodat] = new_fchmodat;
        sys_call_table[__NR_chown] = new_chown;
        sys_call_table[__NR_fchown] = new_fchown;
        sys_call_table[__NR_lchown] = new_lchown;
        sys_call_table[__NR_fchownat] = new_fchownat;
        sys_call_table[__NR_umask] = new_umask;
        sys_call_table[__NR_capset] = new_capset;
        sys_call_table[__NR_mount] = new_mount;
        sys_call_table[__NR_umount2] = new_umount2;

        sys_call_table[__NR_uselib] = new_uselib;

        sys_call_table[__NR_setuid] = new_setuid;
        sys_call_table[__NR_setgid] = new_setgid;
        sys_call_table[__NR_setreuid] = new_setreuid;
        sys_call_table[__NR_setregid] = new_setregid;
        sys_call_table[__NR_setresuid] = new_setresuid;
        sys_call_table[__NR_setresgid] = new_setresgid;

        sys_call_table[__NR_sethostname] = new_sethostname;
        sys_call_table[__NR_setdomainname] = new_setdomainname;
        sys_call_table[__NR_connect] = new_connect;
        sys_call_table[__NR_accept] = new_accept;
        sys_call_table[__NR_accept4] = new_accept4;
        enable_write_protection();

        printk("HELLO %s", utsname()->nodename);
        print_context();
        return 0;
}

static void __exit syscall_edrhook_exit(void) {
        disable_write_protection();
        sys_call_table[__NR_execve] = old_execve;
        sys_call_table[__NR_exit] = old_exit;
        sys_call_table[__NR_kill] = old_kill;

        sys_call_table[__NR_open] = old_open;
        sys_call_table[__NR_openat] = old_openat;
        sys_call_table[__NR_creat] = old_creat;
        sys_call_table[__NR_mkdir] = old_mkdir;
        sys_call_table[__NR_rename] = old_rename;
        sys_call_table[__NR_rmdir] = old_rmdir;
        sys_call_table[__NR_link] = old_link;
        sys_call_table[__NR_linkat] = old_linkat;
        sys_call_table[__NR_unlink] = old_unlink;
        sys_call_table[__NR_unlinkat] = old_unlinkat;
        sys_call_table[__NR_symlink] = old_symlink;
        sys_call_table[__NR_symlinkat] = old_symlinkat;
        sys_call_table[__NR_chmod] = old_chmod;
        sys_call_table[__NR_fchmod] = old_fchmod;
        sys_call_table[__NR_fchmodat] = old_fchmodat;
        sys_call_table[__NR_chown] = old_chown;
        sys_call_table[__NR_fchown] = old_fchown;
        sys_call_table[__NR_lchown] = old_lchown;
        sys_call_table[__NR_fchownat] = old_fchownat;
        sys_call_table[__NR_umask] = old_umask;
        sys_call_table[__NR_capset] = old_capset;
        sys_call_table[__NR_mount] = old_mount;
        sys_call_table[__NR_umount2] = old_umount2;

        sys_call_table[__NR_uselib] = old_uselib;

        sys_call_table[__NR_setuid] = old_setuid;
        sys_call_table[__NR_setgid] = old_setgid;
        sys_call_table[__NR_setreuid] = old_setreuid;
        sys_call_table[__NR_setregid] = old_setregid;
        sys_call_table[__NR_setresuid] = old_setresuid;
        sys_call_table[__NR_setresgid] = old_setresgid;

        sys_call_table[__NR_sethostname] = old_sethostname;
        sys_call_table[__NR_setdomainname] = old_setdomainname;
        sys_call_table[__NR_connect] = old_connect;
        sys_call_table[__NR_accept] = old_accept;
        sys_call_table[__NR_accept4] = old_accept4;
        enable_write_protection();
}

module_init(syscall_edrhook_init);
module_exit(syscall_edrhook_exit);
