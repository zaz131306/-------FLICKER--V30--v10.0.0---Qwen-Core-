/* ==========================================================================
 * FLICKER V30 · IEP seccomp-BPF whitelist  (§9, R9.2)
 *
 * Назначение: второй, НЕЗАВИСИМЫЙ от network namespace барьер. bwrap уже
 * блокирует сеть через --unshare-net, но полагаться на один барьер там, где
 * цена ошибки неограничена, неверно: здесь socket() запрещён на уровне
 * фильтрации системных вызовов.
 *
 * Ядро §9.2: whitelist, а не blacklist. Запрещены безусловно:
 *   ptrace, mount, umount2, pivot_root, kexec_*, *_module, bpf,
 *   perf_event_open, setns, unshare, userfaultfd, keyctl/add_key/request_key,
 *   reboot, swapon/swapoff, sethostname/setdomainname, iopl/ioperm,
 *   process_vm_readv/writev, open_by_handle_at, chroot, acct, personality,
 *   и весь сетевой набор (socket, connect, bind, listen, accept*, send*, recv*).
 *
 * Реализация — raw BPF, БЕЗ libseccomp: только <linux/seccomp.h>,
 * <linux/filter.h>, <linux/audit.h> из libc6-dev. Это сохраняет требование
 * «ноль внешних зависимостей» (§14) и делает фильтр аудируемым целиком.
 *
 * Сборка:  make seccomp        (или cc -O2 -o flicker_seccomp flicker_seccomp.c)
 * Запуск:  flicker_seccomp -- <argv...>
 *
 * ВАЖНО: фильтр наследуется через execve и не может быть снят процессом.
 * ========================================================================== */

#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>   /* offsetof — обязателен для OFF_NR/OFF_ARCH */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/socket.h>  /* AF_UNIX, SOCK_STREAM — только для selftest */
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#if defined(__x86_64__)
#  define FLICKER_AUDIT_ARCH AUDIT_ARCH_X86_64
#  define OFF_NR   offsetof(struct seccomp_data, nr)
#  define OFF_ARCH offsetof(struct seccomp_data, arch)
#elif defined(__aarch64__)
#  define FLICKER_AUDIT_ARCH AUDIT_ARCH_AARCH64
#  define OFF_NR   offsetof(struct seccomp_data, nr)
#  define OFF_ARCH offsetof(struct seccomp_data, arch)
#else
#  error "flicker_seccomp: unsupported architecture (add AUDIT_ARCH mapping)"
#endif

/* --------------------------------------------------------------------------
 * Whitelist. Сгруппирован по назначению, чтобы аудитор мог проверить полноту.
 * -------------------------------------------------------------------------- */
/* НЕ const намеренно: массив сортируется qsort'ом при старте, а .rodata
 * недоступна для записи. Прежняя версия объявляла его `const` и сортировала
 * через приведение типа — запись в read-only страницу давала SIGSEGV до
 * установки фильтра. */
static int ALLOWED[] = {
    /* --- ввод/вывод --- */
    SYS_read, SYS_write, SYS_readv, SYS_writev,
    SYS_open, SYS_openat, SYS_creat, SYS_close, SYS_close_range,
    SYS_lseek, SYS_pread64, SYS_pwrite64,
    SYS_getdents, SYS_getdents64,
    SYS_fcntl, SYS_flock, SYS_ioctl,
    SYS_fsync, SYS_fdatasync, SYS_sync,
    SYS_truncate, SYS_ftruncate,
    SYS_dup, SYS_dup2, SYS_dup3, SYS_pipe, SYS_pipe2,
    SYS_select, SYS_poll, SYS_ppoll, SYS_pselect6,
    SYS_epoll_create, SYS_epoll_create1, SYS_epoll_ctl, SYS_epoll_wait, SYS_epoll_pwait,
    SYS_eventfd, SYS_eventfd2, SYS_timerfd_create, SYS_timerfd_settime, SYS_timerfd_gettime,
    SYS_signalfd, SYS_signalfd4,
    SYS_vmsplice, SYS_tee, SYS_splice,
    SYS_sendfile,

    /* --- состояние файла/каталога --- */
    SYS_stat, SYS_fstat, SYS_lstat, SYS_newfstatat, SYS_statx,
    SYS_statfs, SYS_fstatfs,
    SYS_access, SYS_faccessat, SYS_faccessat2,
    SYS_readlink, SYS_readlinkat,
    SYS_getcwd, SYS_chdir, SYS_fchdir,
    SYS_mkdir, SYS_mkdirat, SYS_rmdir,
    SYS_rename, SYS_renameat, SYS_renameat2,
    SYS_unlink, SYS_unlinkat,
    SYS_symlink, SYS_symlinkat, SYS_link, SYS_linkat,
    SYS_chmod, SYS_fchmod, SYS_fchmodat,
    SYS_chown, SYS_fchown, SYS_fchownat, SYS_lchown,
    SYS_utime, SYS_utimes, SYS_utimensat,
    SYS_umask,

    /* --- память --- */
    SYS_brk, SYS_mmap, SYS_munmap, SYS_mprotect, SYS_mremap,
    SYS_msync, SYS_madvise, SYS_mincore,
    SYS_mlock, SYS_mlock2, SYS_mlockall, SYS_munlock, SYS_munlockall,
    SYS_membarrier, SYS_memfd_create, SYS_memfd_secret,
    SYS_mbind, SYS_set_mempolicy, SYS_get_mempolicy, SYS_move_pages,

    /* --- процессы/потоки --- */
    SYS_execve, SYS_execveat, SYS_exit, SYS_exit_group,
    SYS_clone, SYS_clone3, SYS_fork, SYS_vfork,
    SYS_wait4, SYS_waitid,
    SYS_kill, SYS_tgkill, SYS_tkill,
    SYS_getpid, SYS_getppid, SYS_gettid, SYS_getpgid, SYS_getpgrp,
    SYS_setpgid, SYS_setsid, SYS_getsid,
    SYS_sched_yield, SYS_sched_getaffinity, SYS_sched_setaffinity,
    SYS_sched_getparam, SYS_sched_getscheduler, SYS_sched_setparam, SYS_sched_setscheduler,
    SYS_sched_get_priority_max, SYS_sched_get_priority_min,
    SYS_getgroups, SYS_setgroups,
    SYS_getuid, SYS_geteuid, SYS_getgid, SYS_getegid,
    SYS_getresuid, SYS_getresgid, SYS_setuid, SYS_setgid,
    SYS_setresuid, SYS_setresgid, SYS_setfsuid, SYS_setfsgid,
    SYS_capget, SYS_prctl, SYS_arch_prctl,
    SYS_prlimit64, SYS_getrlimit, SYS_setrlimit,
    SYS_getrusage, SYS_times, SYS_sysinfo, SYS_uname,

    /* --- сигналы --- */
    SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_rt_sigreturn,
    SYS_rt_sigpending, SYS_rt_sigtimedwait, SYS_rt_sigsuspend, SYS_rt_sigqueueinfo,
    SYS_sigaltstack, SYS_rt_tgsigqueueinfo,

    /* --- время --- */
    SYS_clock_gettime, SYS_clock_getres, SYS_clock_nanosleep,
    SYS_nanosleep, SYS_time, SYS_gettimeofday,
    SYS_timer_create, SYS_timer_settime, SYS_timer_gettime,
    SYS_timer_getoverrun, SYS_timer_delete,
    SYS_timerfd_gettime,

    /* --- futex (нужен любому рантайму с потоками) --- */
    SYS_futex, SYS_set_tid_address, SYS_set_robust_list, SYS_get_robust_list,
    SYS_rseq,

    /* --- случайные числа --- */
    SYS_getrandom,

    /* --- file locks / misc, безопасные --- */
    SYS_fadvise64, SYS_fallocate, SYS_copy_file_range,
    SYS_inotify_init, SYS_inotify_init1, SYS_inotify_add_watch, SYS_inotify_rm_watch,
};

/* Явный список запрещённого — НЕ используется фильтром (фильтр строится по
 * whitelist), но присутствует как документация и как цель негативного теста.
 * Проверка: `flicker_seccomp --list-denied`. */
static const char *const DENIED_DOC[] = {
    "socket", "connect", "bind", "listen", "accept", "accept4",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "socketpair",
    "ptrace", "process_vm_readv", "process_vm_writev",
    "mount", "umount2", "pivot_root", "chroot",
    "kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module",
    "bpf", "perf_event_open", "setns", "unshare", "userfaultfd",
    "keyctl", "add_key", "request_key",
    "reboot", "swapon", "swapoff", "sethostname", "setdomainname",
    "iopl", "ioperm", "acct", "personality", "open_by_handle_at",
    NULL,
};

/* -------------------------------------------------------------------------- */

static int cmp_int(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

/* Размер whitelist в элементах. */
#define N_ALLOWED ((int)(sizeof(ALLOWED) / sizeof(ALLOWED[0])))

static int build_filter(struct sock_fprog *prog, struct sock_filter *insns,
                        int max_insns) {
    /* Структура программы:
     *   [0]   load arch      ; отказ, если не наша архитектура (kill)
     *   [1]   jeq  arch -> +1 ; иначе kill
     *   [2]   kill (bad arch)
     *   [3]   load nr
     *   [4..] бинарный поиск по отсортированному whitelist
     *   [..]  allow
     *   [..]  errno(EPERM)
     *
     * Бинарный поиск даёт O(log n) инструкций вместо O(n) линейного перебора:
     * при ~180 разрешённых вызовах линейный фильтр стоил бы ~180 сравнений
     * на КАЖДЫЙ syscall, что неприемлемо в контуре с бюджетом <12 с на планирование.
     */
    int n = 0;
    if (max_insns < N_ALLOWED * 2 + 16) {
        return -1;
    }

    /* --- проверка архитектуры --- */
    insns[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH);
    insns[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                              FLICKER_AUDIT_ARCH, 1, 0);
    insns[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    /* --- загрузка номера syscall --- */
    insns[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR);

    /* --- бинарный поиск ---
     * Для диапазона [lo,hi] сравниваем nr со средним:
     *   nr == mid -> allow
     *   nr <  mid -> recurse left
     *   nr >  mid -> recurse right
     * Реализовано итеративно с заранее вычисленными смещениями: BPF не имеет
     * стека вызовов, поэтому строим плоскую последовательность переходов.
     */
    int lo = 0, hi = N_ALLOWED - 1;
    /* Простая и проверяемая схема: линейный обход по отсортированному массиву
     * с ранним выходом. Количество инструкций = N*2, но каждая — одно
     * сравнение; на практике фильтр выполняется в ядре за наносекунды.
     * Бинарный поиск в BPF требует аккуратного расчёта jt/jf и является
     * частым источником ошибок; корректность важнее микрооптимизации,
     * а измерение (§10.3) покажет, нужна ли она. */
    for (int i = 0; i < N_ALLOWED; i++) {
        (void)lo; (void)hi;
        /* если nr == ALLOWED[i] -> перейти на allow (в конец) */
        int remaining = N_ALLOWED - i - 1;
        insns[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  (unsigned int)ALLOWED[i],
                                                  /* jt: к allow */ remaining + 1,
                                                  /* jf: следующая проверка */ 0);
    }
    /* nr не найден -> EPERM */
    insns[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                              SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    /* allow */
    insns[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    prog->len = (unsigned short)n;
    prog->filter = insns;
    return n;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "FLICKER IEP seccomp whitelist (§9, R9.2)\n"
        "\n"
        "USAGE:\n"
        "  %s -- <argv...>     установить фильтр и exec'нуть команду\n"
        "  %s --selftest       проверить, что фильтр действительно запрещает socket()\n"
        "  %s --list           вывести whitelist\n"
        "  %s --list-denied    вывести документированный список запрещённого\n"
        "\n"
        "Фильтр наследуется через execve и НЕ МОЖЕТ быть снят процессом.\n",
        argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 2; }

    if (strcmp(argv[1], "--list") == 0) {
        printf("whitelist: %d syscalls\n", N_ALLOWED);
        for (int i = 0; i < N_ALLOWED; i++) printf("  %d\n", ALLOWED[i]);
        return 0;
    }
    if (strcmp(argv[1], "--list-denied") == 0) {
        printf("denied (documentation; filter is whitelist-based):\n");
        for (int i = 0; DENIED_DOC[i]; i++) printf("  %s\n", DENIED_DOC[i]);
        return 0;
    }

    /* Сортировка нужна, чтобы whitelist был предсказуем и чтобы дубликаты
     * (если они появятся при правке) не ломали логику. */
    qsort(ALLOWED, (size_t)N_ALLOWED, sizeof(int), cmp_int);

    if (strcmp(argv[1], "--selftest") == 0) {
        /* Устанавливаем фильтр и проверяем, что socket() действительно
         * запрещён. Это эмпирическая проверка, а не декларация. */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            perror("prctl(NO_NEW_PRIVS)");
            return 3;
        }
        struct sock_filter insns[N_ALLOWED * 2 + 32];
        struct sock_fprog prog;
        if (build_filter(&prog, insns, N_ALLOWED * 2 + 32) < 0) {
            fprintf(stderr, "filter too large\n");
            return 3;
        }
        if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
            perror("seccomp(SET_MODE_FILTER)");
            return 3;
        }
        int fd = (int)syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
        if (fd >= 0) {
            fprintf(stderr, "SELFTEST FAIL: socket() succeeded under the filter\n");
            return 1;
        }
        if (errno != EPERM) {
            fprintf(stderr, "SELFTEST FAIL: socket() errno=%d (%s), expected EPERM\n",
                    errno, strerror(errno));
            return 1;
        }
        /* write() обязан оставаться разрешённым */
        const char *ok = "SELFTEST OK: socket()=EPERM, write()=allowed\n";
        ssize_t w = write(1, ok, strlen(ok));
        return (w > 0) ? 0 : 1;
    }

    if (strcmp(argv[1], "--") != 0) { usage(argv[0]); return 2; }
    if (argc < 3) { usage(argv[0]); return 2; }

    /* PR_SET_NO_NEW_PRIVS обязателен: без него не привилегированный процесс
     * не может установить seccomp-фильтр. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return 3;
    }

    struct sock_filter insns[N_ALLOWED * 2 + 32];
    struct sock_fprog prog;
    if (build_filter(&prog, insns, N_ALLOWED * 2 + 32) < 0) {
        fprintf(stderr, "flicker_seccomp: filter too large\n");
        return 3;
    }
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
        perror("seccomp(SECCOMP_SET_MODE_FILTER)");
        return 3;
    }

    /* Фильтр установлен и наследуется через execve. */
    execvp(argv[2], &argv[2]);
    fprintf(stderr, "flicker_seccomp: exec '%s' failed: %s\n", argv[2], strerror(errno));
    return 127;
}
