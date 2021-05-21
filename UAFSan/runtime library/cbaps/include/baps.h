//
// Created by a on 11/2/19.
//


#ifndef BAPS_BAPS_H
#define BAPS_BAPS_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <math.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include<sys/mman.h>
#include<sys/times.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/time.h>
#include<sys/resource.h>
#include<sys/socket.h>
#include<fnmatch.h>
#include <wchar.h>
#include<netinet/in.h>

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <getopt.h>
#include <glob.h>
#include <limits.h>
#include <math.h>
#include <netdb.h>
#include <pwd.h>
#include <syslog.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include<stdio.h>
#include<stdlib.h>

#include <ttyent.h>
#include <time.h>
#include <unistd.h>
#include <langinfo.h>
#include <regex.h>

#include <utime.h>
#include <math.h>
#include <locale.h>

#include <fcntl.h>
#include <wctype.h>
#include<errno.h>
#include<sys/wait.h>
#include <wait.h>
#include <obstack.h>
#include <libintl.h>
#include <execinfo.h>
#include <malloc.h>

/**
 * analysis data structure part
 */
#define baps_pointer_metadata_fields 3
#define baps_key_index 0
#define baps_obj_index 1
#define baps_size_index 2

typedef struct {
    size_t obj_id;  //obj_id is size_t type
    size_t *obj_addr;
    size_t size;
} baps_pointer_metadata_entry;


typedef struct {
    char shadow; //every 8 bytes shadow into 1 byte
} baps_shadow_metadata_entry;

// store malloc/free back trace data structure
typedef struct {
    size_t baps_malloc_back_trace_size;
    size_t baps_free_back_trace_size;
    size_t baps_use_back_trace_size;
    size_t *baps_malloc_back_trace;  // store malloc back trace
    size_t *baps_free_back_trace;   //store free back trace
    size_t *baps_use_back_trace;
} baps_back_trace_entry;


// mmap related flags
#define baps_mmap_flags (MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE)
// mmap related prot
#define baps_mmap_prot (PROT_READ|PROT_WRITE)

// control debug information output

#if __WORDSIZE == 32
static const size_t baps_temporal_stack_entities_size = (size_t) 1 << 16;
static const size_t baps_shadow_stack_size = (size_t) 1 << 12;

static const size_t __baps_lower_zero_pointer_bits = 3;
static const size_t __baps_lower_zero_object_bits = 3;

// for a 32 wordsize machine, it has 32 bit address lines, ie, 7+22+3, first 23 means primary table obj_id, next 22 means secondary table obj_id.
static const size_t baps_lower_zero_pointer_bits = 3;
static const size_t baps_pointer_metadata_primary_table_size = (size_t) 1 << 23;
static const size_t baps_pointer_metadata_secondary_table_size = (size_t) 1 << 22;

static const size_t baps_lower_zero_object_bits = 3;
static const size_t baps_shadow_metadata_primary_table_size = (size_t) 1 << 23;
static const size_t baps_shadow_metadata_secondary_table_size = (size_t) 1 << 22;

static const size_t baps_backtrace_primary_table_size = (size_t) 1 << 26;
static const size_t baps_backtrace_secondary_table_size = (size_t) 1 << 22;
#else
// used to temporal store variables, such as stack, gloabal, and others
static const size_t baps_temporal_stack_entities_size = (size_t) 1 << 16; //store main args and env args
static const size_t baps_shadow_stack_size = (size_t) 1 << 16;

// for a 64 word_size machine, it has 48 address lines, ie, 23+22+3, first 23 means primary table obj_id, next 22 means secondary table obj_id.
static const size_t baps_lower_zero_pointer_bits = 3;
static const size_t baps_pointer_metadata_primary_table_size = (size_t) 1 << 23;
static const size_t baps_pointer_metadata_secondary_table_size = (size_t) 1 << 22;

static const size_t baps_lower_zero_object_bits = 3;
static const size_t baps_shadow_metadata_primary_table_size = (size_t) 1 << 23;
static const size_t baps_shadow_metadata_secondary_table_size = (size_t) 1 << 22;

static const size_t baps_backtrace_primary_table_size = (size_t) 1 << 26;
static const size_t baps_backtrace_secondary_table_size = (size_t) 1 << 22;

#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
* analysis function part
*/
// used to test static or shared library's effectiveness
int add(int a, int b); // used to test static_library's usefulness

int sub(int a, int b);// used to test static_library's usefulness

extern int baps_pseudo_main(int argc, char **argv);

extern int main(int argc, char **argv);

extern size_t get_unique_id(); // used to get generated unique ID


/**
 * used to store/read shadow stack ptr information
 * 1) size of previous stack frame
 * 2) size of current stack frame
 * 3) begin/end/obj_id of each return value/args
 * following size of current stack is pointer information
 */
void baps_allocate_shadow_stack_space(int numOfArgs);

void baps_deallocate_shadow_stack_space();

void *baps_shadow_stack_pointer_load_obj(int arg_no);

void baps_shadow_stack_pointer_store_obj(void *obj_addr, int arg_no);

size_t baps_shadow_stack_pointer_load_size(int arg_no);

void baps_shadow_stack_pointer_store_size(size_t size, int arg_no);

size_t baps_shadow_stack_pointer_load_unique_id(int arg_no);

void baps_shadow_stack_pointer_store_unique_id(size_t unique_id, int arg_no);

void baps_shadow_stack_store_return_metadata(void *ptr, size_t size, size_t id);

void baps_shadow_stack_store_null_return_metadata();

void baps_propagate_shadow_stack_pointer_metadata(int from_arg_no, int to_arg_no);


/**
 * used to store object malloc/free/use back trace
 */


//flag 0 means malloc, 1 means free, 2 means use
void baps_store_back_trace_handler(baps_back_trace_entry *back_trace, int flags);

// store malloc/free back trace function
void baps_store_malloc_back_trace_handler(baps_back_trace_entry *back_trace);
// use pointer reference to avoid un-necessary copy, i.e., pass by reference

void baps_store_free_back_trace_handler(baps_back_trace_entry *back_trace);

void baps_store_use_back_trace_handler(baps_back_trace_entry *back_trace);

// a generic function called by baps_print_malloc_back_trace_handler, baps_print_free_back_trace_handler, and baps_print_use_back_trace_handler
void baps_print_back_trace_handler(baps_back_trace_entry *back_trace, int flags);

// print malloc/free back trace function, when a UAF occurs
void baps_print_malloc_back_trace_handler(baps_back_trace_entry *back_trace);

void baps_print_free_back_trace_handler(baps_back_trace_entry *back_trace);

void baps_print_use_back_trace_handler(baps_back_trace_entry *back_trace);

// used to test our back_trace is right or not.
void baps_print_current_back_trace();

// a generic print function
void baps_printf(const char *str, ...);


/**
 * used to initialize related data structures
 */

void baps_init(void); // used to init our data structures;

baps_pointer_metadata_entry *baps_trie_pointer_metadata_secondary_allocate();

baps_shadow_metadata_entry *baps_trie_shadow_metadata_secondary_allocate();

baps_back_trace_entry *baps_trie_backtrace_metadata_secondary_allocate();

void baps_introspect_metadata(void *ptr, size_t size, size_t id);

void baps_copy_metadata(void *dest, void *src, size_t size);

void baps_store_trie_pointer_metadata(void *ptr, void *obj_addr, size_t size, size_t unique_id);

baps_pointer_metadata_entry *baps_load_trie_pointer_metadata(void *ptr);

void *baps_load_trie_pointer_metadata_obj(void *ptr);

size_t baps_load_trie_pointer_metadata_size(void *ptr);

size_t baps_load_trie_pointer_metadata_unique_id(void *ptr);

void baps_malloc_shadow_metadata(void *ptr, size_t size);

void baps_free_shadow_metadata(void *ptr, size_t size);

// return whether is able to accessed object
size_t baps_access_shadow_metadata(void *ptr);

void baps_print_shadow_metadata(void *ptr, size_t size);

void baps_store_malloc_back_trace(size_t unique_id);

void baps_store_free_back_trace(size_t unique_id);

void baps_store_use_back_trace(size_t unique_id);

void baps_store_backtrace_metadata(size_t unique_id, int flags);

baps_back_trace_entry * baps_load_back_trace_entry(size_t unique_id);

void baps_print_malloc_back_trace(size_t unique_id);

void baps_print_free_back_trace(size_t unique_id);

void baps_print_use_back_trace(size_t unique_id);

// when a error occurs, we need to abort the program, at the same time, we need to provide debug information.
void baps_abort();

/**
 * used to malloc/free memory by baps
 */

void *baps_safe_malloc(size_t size);

void baps_safe_free(void *ptr);

void *baps_safe_calloc(size_t nmeb, size_t size);

void *baps_safe_realloc(void *ptr, size_t size);

void *baps_safe_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

void baps_safe_munmap(void *addr, size_t length);

/**
 * used to check pointer/object metadata
 */
// will call two function, which separately check pointer metadata and object metadata.
void baps_pointer_dereference_check(void *ptr, size_t ptr_id, void *obj);

/**
 * wrapper for malloc/free related functions by our analysed programs
 */

void *__baps_malloc(size_t size);

void __baps_free(void *ptr);

void *__baps_calloc(size_t nmeb, size_t size);

void *__baps_realloc(void *ptr, size_t size);

void *__baps_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

void __baps_munmap(void *addr, size_t length);

void *__baps_new(size_t size);

void __baps_delete(void *ptr);


/*
 * wrappers for library calls
 */

int __baps_setenv(const char *name, const char *value, int overwrite);

int __baps_unsetenv(const char *name);

int __baps_system(char *ptr);

int __baps_setreuid(uid_t ruid, uid_t euid);

int __baps_mkstemp(char *_template);

uid_t __baps_geteuid();

uid_t __baps_getuid(void);

int __baps_getrlimit(int resource, struct rlimit *rlim);

int __baps_setrlimit(int resource, const struct rlimit *rlim);

size_t __baps_fread_unlocked(void *ptr, size_t size,
                             size_t n, FILE *stream);


#if 0
int __baps_fputs_unlocked(const char *s, FILE *stream);
#endif

size_t __baps_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);

mode_t __baps_umask(mode_t mask);

int __baps_mkdir(const char *pathname, mode_t mode);

int __baps_chroot(const char *path);

int __baps_rmdir(const char *pathname);

int __baps_stat(const char *path, struct stat *buf);

int __baps_fputc(int c, FILE *stream);

int __baps_fileno(FILE *stream);

int __baps_fgetc(FILE *stream);

int __baps_ungetc(int c, FILE *stream);

int __baps_strncmp(const char *s1, const char *s2, size_t n);

double __baps_log(double x);

long long __baps_fwrite(char *ptr, size_t size, size_t nmemb, FILE *stream);

double __baps_atof(char *ptr);

int __baps_feof(FILE *stream);

int __baps_remove(const char *pathname);

/*
 * wrappers for math calls
 */

double __baps_acos(double x);

double __baps_atan2(double y, double x);

float __baps_sqrtf(float x);

float __baps_expf(float x);

double __baps_exp2(double x);

float __baps_floorf(float x);

double __baps_ceil(double x);

float __baps_ceilf(float x);

double __baps_floor(double x);

double __baps_sqrt(double x);

double __baps_fabs(double x);

int __baps_abs(int j);

void __baps_srand(unsigned int seed);

void __baps_srand48(long int seed);

double __baps_pow(double x, double y);

float __baps_fabsf(float x);

double __baps_tan(double x);

float __baps_tanf(float x);

long double __baps_tanl(long double x);

double __baps_log10(double x);

double __baps_sin(double x);

float __baps_sinf(float x);

long double __baps_sinl(long double x);

double __baps_cos(double x);

float __baps_cosf(float x);

long double __baps_cosl(long double x);

double __baps_exp(double x);

double __baps_ldexp(double x, int exp);

/*
 * wrappers for File-related function calls
 */

FILE *__baps_tmpfile(void);

int __baps_ferror(FILE *stream);

long __baps_ftell(FILE *stream);

int __baps_fstat(int filedes, struct stat *buff);

int __baps___lxstat(int __ver, const char *__filename, struct stat *__stat_buf);

size_t __baps_mbrtowc(wchar_t *pwc, const char *s, size_t n, mbstate_t *ps);

int __baps_mbsinit(const mbstate_t *ps);

int __baps___fxstat(int ver, int file_des, struct stat *stat_struct);

int __baps___fxstatat(int ver, int file_des, const char *filename, struct stat *stat_struct, int flag);

int __baps_fflush(FILE *stream);

int __baps_fputs(const char *s, FILE *stream);

int __baps_fsync(int fd);

DIR *__baps_fdopendir(int fd);

int __baps_fseeko(FILE *stream, off_t offset, int whence);

char *__baps_mkdtemp(char *_template);

int __baps_raise(int sig);

int __baps_linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);

int __baps_utimes(const char *filename, const struct timeval times[2]);

#if 0
int __baps_futimesat(int dirfd, const char *pathname, const struct timeval times[2]);
#endif

int __baps_futimens(int fd, const struct timespec times[2]);

int __baps_utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);

size_t __baps___ctype_get_mb_cur_max(void);

int __baps_iswprint(wint_t wc);

int __baps_getpagesize(void);

int __baps_dirfd(DIR *dirp);

struct lconv *__baps_localeconv(void);

struct tm *__baps_gmtime(const time_t *timep);

void *
__baps_bsearch(const void *key, const void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));

struct group *__baps_getgrnam(const char *name);

int __baps_rpmatch(const char *response);

int __baps_regcomp(regex_t *preg, const char *regex, int cflags);

size_t __baps_regerror(int errcode, const regex_t *preg, char *errbuf, size_t errbuf_size);

int __baps_regexec(const regex_t *preg, const char *string, size_t nmatch, regmatch_t pmatch[], int eflags);

#ifdef HAVE_ICONV_H

size_t __baps_iconv(iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft) ;

iconv_t __baps_iconv_open(const char *tocode, const char *fromcode) ;

#endif

struct passwd *__baps_getpwnam(const char *name);

struct passwd *__baps_getpwuid(uid_t uid);

struct group *__baps_getgrgid(gid_t gid);

FILE *__baps_fopen(const char *path, const char *mode);

FILE *__baps_fdopen(int fildes, const char *mode);

int __baps_fseek(FILE *stream, long offset, int whence);

int __baps_ftruncate(int fd, off_t length);

FILE *__baps_popen(const char *command, const char *type);

int __baps_fclose(FILE *fp);

int __baps_pclose(FILE *stream);

void __baps_rewind(FILE *stream);

struct dirent *__baps_readdir(DIR *dir);

int __baps_creat(const char *pathname, mode_t mode);

int __baps_fnmatch(const char *pattern, const char *string, int flags);

DIR *__baps_opendir(const char *name);

int __baps_closedir(DIR *dir);

int __baps_rename(const char *old_path, const char *new_path);

/**
 * wrappers for unistd-releated calls
 */

unsigned int __baps_sleep(unsigned int seconds);

char *__baps_getcwd(char *buf, size_t size);

int __baps_setgid(gid_t gid);

gid_t __baps_getgid(void);

gid_t __baps_getegid(void);

int __baps_readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);

int __baps_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

int __baps_unlinkat(int dirfd, const char *pathname, int flags);

int __baps_symlinkat(const char *oldpath, int newdirfd, const char *newpath);

int __baps_mkdirat(int dirfd, const char *pathname, mode_t mode);

int __baps_fchown(int fd, uid_t owner, gid_t group);

int __baps_fchownat(int dirfd, const char *pathname,
                    uid_t owner, gid_t group, int flags);

int __baps_fchmod(int fd, mode_t mode);

int __baps_chmod(const char *path, mode_t mode);

int __baps_openat(int dirfd, const char *pathname, int flags);

int __baps_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);

#if defined (__linux__)

int __baps___xmknodat(int __ver, int __fd, const char *__path, __mode_t __mode, __dev_t *__dev);

int __baps_mkfifoat(int dirfd, const char *pathname, mode_t mode);

#endif

pid_t __baps_getpid(void);

pid_t __baps_getppid(void);

#if 0

int __baps_openat(int dirfd, const char *pathname, int flags, mode_t mode);

#endif

int __baps_chown(const char *path, uid_t owner, gid_t group);

wint_t __baps_towlower(wint_t wc);

int __baps_isatty(int desc);

int __baps_chdir(const char *path);

int __baps_fchdir(int fd);

/**
 * wrrappers for String
 */

int __baps_strcmp(const char *s1, const char *s2);

int __baps_strcasecmp(const char *s1, const char *s2);

int __baps_strncasecmp(const char *s1, const char *s2, size_t n);

size_t __baps_strlen(const char *s);

char *__baps_strpbrk(const char *s, const char *accept);

char *__baps_gets(char *s);

char *__baps_fgets(char *s, int size, FILE *stream);

void __baps_perror(const char *s);

size_t __baps_strspn(const char *s, const char *accept);

size_t __baps_strcspn(const char *s, const char *reject);

#ifdef _GNU_SOURCE

void *__baps_mempcpy(void *dest, const void *src, size_t n);

#endif

int __baps_memcmp(const void *s1, const void *s2, size_t n);

#ifdef _GNU_SOURCE

void *__baps_memrchr(const void *s, int c, size_t n);

#endif

void __baps_rewinddir(DIR *dirp);

void *__baps_memchr(const void *s, int c, size_t n);

char *__baps_rindex(char *s, int c);

ssize_t __baps_getdelim(char **lineptr, size_t *n, int delim, FILE *stream);

unsigned long int __baps_strtoul(const char *nptr, char **endptr, int base);

double __baps_strtod(const char *nptr, char **endptr);

long __baps_strtol(const char *nptr, char **endptr, int base);

#ifdef _GNU_SOURCE

char *__baps_strchrnul(const char *s, int c);

#endif

char *__baps_strchr(const char *s, int c);

char *__baps_strrchr(const char *s, int c);

char *__baps_stpcpy(char *dest, char *src);

char *__baps_strcpy(char *dest, char *src);

int __baps_rand();

int __baps_atoi(const char *ptr);

void __baps_puts(char *ptr);


void __baps_exit(int status);

char *__baps_strtok(char *str, const char *delim);

void __baps_strdup_handler(void *ret_ptr);

//strdup, allocates memory from the system using malloc, thus can be freed
char *__baps_strndup(const char *s, size_t n);

//strdup, allocates memory from the system using malloc, thus can be freed
char *__baps_strdup(const char *s);

char *__baps___strdup(const char *s);

char *__baps_strcat(char *dest, const char *src);

char *__baps_strncat(char *dest, const char *src, size_t n);

char *__baps_strncpy(char *dest, char *src, size_t n);

char *__baps_strstr(const char *haystack, const char *needle);

__sighandler_t __baps_signal(int signum, __sighandler_t handler);

clock_t __baps_clock(void);

long __baps_atol(const char *nptr);

int __baps_putchar(int c);

clock_t __baps_times(struct tms *buf);

size_t __baps_strftime(char *s, size_t max, const char *format, const struct tm *tm);

time_t __baps_mktime(struct tm *tm);

long __baps_pathconf(char *path, int name);

struct tm *__baps_localtime(const time_t *timep);

time_t __baps_time(time_t *t);

double __baps_drand48();

long int __baps_lrand48();

/**
 * wrappers for Time-related calls
 */
char *__baps_ctime(const time_t *timep);

double __baps_difftime(time_t time1, time_t time0);

int __baps_toupper(int c);

int __baps_tolower(int c);

void __baps_setbuf(FILE *stream, char *buf);

char *__baps_getenv(const char *name);

#ifdef _GNU_SOURCE

int__baps_strerror_r(int errnum, char *buf, size_t buf_len);

#endif

char *__baps_strerror(int errnum);

int __baps_unlink(const char *pathname);

int __baps_close(int fd);

int __baps_open(const char *pathname, int flags);

ssize_t __baps_read(int fd, void *buf, size_t count);

ssize_t __baps_write(int fd, void *buf, size_t count);

off_t __baps_lseek(int fildes, off_t offset, int whence);

int __baps_gettimeofday(struct timeval *tv, struct timezone *tz);

int __baps_select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout);

#if defined (__linux__)

char *__baps_setlocale(int category, const char *locale);

char *__baps_textdomain(const char *domainname);

char *__baps_bindtextdomain(const char *domainname, const char *dirname);

char *__baps_gettext(const char *msgid);

char *_baps_dcngettext(const char *domainname,
                       const char *msgid, const char *msgid_plural,
                       unsigned long int n, int category);

/* IMP: struct hostent may have pointers in the structure being returned,
   we need to store the metadata for all those pointers */

struct hostent *__baps_gethostbyname(const char *name);

char *__baps_dcgettext(const char *domainname,
                       const char *msgid,
                       int category);

#endif

#if defined(__linux__)

int *__baps___errno_location();

unsigned short const **__baps___ctype_b_loc(void);

int const **__baps___ctype_toupper_loc(void);

int const **__baps___ctype_tolower_loc(void);

#endif

#if defined(__linux__)

void __baps__obstack_newchunk(struct obstack *obj, int b);

int __baps__obstack_begin(struct obstack *obj, int a, int b,
                          void *(foo)(long), void (bar)(void *));

void __baps_obstack_free(struct obstack *obj, void *object);

char *__baps_nl_langinfo(nl_item item);

int __baps_clock_gettime(clockid_t clk_id, struct timespec *tp);

#endif

#if 0

int __baps__obstack_memory_used(struct obstack *h) ;

#endif

#ifdef __cplusplus
};
#endif

#endif //BAPS_BAPS_H
