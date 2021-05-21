//
// Created by a on 5/12/20.
//
#include "baps.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
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

#define _GNU_SOURCE
#define __USE_GNU

#include <dlfcn.h>

#define _GNU_SOURCE
#define __USE_GNU

#include <string.h>
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
#include "uthash.h"

#include <stdlib.h>  /* atoi, malloc */
#include "uthash.h"
#include <stdbool.h>

//#include <map>
//#include <iostream>
#if defined(__linux__)

#include<errno.h>
#include<sys/wait.h>
#include <wait.h>
#include <obstack.h>
#include <libintl.h>
#include <iconv.h>
#include <malloc.h>

#endif

/**
 * analysis data structure part
 */


size_t unique_id = 2; //

baps_pointer_metadata_entry **baps_trie_pointer_metadata_primary_table = NULL; // is used to store pointer-related metadata, primary table;
baps_shadow_metadata_entry **baps_trie_shadow_metadata_primary_table = NULL;  //is used to store location-related, namely, address-related primary table;
baps_back_trace_entry **baps_trie_backtrace_metadata_primary_table = NULL;
size_t *baps_start_of_shadow_stack_ptr = NULL;
size_t *baps_ptr_to_current_stack_frame = NULL;

/**
* analysis function part
*/
// used to test static or shared library's effectiveness
int add(int a, int b) { // used to test static_library's usefulness
    return a + b;
}

int sub(int a, int b) { // used to test static_library's usefulness
    return a - b;
}

extern int baps_pseudo_main(int argc, char **argv);  // we need replace source code main to baps_pseudo_main


bool has_backtrace_info(size_t unique_id);

bool isAligned(size_t src_addr);

extern int main(int argc, char **argv) {
#if __WORDSIZE == 32
    exit(1);
#endif
//    printf("Hello, World");
    baps_init();
    char **argv_addr = argv;
    size_t argv_key = 2; // we think argv is a stack variable, out of our scope
    for (int i = 0; i < argc; ++i) {
        baps_store_trie_pointer_metadata(&argv_addr[i], &argv_addr[i], strlen(argv_addr[i]) + 1, argv_key);
    }
    baps_allocate_shadow_stack_space(2);
    baps_shadow_stack_pointer_store_obj(&argv_addr[0], 1);
    baps_shadow_stack_pointer_store_size(argc + 1, 1);
    baps_shadow_stack_pointer_store_unique_id(argv_key, 1);
    int ret_value = baps_pseudo_main(argc, argv);
    baps_deallocate_shadow_stack_space();
//    printf("Devil, World");
    return ret_value;
}

size_t get_unique_id() { // used to get generated unique ID
//    printf("call function get_generated_ID: ...\n");
    return ++unique_id;
}

/**
 * used to store/read shadow stack ptr information
 * 1) size of previous stack frame
 * 2) size of current stack frame
 * 3) obj_addr/obj_size/obj_id of each return value/args
 * following size of current stack is pointer information
 */

void baps_allocate_shadow_stack_space(int numOfArgs) {
//    printf("baps_allocate_shadow_stack_space()\n");
    assert(numOfArgs >= 0);
    size_t prev_stack_size = *(baps_ptr_to_current_stack_frame + 1);
    baps_ptr_to_current_stack_frame += prev_stack_size;
    *baps_ptr_to_current_stack_frame = prev_stack_size;
    *(baps_ptr_to_current_stack_frame + 1) = 2 + numOfArgs * baps_pointer_metadata_fields;
    baps_shadow_stack_store_null_return_metadata();
//    printf("baps_allocate_shadow_stack_space:  %p\n", baps_ptr_to_current_stack_frame);
}

void baps_deallocate_shadow_stack_space() {
//    printf("baps_deallocate_shadow_stack_space()\n");
    size_t current_stack_frame_size = *(baps_ptr_to_current_stack_frame);
    assert(baps_ptr_to_current_stack_frame >= baps_start_of_shadow_stack_ptr &&
           current_stack_frame_size < baps_shadow_stack_size);
    baps_ptr_to_current_stack_frame -= current_stack_frame_size;
//    printf("baps_deallocate_shadow_stack_space:  %p\n", baps_ptr_to_current_stack_frame);
}

void *baps_shadow_stack_pointer_load_obj(int arg_no) {
    assert(arg_no >= 0);
    size_t count = 2 + arg_no * baps_pointer_metadata_fields + baps_obj_index;
    size_t *obj_ptr = baps_ptr_to_current_stack_frame + count;
    void *obj_addr = *((void **) obj_ptr);
    return obj_addr;
}

void baps_shadow_stack_pointer_store_obj(void *obj_addr, int arg_no) {
    assert(arg_no >= 0);
    size_t count = 2 + arg_no * baps_pointer_metadata_fields + baps_obj_index;
    void **obj_ptr = (void **) baps_ptr_to_current_stack_frame + count;
    *obj_ptr = obj_addr;
}

size_t baps_shadow_stack_pointer_load_size(int arg_no) {
    assert(arg_no >= 0);
    size_t count = 2 + arg_no * baps_pointer_metadata_fields + baps_size_index;
    size_t *size_ptr = baps_ptr_to_current_stack_frame + count;
    size_t size = *size_ptr;
    return size;
}

void baps_shadow_stack_pointer_store_size(size_t size, int arg_no) {
    assert(arg_no >= 0);
    size_t count = 2 + arg_no * baps_pointer_metadata_fields + baps_size_index;
    size_t *size_ptr = (size_t *) baps_ptr_to_current_stack_frame + count;
    *size_ptr = size;
}

size_t baps_shadow_stack_pointer_load_unique_id(int arg_no) {
    assert(arg_no >= 0);
    size_t count = 2 + arg_no * baps_pointer_metadata_fields + baps_key_index;
    size_t *unique_id_ptr = baps_ptr_to_current_stack_frame + count;
    size_t unique_id = *unique_id_ptr;
    return unique_id;
}

void baps_shadow_stack_pointer_store_unique_id(size_t unique_id, int arg_no) {
    assert(arg_no >= 0);
    size_t count = 2 + arg_no * baps_pointer_metadata_fields + baps_key_index;
    size_t *unique_id_ptr = baps_ptr_to_current_stack_frame + count;
    *unique_id_ptr = unique_id;
}

void baps_shadow_stack_store_return_metadata(void *ptr, size_t size, size_t id) {
    size_t *obj_addr = (size_t *) ptr;
    size_t obj_size = size;
    baps_shadow_stack_pointer_store_obj(obj_addr, 0);
    baps_shadow_stack_pointer_store_size(obj_size, 0);
    baps_shadow_stack_pointer_store_unique_id(id, 0);
}

void baps_shadow_stack_store_null_return_metadata() {
    baps_shadow_stack_pointer_store_obj(NULL, 0);
    baps_shadow_stack_pointer_store_size(0, 0);
    baps_shadow_stack_pointer_store_unique_id(0, 0);
}

void baps_propagate_shadow_stack_pointer_metadata(int from_arg_no, int to_arg_no) {
    void *obj_addr = baps_shadow_stack_pointer_load_obj(from_arg_no);
    size_t size = baps_shadow_stack_pointer_load_size(from_arg_no);
    size_t unique_id = baps_shadow_stack_pointer_load_unique_id(from_arg_no);

    baps_shadow_stack_pointer_store_obj(obj_addr, to_arg_no);
    baps_shadow_stack_pointer_store_size(size, to_arg_no);
    baps_shadow_stack_pointer_store_unique_id(unique_id, to_arg_no);
}

/**
 * used to store object malloc/free/use back trace
 */

static int back_trace_size = 12;

//flag 0 means malloc, 1 means free, 2 means use
void baps_store_back_trace_handler(baps_back_trace_entry *back_trace, int flags) {
//    printf("call function baps_store_back_trace_handler: ...\n");
    size_t size;
    void *array[back_trace_size];
    size = backtrace(array, back_trace_size);
    switch (flags) {
        case 0:
            back_trace->baps_malloc_back_trace_size = size;
            back_trace->baps_malloc_back_trace = (size_t *) (malloc(sizeof(size_t) * size));
            for (int i = 0; i < size; i++) {
                back_trace->baps_malloc_back_trace[i] = (size_t) (array[i]);
            }
            break;
        case 1:
            back_trace->baps_free_back_trace_size = size;
            back_trace->baps_free_back_trace = (size_t *) (malloc(sizeof(size_t) * size));
            for (int i = 0; i < size; i++) {
                back_trace->baps_free_back_trace[i] = (size_t) (array[i]);
            }
            break;
        case 2:
            back_trace->baps_use_back_trace_size = size;
            back_trace->baps_use_back_trace = (size_t *) (malloc(sizeof(size_t) * size));
            for (int i = 0; i < size; i++) {
                back_trace->baps_use_back_trace[i] = (size_t) (array[i]);
            }
            break;
        default:
            break;
    }
}

// store malloc/free back trace function
void baps_store_malloc_back_trace_handler(baps_back_trace_entry *back_trace) {
    // use pointer reference to avoid un-necessary copy, i.e., pass by reference
//    printf("call function baps_store_malloc_back_trace_handler: ...\n");
//    baps_store_back_trace_handler(back_trace, 0);
    size_t size;
    void *array[back_trace_size];
    size = backtrace(array, back_trace_size);
    back_trace->baps_malloc_back_trace_size = size;
    back_trace->baps_malloc_back_trace = (size_t *) (malloc(sizeof(size_t) * size));
    for (int i = 0; i < size; i++) {
        back_trace->baps_malloc_back_trace[i] = (size_t) (array[i]);
    }
}

void baps_store_free_back_trace_handler(baps_back_trace_entry *back_trace) {
//    printf("call function baps_store_free_back_trace_handler: ...\n");
//    baps_store_back_trace_handler(back_trace, 1);
    size_t size;
    void *array[back_trace_size];
    size = backtrace(array, back_trace_size);
    back_trace->baps_free_back_trace_size = size;
    back_trace->baps_free_back_trace = (size_t *) (malloc(sizeof(size_t) * size));
    for (int i = 0; i < size; i++) {
        back_trace->baps_free_back_trace[i] = (size_t) (array[i]);
    }
}


void baps_store_use_back_trace_handler(baps_back_trace_entry *back_trace) {
//    printf("call function baps_store_use_back_trace_handler: ...\n");
//    baps_store_back_trace_handler(back_trace, 2);
    size_t size;
    void *array[back_trace_size];
    size = backtrace(array, back_trace_size);
    back_trace->baps_use_back_trace_size = size;
    back_trace->baps_use_back_trace = (size_t *) (malloc(sizeof(size_t) * size));
    for (int i = 0; i < size; i++) {
        back_trace->baps_use_back_trace[i] = (size_t) (array[i]);
    }
}

// a generic function called by baps_print_malloc_back_trace_handler, baps_print_free_back_trace_handler, and baps_print_use_back_trace_handler
void baps_print_back_trace_handler(baps_back_trace_entry *back_trace, int flags) {
    switch (flags) {
        case 0:
            baps_print_malloc_back_trace_handler(back_trace);
            break;
        case 1:
            baps_print_free_back_trace_handler(back_trace);
            break;
        case 2:
            baps_print_use_back_trace_handler(back_trace);
            break;
        default:
            return;
    }
}

// print malloc/free back trace function, when a UAF occurs
void baps_print_malloc_back_trace_handler(baps_back_trace_entry *back_trace) {
//    printf("call function baps_print_malloc_back_trace_handler: ...\n");
//    baps_print_back_trace_handler(back_trace, 0);
    size_t size = back_trace->baps_malloc_back_trace_size;
    Dl_info info[size];
    int status[size];
    FILE *fp = NULL;
    if (back_trace->baps_malloc_back_trace == NULL) {
        return;
    }
//    printf("back_trace->baps_malloc_back_trace_size %ld\n",back_trace->baps_malloc_back_trace_size);
    for (int cnt = 0; cnt < size; cnt++) {
        char func_name[255];
        char line_addr[255];
        status[cnt] = dladdr((const void *) (back_trace->baps_malloc_back_trace[cnt]), &info[cnt]);

        sprintf(func_name, "addr2line %p -e  %s -f -C ",
                (void *) (back_trace->baps_malloc_back_trace[cnt]), info[cnt].dli_fname);
        sprintf(line_addr, "addr2line %p -e  %s",
                (void *) (back_trace->baps_malloc_back_trace[cnt]), info[cnt].dli_fname);
        fp = popen(func_name, "r");
        fgets(func_name, sizeof(func_name), fp);
        func_name[strlen(func_name) - 1] = '\0';
        pclose(fp);
        fp = popen(line_addr, "r");
        fgets(line_addr, sizeof(line_addr), fp);
        line_addr[strlen(line_addr) - 1] = '\0';
        pclose(fp);
        if (strlen(line_addr) == 4) {
            fprintf(stderr,"\t#%d %p in %s (%s)\n", cnt, (void *) (back_trace->baps_malloc_back_trace[cnt]), func_name,
                   info[cnt].dli_fname);
        } else {
            fprintf(stderr,"\t#%d %p in %s (%s)\n", cnt, (void *) (back_trace->baps_malloc_back_trace[cnt]), func_name,
                   line_addr);
        }
    }
}

void baps_print_free_back_trace_handler(baps_back_trace_entry *back_trace) {
//    printf("call function baps_print_free_back_trace_handler: ...\n");

//    baps_print_back_trace_handler(back_trace, 1);
    size_t size = back_trace->baps_free_back_trace_size;
    Dl_info info[size];
    int status[size];
    char buff[255];
    FILE *fp = NULL;

    if (back_trace->baps_free_back_trace == NULL) {
        return;
    }
//    printf("back_trace->baps_free_back_trace_size: %ld\n",back_trace->baps_free_back_trace_size);
    for (int cnt = 0; cnt < size; cnt++) {
        char func_name[255];
        char line_addr[255];
        status[cnt] = dladdr((const void *) (back_trace->baps_free_back_trace[cnt]), &info[cnt]);
        sprintf(func_name, "addr2line %p -e  %s -f -C ",
                (void *) (back_trace->baps_free_back_trace[cnt]), info[cnt].dli_fname);
        sprintf(line_addr, "addr2line %p -e  %s",
                (void *) (back_trace->baps_free_back_trace[cnt]), info[cnt].dli_fname);
        fp = popen(func_name, "r");
        fgets(func_name, sizeof(func_name), fp);
        func_name[strlen(func_name) - 1] = '\0';
        pclose(fp);
        fp = popen(line_addr, "r");
        fgets(line_addr, sizeof(line_addr), fp);
        line_addr[strlen(line_addr) - 1] = '\0';
        pclose(fp);
        if (strlen(line_addr) == 4) {
            fprintf(stderr,"\t#%d %p in %s (%s)\n", cnt, (void *) (back_trace->baps_free_back_trace[cnt]), func_name,
                   info[cnt].dli_fname);
        } else {
            fprintf(stderr,"\t#%d %p in %s (%s)\n", cnt, (void *) (back_trace->baps_free_back_trace[cnt]), func_name,
                   line_addr);
        }
    }
}


void baps_print_use_back_trace_handler(baps_back_trace_entry *back_trace) {
//    printf("call function baps_print_use_back_trace_handler: ...\n");

//    baps_print_back_trace_handler(back_trace, 2);
    size_t size = back_trace->baps_use_back_trace_size;
    Dl_info info[size];
    int status[size];
    char buff[255];
    FILE *fp = NULL;

    if (back_trace->baps_use_back_trace == NULL) {
        return;
    }

//    printf("back_trace->baps_use_back_trace_size: %ld\n", back_trace->baps_use_back_trace_size);
    for (int cnt = 0; cnt < size; cnt++) {
        char func_name[255];
        char line_addr[255];
        status[cnt] = dladdr((const void *) (back_trace->baps_use_back_trace[cnt]), &info[cnt]);
        sprintf(func_name, "addr2line %p -e  %s -f -C ",
                (void *) (back_trace->baps_use_back_trace[cnt]), info[cnt].dli_fname);
        sprintf(line_addr, "addr2line %p -e  %s",
                (void *) (back_trace->baps_use_back_trace[cnt]), info[cnt].dli_fname);
        fp = popen(func_name, "r");
        fgets(func_name, sizeof(func_name), fp);
        func_name[strlen(func_name) - 1] = '\0';
        pclose(fp);
        fp = popen(line_addr, "r");
        fgets(line_addr, sizeof(line_addr), fp);
        line_addr[strlen(line_addr) - 1] = '\0';
        pclose(fp);
        if (strlen(line_addr) == 4) {
            fprintf(stderr,"\t#%d %p in %s (%s)\n", cnt, (void *) (back_trace->baps_use_back_trace[cnt]), func_name,
                   info[cnt].dli_fname);
        } else {
            fprintf(stderr,"\t#%d %p in %s (%s)\n", cnt, (void *) (back_trace->baps_use_back_trace[cnt]), func_name,
                   line_addr);
        }
    }
}


// used to test our back_trace is right or not.
void baps_print_current_back_trace() {
//    printf("call function baps_print_current_back_trace: ...\n");
    printf("current back_trace information\n");
    size_t size;
    void *array[back_trace_size];
    size = backtrace(array, back_trace_size);
    Dl_info info[size];
    int status[size];
    char buff[255];
    FILE *fp = NULL;
    for (int cnt = 0; cnt < size; cnt++) {
        char func_name[255];
        char line_addr[255];
        status[cnt] = dladdr((const void *) (array[cnt]), &info[cnt]);
        sprintf(func_name, "addr2line %p -e  %s -f -C ",
                (void *) (array[cnt]), info[cnt].dli_fname);
        sprintf(line_addr, "addr2line %p -e  %s",
                (void *) (array[cnt]), info[cnt].dli_fname);
        fp = popen(func_name, "r");
        fgets(func_name, sizeof(func_name), fp);
        func_name[strlen(func_name) - 1] = '\0';
        pclose(fp);
        fp = popen(line_addr, "r");
        fgets(line_addr, sizeof(line_addr), fp);
        line_addr[strlen(line_addr) - 1] = '\0';
        pclose(fp);
        if (strlen(line_addr) == 4) {
            printf("\t#%d %p in %s (%s)\n", cnt, (void *) (array[cnt]), func_name,
                   info[cnt].dli_fname);
        } else {
            printf("\t#%d %p in %s (%s)\n", cnt, (void *) (array[cnt]), func_name,
                   line_addr);
        }
    }
}

// a generic print function
void baps_printf(const char *str, ...) {
    printf("call function baps_printf: ...\n");
    va_list args;
    va_start(args, str);
    printf(str, args);
    va_end(args);
};

/**
 * used to initialize related data structures
 */

static int baps_initialized = 0;

void baps_init(void) { // used to init our data structures;
//    printf("call function baps_init: ...\n");
    if (baps_initialized != 0) {
        printf("yes, the baps has been initialized");
    } else {
        baps_initialized = 1; // we are initializing related data structures;
    }
    assert(sizeof(baps_shadow_metadata_entry) >= 1);
    assert(sizeof(baps_pointer_metadata_entry) >= 24);
    assert(sizeof(baps_back_trace_entry) >= 24);
    /**
     * allocate enough memory for using shadow stack
     */
    size_t shadow_stack_size = (baps_shadow_stack_size) * sizeof(size_t);
    baps_start_of_shadow_stack_ptr = (size_t *) (baps_safe_mmap(0, shadow_stack_size, baps_mmap_prot,
                                                                baps_mmap_flags,
                                                                -1, 0));
    assert(baps_start_of_shadow_stack_ptr != (void *) -1);
    baps_ptr_to_current_stack_frame = baps_start_of_shadow_stack_ptr;
    *baps_ptr_to_current_stack_frame = 0;
    *(baps_ptr_to_current_stack_frame + 1) = 0;

    /**
     * allocate trie pointer metadata shadow space for store memory object identity information
     */
    size_t trie_pointer_metadata_length = (baps_pointer_metadata_primary_table_size) * sizeof(void *);
    baps_trie_pointer_metadata_primary_table = (baps_pointer_metadata_entry **) (baps_safe_mmap(
            0,
            trie_pointer_metadata_length,
            baps_mmap_prot,
            baps_mmap_flags,
            -1, 0));
    assert(baps_trie_pointer_metadata_primary_table != (void *) -1);

    /**
     * allocate trie backtrace shadow space
     */
    size_t trie_backtrace_metadata_length = (baps_backtrace_primary_table_size) * sizeof(void *);
    baps_trie_backtrace_metadata_primary_table = (baps_back_trace_entry **) (baps_safe_mmap(0,
                                                                                            trie_backtrace_metadata_length,
                                                                                            baps_mmap_prot,
                                                                                            baps_mmap_flags,
                                                                                            -1, 0));
    assert(baps_trie_backtrace_metadata_primary_table != (void *) -1);

    /**
     * allocate trie shadow metadata shadow space, shadow every 8 bytes status to 1 byte.
     */

//    size_t trie_object_metadata_length = (baps_shadow_metadata_primary_table_size) * sizeof(void *);
//    baps_trie_shadow_metadata_primary_table = (baps_shadow_metadata_entry **) (baps_safe_mmap(0,
//                                                                                              trie_object_metadata_length,
//                                                                                              baps_mmap_prot,
//                                                                                              baps_mmap_flags,
//                                                                                              -1,
//                                                                                              0));
//    assert(baps_trie_shadow_metadata_primary_table != (void *) -1);

}

baps_pointer_metadata_entry *baps_trie_pointer_metadata_secondary_allocate() {
//    printf("call function baps_trie_pointer_metadata_secondary_allocate(): ...\n");
    baps_pointer_metadata_entry *secondary_entry;
    size_t length =
            (baps_pointer_metadata_secondary_table_size) * sizeof(baps_pointer_metadata_entry);
    secondary_entry = (baps_pointer_metadata_entry *) (baps_safe_mmap(0, length, baps_mmap_prot,
                                                                      baps_mmap_flags, -1, 0));
    return secondary_entry;
};

baps_shadow_metadata_entry *baps_trie_shadow_metadata_secondary_allocate() {
//    printf("call function baps_trie_shadow_metadata_secondary_allocate(): ...\n");
    baps_shadow_metadata_entry *secondary_entry;
    size_t length =
            (baps_shadow_metadata_secondary_table_size) * sizeof(baps_shadow_metadata_entry);
    secondary_entry = (baps_shadow_metadata_entry *) (baps_safe_mmap(0, length, baps_mmap_prot,
                                                                     baps_mmap_flags, -1, 0));
    return secondary_entry;
};

baps_back_trace_entry *baps_trie_backtrace_metadata_secondary_allocate() {
//    printf("call function baps_trie_backtrace_metadata_secondary_allocate(): ...\n");
    baps_back_trace_entry *secondary_entity;
    size_t length = (baps_backtrace_secondary_table_size) * sizeof(baps_back_trace_entry);
    secondary_entity = (baps_back_trace_entry *) (baps_safe_mmap(0, length, baps_mmap_prot, baps_mmap_flags,
                                                                 -1, 0));

    return secondary_entity;
}

void baps_introspect_metadata(void *ptr, size_t size, size_t id) {

}

void baps_copy_metadata(void *dest, void *src, size_t size) {
    size_t src_addr = (size_t) src;
    size_t dest_addr = (size_t) dest;
    if (!isAligned(src_addr) || !isAligned(dest_addr)) {
        return;
    }
    if ((size >> 3) == 0) {
        return;
    }

    size_t src_primary_index = src_addr >> 25;
    size_t src_primary_index_end = (src_addr + size) >> 25;

    size_t dest_primary_index = dest_addr >> 25;
    size_t dest_primary_index_end = (dest_addr + size) >> 25;

    if (src_primary_index == src_primary_index_end && dest_primary_index == dest_primary_index_end) {
        if (baps_trie_pointer_metadata_primary_table[src_primary_index] == NULL) {
            return;
        }
        if (baps_trie_pointer_metadata_primary_table[dest_primary_index] == NULL) {
            baps_trie_pointer_metadata_primary_table[dest_primary_index] = baps_trie_pointer_metadata_secondary_allocate();
        }
        size_t src_secondary_index = ((src_addr >> 3) & 0x3fffff);
        size_t dest_secondary_index = ((dest_addr >> 3) & 0x3fffff);
        void *src_entry_ptr = &baps_trie_pointer_metadata_primary_table[src_primary_index][src_secondary_index];
        void *dest_entry_ptr = &baps_trie_pointer_metadata_primary_table[dest_primary_index][dest_secondary_index];
        memcpy(dest_entry_ptr, src_entry_ptr, 24 * (size >> 3));
        return;
    } else {
        size_t src_size_t = src_addr;
        size_t dest_size_t = dest_addr;
        size_t trie_size = size;
        for (size_t index = 0; index < trie_size; index += 8) {
            size_t temp_src_primary_index = (src_size_t + index) >> 25;
            size_t temp_dest_primary_index = (dest_size_t + index) >> 25;
            size_t temp_src_secondary_index = (((src_size_t + index) >> 3) & 0x3fffff);
            size_t temp_dest_secondary_index = (((dest_size_t + index) >> 3) & 0x3fffff);

            if (baps_trie_pointer_metadata_primary_table[temp_src_primary_index] == NULL) {
                baps_trie_pointer_metadata_primary_table[temp_src_primary_index] = baps_trie_pointer_metadata_secondary_allocate();
            }

            if (baps_trie_pointer_metadata_primary_table[temp_dest_primary_index] == NULL) {
                baps_trie_pointer_metadata_primary_table[temp_dest_primary_index] = baps_trie_pointer_metadata_secondary_allocate();
            }
            void *src_entry_ptr = &baps_trie_pointer_metadata_primary_table[temp_src_primary_index][temp_src_secondary_index];
            void *dest_entry_ptr = &baps_trie_pointer_metadata_primary_table[temp_dest_primary_index][temp_dest_secondary_index];
            memcpy(dest_entry_ptr, src_entry_ptr, 24);
        }
    }
}

bool isAligned(size_t src_addr) { return src_addr % 8 == 0; }

// store ptr to object obj_id
void baps_store_trie_pointer_metadata(void *ptr, void *obj_addr, size_t size, size_t unique_id) {
    size_t addr = (size_t) ptr;
    size_t primary_index = addr >> 25;
    size_t secondary_index = (addr >> 3) & 0x3fffff;
    baps_pointer_metadata_entry *trie_secondary_table = baps_trie_pointer_metadata_primary_table[primary_index];
    if (trie_secondary_table == NULL) {
        trie_secondary_table = baps_trie_pointer_metadata_secondary_allocate();
        baps_trie_pointer_metadata_primary_table[primary_index] = trie_secondary_table;
    }
    assert(trie_secondary_table != NULL && "trie_secondary_table is NULL");
    baps_trie_pointer_metadata_primary_table[primary_index][secondary_index].obj_addr = obj_addr;
    baps_trie_pointer_metadata_primary_table[primary_index][secondary_index].size = size;
    baps_trie_pointer_metadata_primary_table[primary_index][secondary_index].obj_id = unique_id;

}

baps_pointer_metadata_entry *baps_load_trie_pointer_metadata(void *ptr) {
//    printf("addr: %p\n", ptr);
    size_t addr_of_obj = (size_t) ptr;
    size_t primary_index = addr_of_obj >> 25;
    size_t secondary_index = (addr_of_obj >> 3) & 0x3fffff;
    baps_pointer_metadata_entry *trie_secondary_table = baps_trie_pointer_metadata_primary_table[primary_index];
//    assert(trie_secondary_table != NULL && "trie_secondary_table is NULL");
    if (trie_secondary_table == NULL) {
        baps_store_trie_pointer_metadata(ptr, NULL, 0, 0);
    }
    baps_pointer_metadata_entry *object_metadata_entry = &baps_trie_pointer_metadata_primary_table[primary_index][secondary_index];
    return object_metadata_entry;
}

void *baps_load_trie_pointer_metadata_obj(void *ptr) {
    baps_pointer_metadata_entry *entry = baps_load_trie_pointer_metadata(ptr);
    return entry->obj_addr;
}

size_t baps_load_trie_pointer_metadata_size(void *ptr) {
    baps_pointer_metadata_entry *entry = baps_load_trie_pointer_metadata(ptr);
    return entry->size;
}

size_t baps_load_trie_pointer_metadata_unique_id(void *ptr) {
    size_t size = (size_t) ptr;
    baps_pointer_metadata_entry *entry = baps_load_trie_pointer_metadata(ptr);
    return entry->obj_id;
}

// we need to shadow every 8 bytes memory access state  to 1 byte shadow memory, from ptr to ptr+size;
void baps_malloc_shadow_metadata(void *ptr, size_t size) {
//    printf("malloc size: %ld\n",size);
    size_t begin_addr_of_obj = (size_t) ptr;
    size_t end_addr_of_obj = (size_t) ((char *) ptr + size - 1);
    size_t begin_primary_index = begin_addr_of_obj >> 25;
    size_t end_primary_index = end_addr_of_obj >> 25;
    baps_shadow_metadata_entry *trie_secondary_table;
    if (begin_primary_index == end_primary_index) {
        size_t begin_secondary_index = (begin_addr_of_obj >> 3) & 0x3fffff;
        size_t end_secondary_index = (end_addr_of_obj >> 3) & 0x3fffff;
        trie_secondary_table = baps_trie_shadow_metadata_primary_table[begin_primary_index];
        if (trie_secondary_table == NULL) {
            trie_secondary_table = baps_trie_shadow_metadata_secondary_allocate();
            baps_trie_shadow_metadata_primary_table[begin_primary_index] = trie_secondary_table;
        }
        assert(trie_secondary_table != NULL && "trie_secondary_table is NULL");
        for (size_t index = begin_secondary_index; index < end_secondary_index; ++index) {
            trie_secondary_table[index].shadow = 8;
        }
        size_t remain = size % 8;
        trie_secondary_table[end_secondary_index].shadow = remain;
    } else {
        // cross multiple secondary table
        size_t primary_index = begin_primary_index;
        if (primary_index == begin_primary_index) {
            trie_secondary_table = baps_trie_shadow_metadata_primary_table[primary_index];
            if (trie_secondary_table == NULL) {
                trie_secondary_table = baps_trie_shadow_metadata_secondary_allocate();
                baps_trie_shadow_metadata_primary_table[begin_primary_index] = trie_secondary_table;
            }
            assert(trie_secondary_table != NULL && "trie_secondary_table is NULL");
            size_t begin_secondary_index = begin_addr_of_obj >> 25;
            size_t end_secondary_index = baps_shadow_metadata_secondary_table_size - 1;
            for (size_t index = begin_secondary_index;
                 index < end_secondary_index; ++index) {
                trie_secondary_table[index].shadow = 8;
            }
        }
        for (primary_index = begin_primary_index + 1; primary_index < end_primary_index; ++primary_index) {
            trie_secondary_table = baps_trie_shadow_metadata_primary_table[primary_index];
            if (trie_secondary_table == NULL) {
                trie_secondary_table = baps_trie_shadow_metadata_secondary_allocate();
                baps_trie_shadow_metadata_primary_table[begin_primary_index] = trie_secondary_table;
            }
            assert(trie_secondary_table != NULL && "trie_secondary_table is NULL");
            for (size_t index = 0;
                 index < baps_shadow_metadata_secondary_table_size; ++index) {
                trie_secondary_table[index].shadow = 8;
            }
        }
        // when comes to last secondary table, we need to shadow zero to end_secondary_index
        if (primary_index == end_primary_index) {
            trie_secondary_table = baps_trie_shadow_metadata_primary_table[primary_index];
            if (trie_secondary_table == NULL) {
                trie_secondary_table = baps_trie_shadow_metadata_secondary_allocate();
                baps_trie_shadow_metadata_primary_table[begin_primary_index] = trie_secondary_table;
            }
            assert(trie_secondary_table != NULL && "trie_secondary_table is NULL");
            size_t end_secondary_index = (end_addr_of_obj >> 3) & 0x3fffff;
            for (size_t index = 0; index < end_secondary_index; ++index) {
                trie_secondary_table[index].shadow = 8;
            }
            size_t remain = size % 8;
            trie_secondary_table[end_secondary_index].shadow = remain;
        }
    }
}

void baps_free_shadow_metadata(void *ptr, size_t size) {
    size_t addr_of_obj = (size_t) ptr;
    size_t begin_addr_of_obj = addr_of_obj;
    size_t end_addr_of_obj = addr_of_obj + size - 1;
    size_t begin_primary_index = begin_addr_of_obj >> 25;
    size_t end_primary_index = end_addr_of_obj >> 25;
    baps_shadow_metadata_entry *trie_secondary_table;
    if (begin_primary_index == end_primary_index) {
        size_t begin_secondary_index = (begin_addr_of_obj >> 3) & 0x3fffff;
        size_t end_secondary_index = (end_addr_of_obj >> 3) & 0x3fffff;
        trie_secondary_table = baps_trie_shadow_metadata_primary_table[begin_primary_index];
        if (trie_secondary_table == NULL) {
            trie_secondary_table = baps_trie_shadow_metadata_secondary_allocate();
            baps_trie_shadow_metadata_primary_table[begin_primary_index] = trie_secondary_table;
        }
        assert(trie_secondary_table != NULL && "trie_secondary_table is NULL");
        for (size_t index = begin_secondary_index; index <= end_secondary_index; ++index) {
            trie_secondary_table[index].shadow = 32;
        }
    } else {
        // cross multiple secondary table
//        printf("we counter a large memory object allocation request\n");
        size_t primary_index = begin_primary_index;
        if (primary_index == begin_primary_index) {
            trie_secondary_table = baps_trie_shadow_metadata_primary_table[primary_index];
            if (trie_secondary_table == NULL) {
                trie_secondary_table = baps_trie_shadow_metadata_secondary_allocate();
                baps_trie_shadow_metadata_primary_table[begin_primary_index] = trie_secondary_table;
            }
            assert(trie_secondary_table != NULL && "trie_secondary_table is NULL");
            size_t begin_secondary_index = begin_addr_of_obj >> 25;
            size_t end_secondary_index = baps_shadow_metadata_secondary_table_size - 1;
            for (size_t index = begin_secondary_index;
                 index < end_secondary_index; ++index) {
                trie_secondary_table[index].shadow = 32;
            }
        }
        for (primary_index = begin_primary_index + 1; primary_index < end_primary_index; ++primary_index) {
            trie_secondary_table = baps_trie_shadow_metadata_primary_table[primary_index];
            if (trie_secondary_table == NULL) {
                trie_secondary_table = baps_trie_shadow_metadata_secondary_allocate();
                baps_trie_shadow_metadata_primary_table[begin_primary_index] = trie_secondary_table;
            }
            assert(trie_secondary_table != NULL && "trie_secondary_table is NULL");
            for (size_t index = 0;
                 index < baps_shadow_metadata_secondary_table_size; ++index) {
                trie_secondary_table[index].shadow = 32;
            }
        }
        // when comes to last secondary table, we need to shadow zero to end_secondary_index
        if (primary_index == end_primary_index) {
            trie_secondary_table = baps_trie_shadow_metadata_primary_table[primary_index];
            if (trie_secondary_table == NULL) {
                trie_secondary_table = baps_trie_shadow_metadata_secondary_allocate();
                baps_trie_shadow_metadata_primary_table[begin_primary_index] = trie_secondary_table;
            }
            assert(trie_secondary_table != NULL && "trie_secondary_table is NULL");
            size_t end_secondary_index = (end_addr_of_obj >> 3) & 0x3fffff;
            for (size_t index = 0; index < end_secondary_index; ++index) {
                trie_secondary_table[index].shadow = 32;
            }

            trie_secondary_table[end_secondary_index].shadow = 32;
        }
//        abort();
    }
}

size_t baps_access_shadow_metadata(void *ptr) {
    size_t primary_index = (size_t) ptr >> 25;
    size_t secondary_index = ((size_t) ptr >> 3) & 0x3fffff;
    size_t lower_pointer_bits = ((size_t) ptr) & 0x7;
    baps_shadow_metadata_entry *trie_shadow_metadata_secondary_table = baps_trie_shadow_metadata_primary_table[primary_index];
    if (trie_shadow_metadata_secondary_table == NULL) {
        return 0;
    } else {
        size_t status = trie_shadow_metadata_secondary_table[secondary_index].shadow;
        return status;
    }
}

void baps_print_shadow_metadata(void *ptr, size_t size) {
    size_t begin_addr_of_obj = (size_t) ptr;
    size_t end_addr_of_obj = (size_t) ((char *) ptr + size);
    size_t begin_primary_index = begin_addr_of_obj >> 25;
    size_t end_primary_index = end_addr_of_obj >> 25;
    baps_shadow_metadata_entry *trie_secondary_table;
    if (begin_primary_index == end_primary_index) {
        size_t begin_secondary_index = (begin_addr_of_obj >> 3) & 0x3fffff;
        size_t end_secondary_index = (end_addr_of_obj >> 3) & 0x3fffff;
        trie_secondary_table = baps_trie_shadow_metadata_primary_table[begin_primary_index];
        assert(trie_secondary_table != NULL && "trie_secondary_table is NULL");
        for (size_t index = begin_secondary_index; index < end_secondary_index; ++index) {
            printf("index: %ld, state: %d\n", index, (int) trie_secondary_table[index].shadow);
        }
        printf("index: %ld, state: %d\n", end_secondary_index, (int) trie_secondary_table[end_secondary_index].shadow);
    } else {
        // cross multiple secondary table
    }
}

void baps_store_malloc_back_trace(size_t unique_id) {
    baps_store_backtrace_metadata(unique_id, 0);
}

void baps_store_free_back_trace(size_t unique_id) {
    baps_store_backtrace_metadata(unique_id, 1);
}

void baps_store_use_back_trace(size_t unique_id) {
    baps_store_backtrace_metadata(unique_id, 2);
}


/***
 * this function is used to store object-related backtrace, including malloc, free, and use
 * @param unique_id . A unique identifier is a unique identifier that checks whether an object is active
 * @param flags . flags 0 means to store malloc backtrace, 1 means to store free backtrace, 2 means to store use backtrace
 */
void baps_store_backtrace_metadata(size_t unique_id, int flags) {
    size_t primary_index = (size_t) unique_id >> 22;
    size_t secondary_index = ((size_t) unique_id) & 0x3fffff;
    baps_back_trace_entry *trie_secondary_table = baps_trie_backtrace_metadata_primary_table[primary_index];
    if (trie_secondary_table == NULL) {
        trie_secondary_table = baps_trie_backtrace_metadata_secondary_allocate();
        baps_trie_backtrace_metadata_primary_table[primary_index] = trie_secondary_table;
    }
    assert(trie_secondary_table != NULL && "read a backtrace metadata without initialized");
    switch (flags) {
        case 0:
            baps_store_malloc_back_trace_handler(
                    &baps_trie_backtrace_metadata_primary_table[primary_index][secondary_index]);
            break;
        case 1:
            baps_store_free_back_trace_handler(
                    &baps_trie_backtrace_metadata_primary_table[primary_index][secondary_index]);
            break;
        case 2:
            baps_store_use_back_trace_handler(
                    &baps_trie_backtrace_metadata_primary_table[primary_index][secondary_index]);
            break;
        default:
//            baps_store_use_back_trace_handler(
//                    &baps_trie_backtrace_metadata_primary_table[primary_index][secondary_index]);
            break;
    }
}

baps_back_trace_entry *baps_load_back_trace_entry(size_t unique_id) {
    size_t primary_index = (size_t) unique_id >> 22;
    size_t secondary_index = ((size_t) unique_id) & 0x3fffff;
    baps_back_trace_entry *trie_secondary_table = baps_trie_backtrace_metadata_primary_table[primary_index];
    return &baps_trie_backtrace_metadata_primary_table[primary_index][secondary_index];
}

void baps_print_malloc_back_trace(size_t unique_id) {
    fprintf(stderr,"malloc information:\n");
    size_t primary_index = (size_t) unique_id >> 22;
    size_t secondary_index = ((size_t) unique_id) & 0x3fffff;
    baps_back_trace_entry *trie_secondary_table = baps_trie_backtrace_metadata_primary_table[primary_index];
    assert(trie_secondary_table != NULL && "read a backtrace metadata without initialized");
    if (trie_secondary_table == NULL) {
        trie_secondary_table = baps_trie_backtrace_metadata_secondary_allocate();
        baps_trie_backtrace_metadata_primary_table[primary_index] = trie_secondary_table;
    }
    baps_print_malloc_back_trace_handler(&baps_trie_backtrace_metadata_primary_table[primary_index][secondary_index]);
}

void baps_print_free_back_trace(size_t unique_id) {
    fprintf(stderr,"free information:\n");
    size_t primary_index = (size_t) unique_id >> 22;
    size_t secondary_index = ((size_t) unique_id) & 0x3fffff;
    baps_back_trace_entry *trie_secondary_table = baps_trie_backtrace_metadata_primary_table[primary_index];
    assert(trie_secondary_table != NULL && "read a backtrace metadata without initialized");
    if (trie_secondary_table == NULL) {
        trie_secondary_table = baps_trie_backtrace_metadata_secondary_allocate();
        baps_trie_backtrace_metadata_primary_table[primary_index] = trie_secondary_table;
    }
    baps_print_free_back_trace_handler(&baps_trie_backtrace_metadata_primary_table[primary_index][secondary_index]);
}

void baps_print_use_back_trace(size_t unique_id) {
    fprintf(stderr,"use information:\n");
    size_t primary_index = (size_t) unique_id >> 22;
    size_t secondary_index = ((size_t) unique_id) & 0x3fffff;
    baps_back_trace_entry *trie_secondary_table = baps_trie_backtrace_metadata_primary_table[primary_index];
    assert(trie_secondary_table != NULL && "read a backtrace metadata without initialized");
    if (trie_secondary_table == NULL) {
        trie_secondary_table = baps_trie_backtrace_metadata_secondary_allocate();
        baps_trie_backtrace_metadata_primary_table[primary_index] = trie_secondary_table;
    }
    baps_print_use_back_trace_handler(&baps_trie_backtrace_metadata_primary_table[primary_index][secondary_index]);
}


// when a error occurs, we need to abort the program, at the same time, we need to provide debug information.
void baps_abort() {
    printf("Woohs: A UAF may be found here:\n");
    abort();
}


/**
 * used to malloc/free memory by baps
 */

void *baps_safe_malloc(size_t size) {

    return malloc(size);
};

void baps_safe_free(void *ptr) {

    free(ptr);
};

void *baps_safe_calloc(size_t nmeb, size_t size) {

    return calloc(nmeb, size);
};


void *baps_safe_realloc(void *ptr, size_t size) {

    return realloc(ptr, size);
};


void *baps_safe_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    prot = baps_mmap_prot;
    flags = baps_mmap_flags;
    fd = -1;
    offset = 0;
    return mmap(addr, length, prot, flags, fd, offset);
};

void baps_safe_munmap(void *addr, size_t length) {

    munmap(addr, length);
};

/**
 * used to check pointer/object metadata
 */
// will call two function, which separately check pointer metadata and object metadata.
void baps_pointer_dereference_check(void *ptr, size_t ptr_id, void *obj) {
    if (!has_backtrace_info(ptr_id)) { // access global object and is will not freed
        return;
    }
    if (ptr == NULL) {
        return;
    }

//    size_t status = baps_access_shadow_metadata(ptr);
//    if (status == 0) {
//        return;
//    }

    baps_pointer_metadata_entry *entry = baps_load_trie_pointer_metadata(obj);
    size_t *obj_addr = entry->obj_addr;
    size_t obj_id = entry->obj_id;

    if (obj_addr == NULL) {
        if (has_backtrace_info(ptr_id)) {
            fprintf(stderr,"there is a UAF occurs && it is found before memory reuse\n");
//            baps_print_malloc_back_trace(ptr_id);
//            baps_print_free_back_trace(ptr_id);
//            baps_store_use_back_trace(ptr_id);
//            baps_print_use_back_trace(ptr_id);

        } else {
            fprintf(stderr,"there is a UAF occurs && loses UAF diagnosis information\n");
//            baps_print_malloc_back_trace(ptr_id);
//            baps_print_free_back_trace(ptr_id);
//            baps_store_use_back_trace(ptr_id);
//            baps_print_use_back_trace(ptr_id);
        }
    } else {
        if (!has_backtrace_info(ptr_id)) {
            return;
        }

        if (!has_backtrace_info(obj_id)) {
            return;
        }

        if (obj_id == ptr_id || obj_addr == NULL) {
            return;
        }

        if (!has_backtrace_info(ptr_id)) {
            fprintf(stderr,"there is a UAF occurs && it is found after memory reuse\n");
//            baps_print_malloc_back_trace(ptr_id);
//            baps_print_free_back_trace(ptr_id);
//            baps_store_use_back_trace(ptr_id);
//            baps_print_use_back_trace(ptr_id);
//            abort();
        }
        return;
    }

}

bool has_backtrace_info(size_t unique_id) { return unique_id != 0 && unique_id != 1 && unique_id != 2; }


/**
 * wrapper for malloc/free related functions
 */

void *__baps_malloc(size_t size) {
    size_t *ptr = (void *) malloc(size);
    if (ptr == NULL) {
        baps_shadow_stack_store_null_return_metadata();
        return ptr;
    }

    //ptr is not null
    size_t obj_id = get_unique_id(); // get a unique obj_id for this allocation request
    baps_shadow_stack_store_return_metadata(ptr - 1, size, obj_id);
    baps_store_trie_pointer_metadata(ptr - 1, ptr, size, obj_id);
//    baps_malloc_shadow_metadata(ptr, size);
//    baps_store_malloc_back_trace(obj_id);
//    baps_print_malloc_back_trace(obj_id);
    return ptr;
};

void __baps_free(void *ptr) {
    if (ptr == NULL) {
        free(ptr);
        return;
    }
//    printf("%p\n",ptr);
    baps_pointer_metadata_entry *entry = baps_load_trie_pointer_metadata(((size_t *) ptr) - 1);
    size_t *obj_addr = entry->obj_addr;
    size_t obj_id = entry->obj_id;
    size_t obj_size = entry->size;
    size_t ptr_id = baps_shadow_stack_pointer_load_unique_id(1);

    if (!has_backtrace_info(ptr_id) || (ptr_id == obj_id && ptr == obj_addr)) {
        entry->obj_addr = NULL; //invalid object address
//        baps_free_shadow_metadata(obj_addr, obj_size);
//        baps_store_free_back_trace(obj_id);
    } else {
        if (has_backtrace_info(ptr_id)) {
            baps_back_trace_entry *back_trace_entry = baps_load_back_trace_entry(ptr_id);
            if (back_trace_entry->baps_free_back_trace != NULL) {
                if (obj_addr == NULL) {
                    // means we are not freeing reallocated memory
                    printf("there is a UAF occurs[__baps_free] && it is found before memory reuse\n");
//                    baps_print_malloc_back_trace(ptr_id);
//                    baps_print_free_back_trace(ptr_id);
//                    baps_store_use_back_trace(ptr_id);
//                    baps_print_use_back_trace(ptr_id);
                } else if (ptr_id != obj_id) {
//                     means we are freeing reallocated memory
                    entry->obj_addr = NULL;
//                    baps_free_shadow_metadata(obj_addr, obj_size);
//                    baps_store_free_back_trace(obj_id);
//
                    printf("there is a UAF occurs[__baps_free] && it is found after memory reuse\n");
//                    baps_print_malloc_back_trace(ptr_id);
//                    baps_print_free_back_trace(ptr_id);
//                    baps_store_use_back_trace(ptr_id);
//                    baps_print_use_back_trace(ptr_id);
                } else {

                }
            } else {
            }
        } else {

        }
    }
    free(ptr);
};

void *__baps_calloc(size_t nmeb, size_t size) {
    size_t *ptr = calloc(nmeb, size);
    if (ptr == NULL) {
        baps_shadow_stack_store_null_return_metadata();
        return ptr;
    }
    size_t obj_id = get_unique_id(); // get a unique obj_id for this allocation request
    baps_shadow_stack_store_return_metadata(ptr - 1, nmeb * size, obj_id);
    baps_store_trie_pointer_metadata(ptr - 1, ptr, nmeb * size, obj_id);
//    baps_malloc_shadow_metadata(ptr, nmeb * size);
//    baps_store_malloc_back_trace(obj_id);
    return ptr;
};

void *__baps_realloc(void *ptr, size_t size) {
    if (ptr == NULL) { //ptr is NULL, the call is equivalent to malloc(size)
        size_t *ret_ptr = realloc(ptr, size);
        if (ret_ptr == NULL) {
            baps_shadow_stack_store_null_return_metadata();
            return ret_ptr;
        }
        size_t obj_id = get_unique_id(); // get a unique obj_id for this allocation request
        baps_shadow_stack_store_return_metadata(ret_ptr - 1, size, obj_id);
        baps_store_trie_pointer_metadata(ret_ptr - 1, ret_ptr, size, obj_id);
//        baps_malloc_shadow_metadata(ret_ptr, size);
//        baps_store_malloc_back_trace(obj_id);
        return ret_ptr;
    } else if (size == 0) { // size is zero, the call is equivalent to free(size)
        void *ret_ptr = realloc(ptr, size);
        baps_pointer_metadata_entry *entry = baps_load_trie_pointer_metadata(((size_t *) ptr) - 1);
        size_t *obj_addr = entry->obj_addr;
        size_t obj_id = entry->obj_id;
        size_t obj_size = entry->size;
        size_t ptr_id = baps_shadow_stack_pointer_load_unique_id(1);
//        size_t status = baps_access_shadow_metadata(ptr);

        if (!has_backtrace_info(ptr_id) || (ptr_id == obj_id && ptr == obj_addr)) {
            entry->obj_addr = NULL; //invalid object address
//            baps_free_shadow_metadata(obj_addr, obj_size);
//            baps_store_free_back_trace(obj_id);
        } else {
            if (has_backtrace_info(ptr_id)) {
                baps_back_trace_entry *back_trace_entry = baps_load_back_trace_entry(ptr_id);
                if (back_trace_entry->baps_free_back_trace != NULL) {
                    if (obj_addr == NULL) {
                        // means we are not freeing reallocated memory
                        printf("there is a UAF occurs[__baps_realloc] && it is found before memory reuse\n");
//                        baps_print_malloc_back_trace(ptr_id);
//                        baps_print_free_back_trace(ptr_id);
//                        baps_store_use_back_trace(ptr_id);
//                        baps_print_use_back_trace(ptr_id);
                    } else if (ptr_id != obj_id) {
                        // means we are freeing reallocated memory
                        entry->obj_addr = NULL;
//                        baps_free_shadow_metadata(obj_addr, obj_size);
//                        baps_store_free_back_trace(obj_id);

                        printf("there is a UAF occurs[__baps_realloc] && it is found after memory reuse\n");
//                        baps_print_malloc_back_trace(ptr_id);
//                        baps_print_free_back_trace(ptr_id);
//                        baps_store_use_back_trace(ptr_id);
//                        baps_print_use_back_trace(ptr_id);
                    } else {

                    }
                } else {
                }
            } else {

            }
        }
        return ret_ptr;
    } else { // ptr is not NULL, and size is not zero
        size_t *ret_ptr = realloc(ptr, size);
        // if ptr == ret_ptr, obj is not freed, but modify obj size
        if (ptr == ret_ptr) {
            baps_pointer_metadata_entry *entry = baps_load_trie_pointer_metadata(((size_t *) ptr) - 1);
            size_t obj_id = entry->obj_id;
            size_t old_size = entry->size;
            entry->size = size;
            // if not change memory object begin address, we only need to modify memory object size;
//            baps_free_shadow_metadata(ptr, old_size);
//            baps_store_malloc_back_trace(obj_id);
//            baps_malloc_shadow_metadata(ptr, size);

        } else { //old obj is freed, a new obj is allocated
            //old obj is freed
            baps_pointer_metadata_entry *entry = baps_load_trie_pointer_metadata(((size_t *) ptr) - 1);
            size_t obj_id = entry->obj_id;
            size_t *obj_addr = entry->obj_addr;
            size_t old_size = entry->size;

            entry->obj_addr = NULL;
//            baps_store_free_back_trace(obj_id);
//            baps_free_shadow_metadata(ptr, old_size);

            //new obj is allocated
            size_t new_unique_id = get_unique_id();
            baps_shadow_stack_store_return_metadata(ret_ptr - 1, size, new_unique_id);
            baps_store_trie_pointer_metadata(ret_ptr - 1, ret_ptr, size, new_unique_id);
//            baps_store_malloc_back_trace(new_unique_id);
//            baps_malloc_shadow_metadata(ret_ptr, size);
        }
        return ret_ptr;
    }

};

void *__baps_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
//    printf("[__baps_mmap]malloc size: %ld\n", length);
    size_t *ret_ptr = (mmap(addr, length, prot, flags, fd, offset));
    if (ret_ptr == NULL) {
        baps_shadow_stack_store_null_return_metadata();
        return ret_ptr;
    }
    size_t unique_id = get_unique_id(); // get a unique obj_id for this allocation request
    baps_shadow_stack_store_return_metadata(ret_ptr - 1, length, unique_id);
    baps_store_trie_pointer_metadata(ret_ptr - 1, ret_ptr, length, unique_id);
//    baps_malloc_shadow_metadata(ret_ptr, length);
//    baps_store_malloc_back_trace(unique_id);
    return ret_ptr;
};

void __baps_munmap(void *ptr, size_t length) {
//    printf("[__baps_munmap]obj address: %p\n", addr);
    baps_pointer_metadata_entry *entry = baps_load_trie_pointer_metadata(((size_t *) ptr) - 1);
    size_t *obj_addr = entry->obj_addr;
    size_t obj_id = entry->obj_id;
    size_t obj_size = entry->size;
    size_t ptr_id = baps_shadow_stack_pointer_load_unique_id(1);
//    size_t status = baps_access_shadow_metadata(ptr);

    if (!has_backtrace_info(ptr_id) || (ptr_id == obj_id && ptr == obj_addr)) {
        entry->obj_addr = NULL; //invalid object address
//        baps_free_shadow_metadata(obj_addr, obj_size);
//        baps_store_free_back_trace(obj_id);
    } else {
        if (has_backtrace_info(ptr_id)) {
            baps_back_trace_entry *back_trace_entry = baps_load_back_trace_entry(ptr_id);
            if (back_trace_entry->baps_free_back_trace != NULL) {
                if (obj_addr == NULL) {
                    // means we are not freeing reallocated memory
                    printf("there is a UAF occurs[__baps_munmap] && it is found before memory reuse\n");
//                    baps_print_malloc_back_trace(ptr_id);
//                    baps_print_free_back_trace(ptr_id);
//                    baps_store_use_back_trace(ptr_id);
//                    baps_print_use_back_trace(ptr_id);
                } else if (ptr_id != obj_id) {
                    // means we are freeing reallocated memory
                    entry->obj_addr = NULL;
//                    baps_free_shadow_metadata(obj_addr, obj_size);
//                    baps_store_free_back_trace(obj_id);

                    printf("there is a UAF occurs[__baps_munmap] && it is found after memory reuse\n");
//                    baps_print_malloc_back_trace(ptr_id);
//                    baps_print_free_back_trace(ptr_id);
//                    baps_store_use_back_trace(ptr_id);
//                    baps_print_use_back_trace(ptr_id);
                } else {

                }
            } else {
            }
        } else {

        }
    }
    munmap(ptr, length);
}

void *__baps_new(size_t size) {
//    printf("call function __baps_new: ...\n");
    size_t *ptr = malloc(size);
    if (ptr == NULL) {
        baps_shadow_stack_store_null_return_metadata();
        return ptr;
    }
    /**
   * ptr is not null
   */
    size_t obj_id = get_unique_id(); // get a unique obj_id for this allocation request
    baps_shadow_stack_store_return_metadata(ptr - 1, size, obj_id);
    baps_store_trie_pointer_metadata(ptr - 1, ptr, size, obj_id);
//    baps_malloc_shadow_metadata(ptr, size);
//    baps_store_malloc_back_trace(obj_id);
    return ptr;
};

void __baps_delete(void *ptr) {
//    printf("call function __baps_delete: %p...\n",ptr);
    baps_pointer_metadata_entry *entry = baps_load_trie_pointer_metadata(((size_t *) ptr) - 1);
    size_t obj_id = entry->obj_id;
    size_t obj_size = entry->size;
    size_t *obj_addr = entry->obj_addr;
    size_t ptr_id = baps_shadow_stack_pointer_load_unique_id(1);
//    size_t status = baps_access_shadow_metadata(ptr);

    printf("%ld %ld %p %p\n", ptr_id, obj_id, ptr, obj_addr);
    if (!has_backtrace_info(ptr_id) || (ptr_id == obj_id && ptr == obj_addr)) {
        entry->obj_addr = NULL; //invalid object address
//        baps_free_shadow_metadata(obj_addr, obj_size);
//        baps_store_free_back_trace(obj_id);
    } else {
        if (has_backtrace_info(ptr_id)) {
            baps_back_trace_entry *back_trace_entry = baps_load_back_trace_entry(ptr_id);
            if (back_trace_entry->baps_free_back_trace != NULL) {
                if (obj_addr == NULL) {
                    // means we are not freeing reallocated memory
                    printf("there is a UAF occurs[__baps_delete] && it is found before memory reuse\n");
//                    baps_print_malloc_back_trace(ptr_id);
//                    baps_print_free_back_trace(ptr_id);
//                    baps_store_use_back_trace(ptr_id);
//                    baps_print_use_back_trace(ptr_id);
                } else if (ptr_id != obj_id) {
                    // means we are freeing reallocated memory
                    entry->obj_addr = NULL;
//                    baps_free_shadow_metadata(obj_addr, obj_size);
//                    baps_store_free_back_trace(obj_id);

                    printf("there is a UAF occurs[__baps_delete] && it is found after memory reuse\n");
//                    baps_print_malloc_back_trace(ptr_id);
//                    baps_print_free_back_trace(ptr_id);
//                    baps_store_use_back_trace(ptr_id);
//                    baps_print_use_back_trace(ptr_id);
                } else {

                }
            } else {
            }
        } else {

        }
    }
    free(ptr);
};

/*
 * wrappers for library calls
 */

int __baps_setenv(const char *name, const char *value, int overwrite) {
//    printf("call function __baps_setenv: ...\n");
    return setenv(name, value, overwrite);
}


int __baps_unsetenv(const char *name) {
//    printf("call function __baps_unsetenv: ...\n");
    return unsetenv(name);
}


int __baps_system(char *ptr) {
//    printf("call function __baps_system: ...\n");
    return system(ptr);
}

int __baps_setreuid(uid_t ruid, uid_t euid) {
//    printf("call function __baps_setreuid: ...\n");
    return setreuid(ruid, euid);
}

int __baps_mkstemp(char *_template) {
//    printf("call function __baps_mkstemp: ...\n");
    return mkstemp(_template);
}

uid_t __baps_geteuid() {
//    printf("call function __baps_geteuid: ...\n");
    return geteuid();
}

uid_t __baps_getuid(void) {
//    printf("call function __baps_getuid: ...\n");
    return getuid();
}

int __baps_getrlimit(int resource, struct rlimit *rlim) {
//    printf("call function __baps_getrlimit: ...\n");
    return getrlimit(resource, rlim);
}

int __baps_setrlimit(int resource, const struct rlimit *rlim) {
//    printf("call function __baps_setrlimit: ...\n");
    return setrlimit(resource, rlim);
}

size_t __baps_fread_unlocked(void *ptr, size_t size,
                             size_t n, FILE *stream) {
//    printf("call function __baps_fread_unlocked: ...\n");
    return fread_unlocked(ptr, size, n, stream);
}

#if 0
int __baps_fputs_unlocked(const char *s, FILE *stream){
    printf("call function __baps_fputs_unlocked: ...\n");
    return fputs_unlocked(s, stream);
}
#endif

size_t __baps_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
//    printf("call function __baps_fread: ...\n");
    return fread(ptr, size, nmemb, stream);
}

mode_t __baps_umask(mode_t mask) {
//    printf("call function __baps_umask: ...\n");
    return umask(mask);
}

int __baps_mkdir(const char *pathname, mode_t mode) {
//    printf("call function __baps_mkdir: ...\n");
    return mkdir(pathname, mode);
}

int __baps_chroot(const char *path) {
//    printf("call function __baps_chroot: ...\n");
    return chroot(path);
}

int __baps_rmdir(const char *pathname) {
//    printf("call function __baps_rmdir: ...\n");
    return rmdir(pathname);
}

int __baps_stat(const char *path, struct stat *buf) {
//    printf("call function __baps_stat: ...\n");
    return stat(path, buf);
}

int __baps_fputc(int c, FILE *stream) {
//    printf("call function __baps_fputc: ...\n");
    return fputc(c, stream);
}

int __baps_fileno(FILE *stream) {
//    printf("call function __baps_fileno: ...\n");
    return fileno(stream);
}

int __baps_fgetc(FILE *stream) {
//    printf("call function __baps_fgetc: ...\n");
    return fgetc(stream);
}

int __baps_ungetc(int c, FILE *stream) {
//    printf("call function __baps_ungetc: ...\n");
    return ungetc(c, stream);
}

int __baps_strncmp(const char *s1, const char *s2, size_t n) {
//    printf("call function __baps_strncmp: ...\n");
    return strncmp(s1, s2, n);
}

double __baps_log(double x) {
//    printf("call function __baps_log: ...\n");
    return log(x);
}


long long __baps_fwrite(char *ptr, size_t size, size_t nmemb, FILE *stream) {
//    printf("call function __baps_fwrite: ...\n");
    return fwrite(ptr, size, nmemb, stream);
}

double __baps_atof(char *ptr) {
//    printf("call function __baps_atof: ...\n");
    return atof(ptr);
}

int __baps_feof(FILE *stream) {
//    printf("call function __baps_feof: ...\n");
    return feof(stream);
}

int __baps_remove(const char *pathname) {
//    printf("call function __baps_remove: ...\n");
    return remove(pathname);
}

/*
 * wrappers for math calls
 */

double __baps_acos(double x) {
//    printf("call function __baps_acos: ...\n");
    return acos(x);
}

double __baps_atan2(double y, double x) {
//    printf("call function __baps_atan2: ...\n");
    return atan2(y, x);
}

float __baps_sqrtf(float x) {
//    printf("call function __baps_sqrtf: ...\n");
    return sqrtf(x);
}

float __baps_expf(float x) {
//    printf("call function __baps_expf: ...\n");
    return expf(x);
}

double __baps_exp2(double x) {
//    printf("call function __baps_exp2: ...\n");
    return exp2(x);
}

float __baps_floorf(float x) {
//    printf("call function __baps_floorf: ...\n");
    return floorf(x);
}

double __baps_ceil(double x) {
//    printf("call function __baps_ceil: ...\n");
    return ceil(x);
}

float __baps_ceilf(float x) {
//    printf("call function __baps_ceilf: ...\n");
    return ceilf(x);
}

double __baps_floor(double x) {
//    printf("call function __baps_floor: ...\n");
    return floor(x);
}

double __baps_sqrt(double x) {
//    printf("call function __baps_sqrt: ...\n");
    return sqrt(x);
}

double __baps_fabs(double x) {
//    printf("call function __baps_fabs: ...\n");
    return fabs(x);
}

int __baps_abs(int j) {
//    printf("call function __baps_abs: ...\n");
    return abs(j);
}

void __baps_srand(unsigned int seed) {
//    printf("call function __baps_srand: ...\n");
    srand(seed);
}

void __baps_srand48(long int seed) {
//    printf("call function __baps_srand48: ...\n");
    srand48(seed);
}


double __baps_pow(double x, double y) {
//    printf("call function __baps_pow: ...\n");
    return pow(x, y);

}

float __baps_fabsf(float x) {
//    printf("call function __baps_fabsf: ...\n");
    return fabsf(x);
}

double __baps_tan(double x) {
//    printf("call function __baps_tan: ...\n");
    return tan(x);
}

float __baps_tanf(float x) {
//    printf("call function __baps_tanf: ...\n");
    return tanf(x);
}

long double __baps_tanl(long double x) {
//    printf("call function __baps_tanl: ...\n");
    return tanl(x);
}

double __baps_log10(double x) {
//    printf("call function __baps_log10: ...\n");
    return log10(x);
}

double __baps_sin(double x) {
//    printf("call function __baps_sin: ...\n");
    return sin(x);
}

float __baps_sinf(float x) {
//    printf("call function __baps_sinf: ...\n");
    return sinf(x);
}

long double __baps_sinl(long double x) {
//    printf("call function __baps_sinl: ...\n");
    return sinl(x);
}

double __baps_cos(double x) {
//    printf("call function __baps_cos: ...\n");
    return cos(x);
}

float __baps_cosf(float x) {
//    printf("call function __baps_cosf: ...\n");
    return cosf(x);
}

long double __baps_cosl(long double x) {
//    printf("call function __baps_cosl: ...\n");
    return cosl(x);
}

double __baps_exp(double x) {
//    printf("call function __baps_exp: ...\n");
    return exp(x);
}

double __baps_ldexp(double x, int exp) {
//    printf("call function __baps_ldexp: ...\n");
    return ldexp(x, exp);
}

/*
 * wrappers for File-related function calls
 */
FILE *__baps_tmpfile(void) {
//    printf("call function __baps_tmpfile: ...\n");
    void *ptr = tmpfile();
    baps_shadow_stack_store_return_metadata(ptr, sizeof(FILE), 1);
    return ptr;
}

int __baps_ferror(FILE *stream) {
//    printf("call function __baps_ferror: ...\n");
    return ferror(stream);
}

long __baps_ftell(FILE *stream) {
//    printf("call function __baps_ftell: ...\n");
    return ftell(stream);
}

int __baps_fstat(int filedes, struct stat *buff) {
//    printf("call function __baps_fstat: ...\n");
    return fstat(filedes, buff);
}

int __baps___lxstat(int __ver, const char *__filename,
                    struct stat *__stat_buf) {
//    printf("call function __baps___lxstat: ...\n");
    return __lxstat(__ver, __filename, __stat_buf);
}

size_t __baps_mbrtowc(wchar_t *pwc, const char *s,
                      size_t n, mbstate_t *ps) {
//    printf("call function __baps_mbrtowc: ...\n");
    return mbrtowc(pwc, s, n, ps);
}


int __baps_mbsinit(const mbstate_t *ps) {
//    printf("call function __baps_mbsinit: ...\n");
    return mbsinit(ps);
}


int __baps___fxstat(int ver, int file_des, struct stat *stat_struct) {
//    printf("call function __baps___fxstat: ...\n");
    return __fxstat(ver, file_des, stat_struct);
}

int __baps___fxstatat(int ver, int file_des, const char *filename, struct stat *stat_struct, int flag) {
//    printf("call function __baps___fxstatat: ...\n");
    return __fxstatat(ver, file_des, filename, stat_struct, flag);
}


int __baps_fflush(FILE *stream) {
//    printf("call function __baps_fflush: ...\n");
    return fflush(stream);
}

int __baps_fputs(const char *s, FILE *stream) {
//    printf("call function __baps_fputs: ...\n");
    return fputs(s, stream);
}

int __baps_fsync(int fd) {
//    printf("call function __baps_fsync: ...\n");
    return fsync(fd);
}

DIR *__baps_fdopendir(int fd) {
//    printf("call function __baps_fdopendir: ...\n");
    void *ptr = (void *) fdopendir(fd);
    baps_shadow_stack_store_return_metadata(ptr, 1024 * 1024, 1);
    return ptr;
}

int __baps_fseeko(FILE *stream, off_t offset, int whence) {
//    printf("call function __baps_fseeko: ...\n");
    return fseeko(stream, offset, whence);
}

char *__baps_mkdtemp(char *_template) {
//    printf("call function __baps_mkdtemp: ...\n");
    baps_propagate_shadow_stack_pointer_metadata(1, 0);
    return (char *) mkdtemp(_template);
}

int __baps_raise(int sig) {
//    printf("call function __baps_raise: ...\n");
    return raise(sig);
}

int __baps_linkat(int olddirfd, const char *oldpath,
                  int newdirfd, const char *newpath,
                  int flags) {
//    printf("call function __baps_linkat: ...\n");
    return linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

int __baps_utimes(const char *filename,
                  const struct timeval times[2]) {
//    printf("call function __baps_utimes: ...\n");
    return utimes(filename, times);
}

#if 0
int __baps_futimesat(int dirfd, const char *pathname,
                                          const struct timeval times[2]){
    printf("call function __baps_futimesat: ...\n");
    return futimesat(dirfd, pathname, times);
}
#endif

int __baps_futimens(int fd, const struct timespec times[2]) {
//    printf("call function __baps_futimens: ...\n");
    return futimens(fd, times);
}

int __baps_utimensat(int dirfd, const char *pathname,
                     const struct timespec times[2], int flags) {
//    printf("call function __baps_utimensat: ...\n");
    return utimensat(dirfd, pathname, times, flags);
}

size_t __baps___ctype_get_mb_cur_max(void) {
//    printf("call function __baps___ctype_get_mb_cur_max: ...\n");
    return __ctype_get_mb_cur_max();
}

int __baps_iswprint(wint_t wc) {
//    printf("call function __baps_iswprint: ...\n");
    return iswprint(wc);
}

int __baps_getpagesize(void) {
//    printf("call function __baps_getpagesize: ...\n");
    return getpagesize();
}

int __baps_dirfd(DIR *dirp) {
//    printf("call function __baps_dirfd: ...\n");
    return dirfd(dirp);
}

struct lconv *__baps_localeconv(void) {
//    printf("call function __baps_localeconv: ...\n");
    struct lconv *ptr = localeconv();
    baps_shadow_stack_store_return_metadata(ptr, 1024, 1);
    return ptr;
}

struct tm *__baps_gmtime(const time_t *timep) {
//    printf("call function __baps_gmtime: ...\n");
    struct tm *ptr = gmtime(timep);
    baps_shadow_stack_store_return_metadata(ptr, 1024, 1);
    return ptr;
}

void *__baps_bsearch(const void *key, const void *base,
                     size_t nmemb, size_t size,
                     int (*compar)(const void *, const void *)) {
//    printf("call function __baps_bsearch: ...\n");
    void *ptr = bsearch(key, base, nmemb, size, compar);
    baps_propagate_shadow_stack_pointer_metadata(2, 0);
    return ptr;
}


struct group *__baps_getgrnam(const char *name) {
//    printf("call function __baps_getgrnam: ...\n");
    struct group *ptr = getgrnam(name);
    baps_shadow_stack_store_return_metadata(ptr, 1024 * 1024, 1);
    return ptr;
}


int __baps_rpmatch(const char *response) {
//    printf("call function __baps_rpmatch: ...\n");
    return rpmatch(response);
}


int __baps_regcomp(regex_t *preg, const char *regex, int cflags) {
//    printf("call function __baps_regcomp: ...\n");
    return regcomp(preg, regex, cflags);
}


size_t __baps_regerror(int errcode, const regex_t *preg, char *errbuf,
                       size_t errbuf_size) {
//    printf("call function __baps_regerror: ...\n");
    return regerror(errcode, preg, errbuf, errbuf_size);
}


int __baps_regexec(const regex_t *preg, const char *string,
                   size_t nmatch,
                   regmatch_t pmatch[], int eflags) {
//    printf("call function __baps_regexec: ...\n");
    return regexec(preg, string, nmatch, pmatch, eflags);
}


#ifdef HAVE_ICONV_H

size_t __baps_iconv(iconv_t cd,
                    char **inbuf, size_t *inbytesleft,
                    char **outbuf, size_t *outbytesleft) {
    printf("call function __baps_iconv: ...\n");
    return iconv(cd, inbuf, inbytesleft, outbuf, outbytesleft);
}


iconv_t __baps_iconv_open(const char *tocode, const char *fromcode) {
    printf("call function __baps_iconv_open: ...\n");
    return iconv_open(tocode, fromcode);
}

#endif


struct passwd *__baps_getpwnam(const char *name) {
//    printf("call function __baps_getpwnam: ...\n");
    struct passwd *ptr = getpwnam(name);
    baps_shadow_stack_store_return_metadata(ptr, 1024 * 1024, 1);
    return ptr;
}

struct passwd *__baps_getpwuid(uid_t uid) {
//    printf("call function __baps_getpwuid: ...\n");
    struct passwd *ptr = getpwuid(uid);
    baps_shadow_stack_store_return_metadata(ptr, 1024 * 1024, 1);
    return ptr;
}

struct group *__baps_getgrgid(gid_t gid) {
//    printf("call function __baps_getgrgid: ...\n");
    struct group *ptr = getgrgid(gid);
    baps_shadow_stack_store_return_metadata(ptr, 1024 * 1024, 1);
    return ptr;

}


FILE *__baps_fopen(const char *path, const char *mode) {
//    printf("call function __baps_fopen: ...\n");
    FILE *ptr = fopen(path, mode);
    baps_shadow_stack_store_return_metadata(ptr, sizeof(FILE), 1);
    return ptr;
}

FILE *__baps_fdopen(int fildes, const char *mode) {
//    printf("call function __baps_fdopen: ...\n");
    FILE *ptr = fdopen(fildes, mode);
    baps_shadow_stack_store_return_metadata(ptr, sizeof(FILE), 1);
    return ptr;
}


int __baps_fseek(FILE *stream, long offset, int whence) {
//    printf("call function __baps_fseek: ...\n");
    return fseek(stream, offset, whence);
}

int __baps_ftruncate(int fd, off_t length) {
//    printf("call function __baps_ftruncate: ...\n");
    return ftruncate(fd, length);
}


FILE *__baps_popen(const char *command, const char *type) {
//    printf("call function __baps_popen: ...\n");
    FILE *ptr = popen(command, type);
    baps_shadow_stack_store_return_metadata(ptr, sizeof(FILE), 1);
    return ptr;
}

int __baps_fclose(FILE *fp) {
//    printf("call function __baps_fclose: ...\n");
    return fclose(fp);
}

int __baps_pclose(FILE *stream) {
//    printf("call function __baps_pclose: ...\n");
    return pclose(stream);
}

void __baps_rewind(FILE *stream) {
//    printf("call function __baps_rewind: ...\n");
    rewind(stream);
}

struct dirent *__baps_readdir(DIR *dir) {
//    printf("call function __baps_readdir: ...\n");
    struct dirent *ptr = readdir(dir);
    baps_shadow_stack_store_return_metadata(ptr, sizeof(FILE), 1);
    return ptr;
}

int __baps_creat(const char *pathname, mode_t mode) {
//    printf("call function __baps_creat: ...\n");
    return creat(pathname, mode);
}

int __baps_fnmatch(const char *pattern, const char *string, int flags) {
//    printf("call function __baps_fnmatch: ...\n");
    return fnmatch(pattern, string, flags);
}


DIR *__baps_opendir(const char *name) {
//    printf("call function __baps_opendir: ...\n");
    DIR *ptr = opendir(name);
    baps_shadow_stack_store_return_metadata(ptr, 1024 * 1024, 1);
    return ptr;
}

int __baps_closedir(DIR *dir) {
//    printf("call function __baps_closedir: ...\n");
    return closedir(dir);
}

int __baps_rename(const char *old_path, const char *new_path) {
//    printf("call function __baps_rename: ...\n");
    return rename(old_path, new_path);
}

/**
 * wrappers for unistd-releated calls
 */

unsigned int __baps_sleep(unsigned int seconds) {
//    printf("call function __baps_sleep: ...\n");
    return sleep(seconds);
}

char *__baps_getcwd(char *buf, size_t size) {
//    printf("call function __baps_getcwd: ...\n");
    char *ptr = getcwd(buf, size);
    baps_propagate_shadow_stack_pointer_metadata(1, 0);
    return ptr;
}

int __baps_setgid(gid_t gid) {
//    printf("call function __baps_setgid: ...\n");
    return setgid(gid);
}


gid_t __baps_getgid(void) {
//    printf("call function __baps_getgid: ...\n");
    return getgid();
}

gid_t __baps_getegid(void) {
//    printf("call function __baps_getegid: ...\n");
    return getegid();
}

int __baps_readlinkat(int dirfd, const char *pathname,
                      char *buf, size_t bufsiz) {
//    printf("call function __baps_readlinkat: ...\n");
    return readlinkat(dirfd, pathname, buf, bufsiz);
}

int __baps_renameat(int olddirfd, const char *oldpath,
                    int newdirfd, const char *newpath) {
//    printf("call function __baps_renameat: ...\n");
    return renameat(olddirfd, oldpath, newdirfd, newpath);
}

int __baps_unlinkat(int dirfd, const char *pathname, int flags) {
//    printf("call function __baps_unlinkat: ...\n");
    return unlinkat(dirfd, pathname, flags);
}

int __baps_symlinkat(const char *oldpath, int newdirfd,
                     const char *newpath) {
//    printf("call function __baps_symlinkat: ...\n");
    return symlinkat(oldpath, newdirfd, newpath);
}

int __baps_mkdirat(int dirfd, const char *pathname, mode_t mode) {
//    printf("call function __baps_mkdirat: ...\n");
    return mkdirat(dirfd, pathname, mode);
}

int __baps_fchown(int fd, uid_t owner, gid_t group) {
//    printf("call function __baps_fchown: ...\n");
    return fchown(fd, owner, group);
}

int __baps_fchownat(int dirfd, const char *pathname,
                    uid_t owner, gid_t group, int flags) {
//    printf("call function __baps_fchownat: ...\n");
    return fchownat(dirfd, pathname, owner, group, flags);
}

int __baps_fchmod(int fd, mode_t mode) {
//    printf("call function __baps_fchmod: ...\n");
    return fchmod(fd, mode);
}

int __baps_chmod(const char *path, mode_t mode) {
//    printf("call function __baps_chmod: ...\n");
    return chmod(path, mode);
}

int __baps_openat(int dirfd, const char *pathname, int flags) {
//    printf("call function __baps_openat: ...\n");
    return openat(dirfd, pathname, flags);
}


int __baps_fchmodat(int dirfd, const char *pathname,
                    mode_t mode, int flags) {
//    printf("call function __baps_fchmodat: ...\n");
    return fchmodat(dirfd, pathname, mode, flags);
}

#if defined (__linux__)

int __baps___xmknodat(int __ver, int __fd, const char *__path,
                      __mode_t __mode, __dev_t *__dev) {
//    printf("call function __baps___xmknodat: ...\n");
    return __xmknodat(__ver, __fd, __path, __mode, __dev);
}

int __baps_mkfifoat(int dirfd, const char *pathname, mode_t mode) {
//    printf("call function __baps_mkfifoat: ...\n");
    return mkfifoat(dirfd, pathname, mode);
}

#endif

pid_t __baps_getpid(void) {
//    printf("call function __baps_getpid: ...\n");
    return getpid();
}

pid_t __baps_getppid(void) {
//    printf("call function __baps_getppid: ...\n");
    return getppid();
}

#if 0

int __baps_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    printf("call function __baps_openat: ...\n");
    return opennat(dirfd, pathname, flags, mode);
}

#endif

int __baps_chown(const char *path, uid_t owner, gid_t group) {
//    printf("call function __baps_chown: ...\n");
    return chown(path, owner, group);
}

wint_t __baps_towlower(wint_t wc) {
//    printf("call function __baps_towlower: ...\n");
    return towlower(wc);
}

int __baps_isatty(int desc) {
//    printf("call function __baps_isatty: ...\n");
    return isatty(desc);
}

int __baps_chdir(const char *path) {
//    printf("call function __baps_chdir: ...\n");
    return chdir(path);
}

int __baps_fchdir(int fd) {
//    printf("call function __baps_fchdir: ...\n");
    return fchdir(fd);
}

/**
 * wrrappers for String
 */

int __baps_strcmp(const char *s1, const char *s2) {
//    printf("call function __baps_strcmp: ...\n");
    return strcmp(s1, s2);
}

int __baps_strcasecmp(const char *s1, const char *s2) {
//    printf("call function __baps_strcasecmp: ...\n");
    return strcasecmp(s1, s2);
}

int __baps_strncasecmp(const char *s1, const char *s2, size_t n) {
//    printf("call function __baps_strncasecmp: ...\n");
    return strncasecmp(s1, s2, n);
}

size_t __baps_strlen(const char *s) {
//    printf("call function __baps_strlen: ...\n");
    return strlen(s);
}

char *__baps_strpbrk(const char *s, const char *accept) {
//    printf("call function __baps_strpbrk: ...\n");
    char *ptr = strpbrk(s, accept);
    if (ptr == NULL) {
        baps_shadow_stack_store_null_return_metadata();
    } else {
        baps_propagate_shadow_stack_pointer_metadata(1, 0);
    }
    return ptr;
}

char *__baps_gets(char *s) {
//    printf("call function __baps_gets: ...\n");
    baps_propagate_shadow_stack_pointer_metadata(1, 0);
    return NULL;
}

char *__baps_fgets(char *s, int size, FILE *stream) {
//    printf("call function __baps_fgets: ...\n");
    char *ptr = fgets(s, size, stream);
    baps_propagate_shadow_stack_pointer_metadata(1, 0);
    return ptr;
}


void __baps_perror(const char *s) {
//    printf("call function __baps_perror: ...\n");
    perror(s);
}

size_t __baps_strspn(const char *s, const char *accept) {
//    printf("call function __baps_strspn: ...\n");
    return strspn(s, accept);
}

size_t __baps_strcspn(const char *s, const char *reject) {
//    printf("call function __baps_strcspn: ...\n");
    return strcspn(s, reject);
}

#ifdef _GNU_SOURCE
//void *__baps_mempcpy(void *dest, const void *src, size_t n){
//
//    // IMP: need to copy the metadata
//    void* ret_ptr = mempcpy(dest, src, n);
//    baps_propagate_shadow_stack_pointer_metadata(1,0);
//    return ret_ptr;
//}
#endif

int __baps_memcmp(const void *s1, const void *s2, size_t n) {
//    printf("call function __baps_memcmp: ...\n");
    return memcmp(s1, s2, n);
}

#ifdef _GNU_SOURCE

#endif

void __baps_rewinddir(DIR *dirp) {
//    printf("call function __baps_rewinddir: ...\n");
    rewinddir(dirp);
}


void *__baps_memchr(const void *s, int c, size_t n) {
//    printf("call function __baps_memchr: ...\n");
    char *ptr = memchr(s, c, n);
    if (ptr == NULL) {
        baps_shadow_stack_store_null_return_metadata();
    } else {
        baps_propagate_shadow_stack_pointer_metadata(1, 0);
    }
    return ptr;
}

char *__baps_rindex(char *s, int c) {
//    printf("call function __baps_rindex: ...\n");
    char *ret_ptr = rindex(s, c);
    baps_propagate_shadow_stack_pointer_metadata(1, 0);
    return ret_ptr;
}

ssize_t __baps_getdelim(char **lineptr, size_t *n, int delim, FILE *stream) {
//    printf("call function __baps_getdelim: ...\n");
    return getdelim(lineptr, n, delim, stream);
}

unsigned long int __baps_strtoul(const char *nptr, char **endptr, int base) {
//    printf("call function __baps_strtoul: ...\n");
    unsigned long temp = strtoul(nptr, endptr, base);
    return temp;
}

double __baps_strtod(const char *nptr, char **endptr) {
//    printf("call function __baps_strtod: ...\n");
    double temp = strtod(nptr, endptr);
    return temp;
}

long __baps_strtol(const char *nptr, char **endptr, int base) {
//    printf("call function __baps_strtol: ...\n");
    long temp = strtol(nptr, endptr, base);
    return temp;
}


char *__baps_strchr(const char *s, int c) {
//    printf("call function __baps_strchr: ...\n");
    const char *ret_ptr = strchr(s, c);
    baps_propagate_shadow_stack_pointer_metadata(1, 0);
    return (char *) (ret_ptr);
}

char *__baps_strrchr(const char *s, int c) {
//    printf("call function __baps_strrchr: ...\n");
    const char *ret_ptr = strrchr(s, c);
    return (char *) (ret_ptr);
}

char *__baps_stpcpy(char *dest, char *src) {
//    printf("call function __baps_stpcpy: ...\n");
    void *ret_ptr = stpcpy(dest, src);
    return (char *) (ret_ptr);
}

char *__baps_strcpy(char *dest, char *src) {
//    printf("call function __baps_strcpy: ...\n");
    void *ret_ptr = strcpy(dest, src);
    baps_propagate_shadow_stack_pointer_metadata(1, 0);
    return (char *) (ret_ptr);
}

int __baps_rand() {
//    printf("call function __baps_rand: ...\n");
    return rand();
}

int __baps_atoi(const char *ptr) {
//    printf("call function __baps_atoi: ...\n");
    return atoi(ptr);
}

void __baps_puts(char *ptr) {
//    printf("call function __baps_puts: ...\n");
    puts(ptr);
}


void __baps_exit(int status) {
//    printf("call function __baps_exit: ...\n");
    exit(status);
}

char *__baps_strtok(char *str, const char *delim) {
//    printf("call function __baps_strtok: ...\n");
    char *ret_ptr = strtok(str, delim);
    baps_shadow_stack_store_return_metadata(str, 1, 1);
    return ret_ptr;
}

void __baps_strdup_handler(void *ret_ptr) {
//    printf("call function __baps_strdup_handler: ...\n");

}

//strdup, allocates memory from the system using malloc, thus can be freed
char *__baps_strndup(const char *s, size_t n) {
//    printf("call function __baps_strndup: ...\n");
    char *ptr = strndup(s, n);
    if (ptr == NULL) {
        baps_shadow_stack_store_null_return_metadata();
    } else {
        baps_shadow_stack_store_return_metadata(ptr, 1, 1);
    }
    return ptr;
}

//strdup, allocates memory from the system using malloc, thus can be freed
char *__baps_strdup(const char *s) {
//    printf("call function __baps_strdup: ...\n");
    void *ptr = strdup(s);
    if (ptr == NULL) {
        baps_shadow_stack_store_null_return_metadata();
    } else {
        baps_shadow_stack_store_return_metadata(ptr, 1, 1);
    }
    return ptr;
}

char *__baps___strdup(const char *s) {
//    printf("call function __baps___strdup: ...\n");
    void *ret_ptr = strdup(s);
    __baps_strdup_handler(ret_ptr);
    return strdup(s);
}


char *__baps_strcat(char *dest, const char *src) {
//    printf("call function __baps_strcat: ...\n");
    char *ptr = strcat(dest, src);
    baps_propagate_shadow_stack_pointer_metadata(1, 0);
    return ptr;
}

char *__baps_strncat(char *dest, const char *src, size_t n) {
//    printf("call function __baps_strncat: ...\n");
    char *ptr = strncat(dest, src, n);
    baps_propagate_shadow_stack_pointer_metadata(1, 0);
    return ptr;
}

char *__baps_strncpy(char *dest, char *src, size_t n) {
//    printf("call function __baps_strncpy: ...\n");
    char *ptr = strncpy(dest, src, n);
    baps_propagate_shadow_stack_pointer_metadata(1, 0);
    return ptr;
}

char *__baps_strstr(const char *haystack, const char *needle) {
//    printf("call function __baps_strstr: ...\n");
    char *ptr = strstr(haystack, needle);
    if (ptr == NULL) {
        baps_shadow_stack_store_null_return_metadata();
    } else {
        baps_propagate_shadow_stack_pointer_metadata(1, 0);
    }
    return ptr;
}

__sighandler_t __baps_signal(int signum, __sighandler_t handler) {
//    printf("call function __baps_signal: ...\n");
    __sighandler_t ptr = signal(signum, handler);
    baps_shadow_stack_store_return_metadata(ptr, 1, 1);
    return ptr;
}

clock_t __baps_clock(void) {
//    printf("call function __baps_clock: ...\n");
    return clock();
}


long __baps_atol(const char *nptr) {
//    printf("call function __baps_atol: ...\n");
    return atol(nptr);
}

int __baps_putchar(int c) {
//    printf("call function __baps_putchar: ...\n");
    return putchar(c);
}


clock_t __baps_times(struct tms *buf) {
//    printf("call function __baps_times: ...\n");
    return times(buf);
}

size_t __baps_strftime(char *s, size_t max, const char *format, const struct tm *tm) {
//    printf("call function __baps_strftime: ...\n");
    return strftime(s, max, format, tm);
}

time_t __baps_mktime(struct tm *tm) {
//    printf("call function __baps_mktime: ...\n");
    return mktime(tm);
}

long __baps_pathconf(char *path, int name) {
//    printf("call function __baps_pathconf: ...\n");
    return pathconf(path, name);
}

struct tm *__baps_localtime(const time_t *timep) {
//    printf("call function __baps_localtime: ...\n");
    struct tm *ptr = localtime(timep);
    baps_shadow_stack_store_return_metadata(ptr, 1, 1);
    return ptr;
}

time_t __baps_time(time_t *t) {
//    printf("call function __baps_time: ...\n");
    return time(t);
}

double __baps_drand48() {
//    printf("call function __baps_drand48: ...\n");
    return drand48();
}

long int __baps_lrand48() {
//    printf("call function __baps_lrand48: ...\n");
    return lrand48();
}

/**
 * wrappers for Time-related calls
 */

char *__baps_ctime(const time_t *timep) {
//    printf("call function __baps_ctime: ...\n");
    char *ptr = ctime(timep);
    if (ptr == NULL) {
        baps_shadow_stack_store_null_return_metadata();
    } else {
        baps_shadow_stack_store_return_metadata(ptr, strlen(ptr) + 1, 1);
    }
    return ptr;
}

double __baps_difftime(time_t time1, time_t time0) {
//    printf("call function __baps_difftime: ...\n");
    return difftime(time1, time0);
}

int __baps_toupper(int c) {
//    printf("call function __baps_toupper: ...\n");
    return toupper(c);
}

int __baps_tolower(int c) {
//    printf("call function __baps_tolower: ...\n");
    return tolower(c);
}

void __baps_setbuf(FILE *stream, char *buf) {
//    printf("call function __baps_setbuf: ...\n");
    setbuf(stream, buf);
}

char *__baps_getenv(const char *name) {
//    printf("call function __baps_getenv: ...\n");
    char *ptr = getenv(name);
    if (ptr != NULL) {
        baps_shadow_stack_store_return_metadata(ptr, strlen(ptr), 1);
    } else {
        baps_shadow_stack_store_null_return_metadata();
    }
    return ptr;
}

#ifdef _GNU_SOURCE

int __baps_strerror_r(int errnum, char *buf, size_t buf_len) {
//    printf("call function __baps_strerror_r: ...\n");
    return strerror_r(errnum, buf, buf_len);
}

#endif

char *__baps_strerror(int errnum) {
//    printf("call function __baps_strerror: ...\n");
    void *ptr = strerror(errnum);
    baps_shadow_stack_store_return_metadata(ptr, strlen(ptr), 1);
    return ptr;
}

int __baps_unlink(const char *pathname) {
//    printf("call function __baps_unlink: ...\n");
    return unlink(pathname);
}


int __baps_close(int fd) {
//    printf("call function __baps_close: ...\n");
    return close(fd);
}


int __baps_open(const char *pathname, int flags) {
//    printf("call function __baps_open: ...\n");
    return open(pathname, flags);

}

ssize_t __baps_read(int fd, void *buf, size_t count) {
//    printf("call function __baps_read: ...\n");
    return read(fd, buf, count);
}

ssize_t __baps_write(int fd, void *buf, size_t count) {
//    printf("call function __baps_write: ...\n");
    return write(fd, buf, count);
}


off_t __baps_lseek(int fildes, off_t offset, int whence) {
//    printf("call function __baps_lseek: ...\n");
    return lseek(fildes, offset, whence);
}


int __baps_gettimeofday(struct timeval *tv, struct timezone *tz) {
//    printf("call function __baps_gettimeofday: ...\n");
    return gettimeofday(tv, tz);
}


int __baps_select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout) {
//    printf("call function __baps_select: ...\n");
    return select(nfds, readfds, writefds, exceptfds, timeout);
}

#if defined (__linux__)

char *__baps_setlocale(int category, const char *locale) {
//    printf("call function __baps_setlocale: ...\n");
    char *ptr = setlocale(category, locale);
    baps_shadow_stack_store_return_metadata(ptr, strlen(ptr), 1);
    return ptr;

}

char *__baps_textdomain(const char *domainname) {
//    printf("call function __baps_textdomain: ...\n");
    void *ptr = textdomain(domainname);
    baps_shadow_stack_store_return_metadata(ptr, strlen(ptr), 1);
    return ptr;
}


char *__baps_bindtextdomain(const char *domainname, const char *dirname) {
//    printf("call function __baps_bindtextdomain: ...\n");
    void *ptr = bindtextdomain(domainname, dirname);
    baps_shadow_stack_store_return_metadata(ptr, strlen(ptr), 1);
    return ptr;
}

char *__baps_gettext(const char *msgid) {
//    printf("call function __baps_gettext: ...\n");
    void *ptr = gettext(msgid);
    baps_shadow_stack_store_return_metadata(ptr, strlen(ptr), 1);
    return ptr;
}


char *_baps_dcngettext(const char *domainname,
                       const char *msgid, const char *msgid_plural,
                       unsigned long int n, int category) {
//    printf("call function _baps_dcngettext: ...\n");
    void *ptr = dcngettext(domainname, msgid, msgid_plural, n, category);
    baps_shadow_stack_store_return_metadata(ptr, strlen(ptr), 1);
    return ptr;

}


/* IMP: struct hostent may have pointers in the structure being returned,
   we need to store the metadata for all those pointers */

struct hostent *__baps_gethostbyname(const char *name) {
//    printf("call function __baps_gethostbyname: ...\n");
    struct hostent *ptr = gethostbyname(name);
    baps_shadow_stack_store_return_metadata(ptr, sizeof(struct hostent), 1);
    return ptr;
}


char *__baps_dcgettext(const char *domainname,
                       const char *msgid,
                       int category) {
//    printf("call function __baps_dcgettext: ...\n");
    char *ptr = dcgettext(domainname, msgid, category);
    baps_shadow_stack_store_return_metadata(ptr, strlen(ptr), 1);
    return ptr;
}

#endif

#if defined(__linux__)

int *__baps___errno_location() {
//    printf("call function __baps___errno_location: ...\n");
    int *ptr = (int *) __errno_location();
    //  printf("ERRNO: ptr is %lx", ptrs->ptr);
    baps_shadow_stack_store_return_metadata(ptr, sizeof(int *), 1);
    return ptr;
}

unsigned short const **__baps___ctype_b_loc(void) {
//    printf("call function __baps___ctype_b_loc: ...\n");
    unsigned short const **ptr = __ctype_b_loc();
    baps_shadow_stack_store_return_metadata(ptr, 1024 * 1024, 1);
    return ptr;
}

int const **__baps___ctype_toupper_loc(void) {
//    printf("call function __baps___ctype_toupper_loc: ...\n");
    int const **ptr = __ctype_toupper_loc();
    baps_shadow_stack_store_return_metadata(ptr, 1024 * 1024, 1);
    return ptr;
}


int const **__baps___ctype_tolower_loc(void) {
//    printf("call function __baps___ctype_tolower_loc: ...\n");
    int const **ptr = __ctype_tolower_loc();
    baps_shadow_stack_store_return_metadata(ptr, 1024 * 1024, 1);
    return ptr;

}

#endif

#if defined(__linux__)


void __baps__obstack_newchunk(struct obstack *obj, int b) {
//    printf("call function __baps__obstack_newchunk: ...\n");
    _obstack_newchunk(obj, b);
}


int __baps__obstack_begin(struct obstack *obj, int a, int b,
                          void *(foo)(long), void (bar)(void *)) {
//    printf("call function __baps__obstack_begin: ...\n");
    return _obstack_begin(obj, a, b, foo, bar);
}


void __baps_obstack_free(struct obstack *obj, void *object) {
//    printf("call function __baps_obstack_free: ...\n");
    obstack_free(obj, object);
}


char *__baps_nl_langinfo(nl_item item) {
//    printf("call function __baps_nl_langinfo: ...\n");
    char *ptr = nl_langinfo(item);
    baps_shadow_stack_store_return_metadata(ptr, 1024 * 1024, 1);
    return ptr;
}


int __baps_clock_gettime(clockid_t clk_id, struct timespec *tp) {
//    printf("call function __baps_clock_gettime: ...\n");
    return clock_gettime(clk_id, tp);
}

#endif

#if 0

int __baps__obstack_memory_used(struct obstack *h) {
    printf("call function __baps_lrand48: ...\n");
    return _obstack_memory_used(h);
}

#endif
