#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#ifndef FRANKENSTEIN_UTILS_H
#define FRANKENSTEIN_UTILS_H

//Lib GCC import to support software division
#include "lgcc.h"



char hex_chars[] = "0123456789abcdef";
void _print_ptr(size_t p) {
    char prefix[] = "0x";
    char not_skip_prefix = 0;

    write(2, prefix, 2);
    for (int i=sizeof(size_t)-1; i>=0; i--) {
        if (not_skip_prefix = not_skip_prefix | ((p>>(i*8)&0xff))) {
            write(2, &hex_chars[(p>>(i*8+4))&0xf], 1);
            write(2, &hex_chars[(p>>(i*8))&0xf], 1);
        }
    }
    if (!not_skip_prefix) write(2, &hex_chars[0], 1);
}

int itoa(unsigned int n, char *str) {
    unsigned int dec,i;
    for (dec=1; n/(dec*10) > 0; dec *= 10);

    for (i=0; dec > 0; dec /=10, i++) {
        str[i] = '0' + n/dec;
        while (n >= dec) n -= dec;//n -= (n / dec) * dec;
    }
}


//common stuff
size_t strlen(const char *c) {
    for (int i=0; ; i++)
        if (!c[i]) return i;
}
void *memcpy(void *dest, const void *src, size_t n) {
    for (int i=0; i < n; i++) ((char *)dest)[i] = ((char *)src)[i];
    return dest;

}
void *memset(void *s, int c, size_t n) {
    for (int i=0; i < n; i++) ((char *)s)[i] = c;
    return s;
}

void _hexdump(char *c, size_t len) {
    for (int i=0; i<len; i++) {
        write(2, &hex_chars[(c[i]>>4)&0xf], 1);
        write(2, &hex_chars[c[i]&0xf], 1);
    }
}

int _puts(const char *x) {
    write(2, (x), strlen(x));
}

#include <sys/time.h>
void set_timeout(int us) {
    if (us < 0) us = 100;
    struct itmr {
        int interval_sec;
        int interval_usec;
        int value_sec;
        int value_usec;
    } timer;
    timer.value_sec = us/1000000;
    timer.value_usec = (us%1000000);
    timer.interval_sec = 0;
    timer.interval_usec = 0;
    setitimer (ITIMER_REAL, (void *)&timer, NULL);
}

#include <signal.h>
#define SA_RESTORER 0x04000000
# define SA_RESTART   0x10000000
//The original sigaction struct has _sa_mask after sa_handler
//as this has changed with rt_sigaction, here is the redefinition
struct rt_sigaction {
    void * _sa_handler;
    unsigned long sa_flags;
    void * sa_restorer;
    unsigned long _sa_mask;
};

void register_signal(int sig, void *sighandler, void *restorer) {
    struct rt_sigaction action;
    memset(&action, 0, sizeof(action));
    action._sa_handler = sighandler;
    action._sa_mask |= 1<<(sig-1);
    action.sa_flags = SA_RESTART;
    if (restorer) action.sa_flags |= SA_RESTORER;
    action.sa_restorer = restorer;
    sigaction(sig, (struct sigaction *) &action, NULL);
}


//Syscalls
#include "syscalls.h"

//exports from firmware
extern void cont();
extern struct saved_regs *saved_regs;


/*
ptmx
*/


#include <sys/stat.h>
#include <fcntl.h>
#include <asm-generic/ioctl.h>
#include <asm-generic/ioctls.h>


int ptmx_open() {
    int zero=0;
    int ptmx = open("/dev/ptmx", O_RDWR);
    ioctl(ptmx, TIOCSPTLCK, &zero);
    
    return ptmx;
}

char *ptmx_name(int ptmx) {
    static char name[32] = "/dev/pts/";
    int ptn;
    ioctl(ptmx, TIOCGPTN, &ptn);
    _print_ptr(ptn);
    itoa(ptn, name+9);

    return name;
}

char *ptmx_btattach(int ptmx) {
    char *pts_name = ptmx_name(ptmx);
    char *params[] = {"/usr/bin/btattach", "-B", pts_name, NULL};
    if (fork() == 0) {
        execve("/usr/bin/btattach", params, NULL);
    }

    return NULL;
}

/*
TCP connect
*/
#include <netinet/tcp.h>
#define IPaddr(a,b,c,d) (((a&0xff)<<0)|((b&0xff)<<8)|((c&0xff)<<16)|((d&0xff)<<24)) 
#define htons(s) (((s>>8)&0xff) | ((s<<8)&0xff00))
int tcp_connect(unsigned char a, unsigned char b, unsigned char c, unsigned char d, unsigned short port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0x00, sizeof(struct sockaddr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = IPaddr(a,b,c,d);
    int ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr));
    if (ret != 0) exit(1);

    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (int[]){1}, sizeof(int));

    return sockfd;
}


void _print_ptr(size_t p);
void _hexdump(char *c, size_t len);
int _puts(const char *x);

#define DEBUG
#ifdef DEBUG
    #define print_ptr(x) _print_ptr((size_t)x)
    #define print(x) puts(x);
    int puts(const char *s) { write(2, (s), strlen(s));}
    #define print_var(x) {print(#x" = "); print_ptr(x); print("\n");}
    #define fatal(x) {print(x); *((int *)0xbeefbeef) = 42;}
    #define hexdump(c,n) _hexdump((char *)c,n)
    #define print_caller() {int lr; asm("mov %0, lr": "=r" (lr)); print_ptr(lr);}
#else
    int puts(const char *s) {}
    #define print_ptr(x) {}
    #define print(x) {}
    #define print_var(x) {}
    #define fatal(x) {}
    #define hexdump(c,n) {}
    #define print_caller() {}
#endif

#endif
