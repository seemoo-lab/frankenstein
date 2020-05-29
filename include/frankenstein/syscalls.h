#ifndef FRANKENSTEIN_SYSCALLS_H
#define FRANKENSTEIN_SYSCALLS_H

void __attribute__((naked)) exit(int code)
{asm("push {lr}; swi #0x900001; pop {pc}\n");}

pid_t __attribute__((naked)) fork()
{asm("push {lr}; swi #0x900002; pop {pc}\n");}

ssize_t __attribute__((naked))read(int fildes, void *buf, size_t nbyte)
{asm("push {lr}; swi #0x900003; pop {pc}\n");}

ssize_t __attribute__((naked))write(int fildes, const void *buf, size_t nbyte)
{asm("push {lr}; swi #0x900004; pop {pc}\n");}

int __attribute__((naked))open(const char *path, int oflag, ... )
{asm("push {lr}; swi #0x900005; pop {pc}\n");}

int __attribute__((naked))close(int fildes)
{asm("push {lr}; swi #0x900006; pop {pc}\n");}

int __attribute__((naked))execve(const char *path, char *const argv[], char *const envp[])
{asm("push {lr}; swi #0x90000b; pop {pc}\n");}

unsigned __attribute__((naked))alarm(unsigned seconds)
{asm("push {lr}; swi #0x90001b; pop {pc}\n");}

#include <sys/time.h>
int  __attribute__((naked))setitimer(int which, const struct itimerval *restrict value,
struct itimerval *restrict ovalue)
{asm("push {lr}; swi #0x900068; pop {pc}\n");}

#include <sys/ioctl.h>
int  __attribute__((naked))ioctl(int fildes, unsigned long int request, ... /* arg */)
{asm("push {lr}; swi #0x900036; pop {pc}\n");}

int __attribute__((naked))dup2(int fildes, int fildes2)
{asm("push {lr}; swi #0x90003f; pop {pc}\n");}

int __attribute__((naked))sigaction(int sig, const struct sigaction *restrict act,
struct sigaction *restrict oact)
{asm("push {lr}; swi #0x900043; pop {pc}\n");}

#include <poll.h>
//int __attribute__((naked))poll(struct pollfd fds[], nfds_t nfds, int timeout)
int __attribute__((naked))poll(struct pollfd fds[], nfds_t nfds, int timeout)
{asm("poll: push {lr}; swi #0x9000a8; pop {pc}\n");}

#include <sys/socket.h>
#include <netinet/in.h> 
int __attribute__((naked))socket(int domain, int type, int protocol)
{asm("push {lr}; swi #0x900119; pop {pc}\n");}

int __attribute__((naked))setsockopt(int socket, int level, int option_name,
const void *option_value, socklen_t option_len)
{asm("push {lr}; swi #0x900126; pop {pc}\n");}

int __attribute__((naked))connect(int socket, const struct sockaddr *address,
socklen_t address_len)
{asm("push {lr}; swi #0x90011b; pop {pc}\n");}


#include <sys/mman.h>
struct mmap_arg_struct {
    void *addr;
    uint32_t len;
    uint32_t prot;
    uint32_t flags;
    uint32_t fd;
    uint32_t offset;
};
void *mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off) {
    struct mmap_arg_struct arg;
    void *ret;
    arg.addr = addr;
    arg.len = len;
    arg.prot = prot;
    arg.flags = flags;
    arg.fd = fildes;
    arg.offset = off;
    asm("mov r0, %0; swi #0x90005a;mov %0, r0\n":"=r" (ret): "r" (&arg));

    return ret;
}

#endif
