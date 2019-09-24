#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <unistd.h>
#include <asm-generic/ioctl.h>
#include <asm-generic/ioctls.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stropts.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <linux/tty.h>

/*
btattach wrapper
*/
int btattach(const char *path) {
    int btfd = open(path, O_RDWR|O_NOCTTY);
    //tcflush(btfd, TCIOFLUSH);

    struct termios ti;
    int ldisc = 15;//N_HCI;
    ioctl(btfd, TIOCSETD, &ldisc);
    perror("ioctl");

    ioctl(btfd, _IOC(_IOC_WRITE, 0x55, 0xcb, 0x4), 0x2);
    perror("ioctl");
    ioctl(btfd, _IOC(_IOC_WRITE, 0x55, 0xc8, 0x4), 0);
    perror("ioctl");
    int devid;
    ioctl(btfd, _IOC(_IOC_READ, 0x55, 0xca, 0x4), &devid);
    perror("ioctl");

    printf("devid = %d\n", devid);
}

/*
Gets the pseudo terminal name and calls btattach on it
*/
int btattach_ptmx(int ptmx) {
    char path[128];
    ptsname_r(ptmx, path, 128);
    printf("%s\n", path);
    return btattach(path);
}


/*
Opens a new pseudo terminal device
*/
int open_ptmx() {
    int ptmx = open("/dev/ptmx", O_RDWR);
    //printf("ptmx = %d\n", ptmx);

    int ptn;
    ioctl(ptmx, TIOCGPTN, &ptn);
    //printf("ptn = %d\n", ptn);

    //grantpt(ptmx);
    //perror("grantpt");
    //unlockpt(ptmx);
    //perror("unlockpt");
    int zero=0;
    ioctl(ptmx, TIOCSPTLCK, &zero);

    return ptmx;

}

