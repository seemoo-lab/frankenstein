#include <frankenstein/BCMBT/patching/patchram.h>
#include <frankenstein/BCMBT/patching/hciio.h>
#include <frankenstein/hook.h>


void bcs_dmaTxEnable();
void _aclTaskFsmSetup();
int rand();
void srand(int);

extern int tx_pkt_info;
extern int tx_pkt_pyld_hdr;
int seed;

#define set_pkt_type(type) ((((type) & 0xf)<<3) | ((~(0xf<<3)) & tx_pkt_info))

void fuzz_acl(struct saved_regs *regs, void *arg) {
    int len = (*(int *)(regs->r0 + 0x0a)>>3) & 0x3ff;
    char *data = (char *)(*(int *)(regs->r0 + 0x10) & 0xfffffffc);
    if (len < 30) return;

    srand(seed++);

    tx_pkt_info ^= 1<<(rand()%16);
    tx_pkt_info ^= 1<<(rand()%16);

    tx_pkt_pyld_hdr ^= 1<<(rand()%16);
    tx_pkt_pyld_hdr ^= 1<<(rand()%16);

    data[rand()%len] ^= 1<<(rand()%8);
    data[rand()%len] ^= 1<<(rand()%8);
    data[rand()%len] ^= 1<<(rand()%8);
    data[rand()%len] ^= 1<<(rand()%8);
}

int _start() {
    seed = 0x0;
    print("Hello\n");
    add_hook(bcs_dmaTxEnable, fuzz_acl, NULL, NULL);
}

void _fini() {
    print("Goodbye cruel world\n");
    for (int i=0; i < installed_hooks; i++) {
        uninstall_hook(&hooks[i]);
    }
}
