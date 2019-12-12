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
    int len = (*(int *)(regs->r0 + 10)>>3) & 0x3ff;
    if (len < 30) return;

    srand(seed++);

    tx_pkt_info ^= 1<<(rand()%32);
    tx_pkt_info ^= 1<<(rand()%32);
    //tx_pkt_info ^= 1<<(3+(rand()%4));
    //tx_pkt_info ^= 1<<(3+(rand()%4));



    tx_pkt_pyld_hdr ^= 1<<(rand()%32);
    tx_pkt_pyld_hdr ^= 1<<(rand()%32);
    //tx_pkt_pyld_hdr ^= 1<<(0+(rand()%8));
    //tx_pkt_pyld_hdr ^= 1<<(0+(rand()%8));
    //tx_pkt_pyld_hdr ^= 1<<(rand()%32);

    //tx_pkt_pyld_hdr ^= 1<<(5+(rand()%13));
}

int _start() {
    seed = 0x2dad-256; //0x2dad
    print("Hello\n");
    add_hook(bcs_dmaTxEnable, fuzz_acl, NULL, NULL);
}

void _fini() {
    print("Goodbye cruel world\n");
    for (int i=0; i < installed_hooks; i++) {
        uninstall_hook(&hooks[i]);
    }
}
