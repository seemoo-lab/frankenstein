#include <frankenstein/BCMBT/patching/patchram.h>
#include <frankenstein/BCMBT/patching/hciio.h>
#include <frankenstein/hook.h>


void bcs_dmaTxEnableEir();
void _aclTaskFsmSetup();
int rbg_rand();
int rand();
void srand(int);

extern int dc_bta_lo;
extern int tx_pkt_info;
extern int tx_pkt_pyld_hdr;
int seed;

#define set_pkt_type(type) ((((type) & 0xf)<<3) | ((~(0xf<<3)) & tx_pkt_info))

void eir_flood(struct saved_regs *regs, void *arg) {
    srand(seed++);
    dc_bta_lo = rand(); //Randomize BT address

    char *eir = (char *)regs->r0;
    //for (int i=0; i<0xf0; i++ ) eir[i] = rand() & 0xff;
    //eir[0] = 5;

    //tx_pkt_info ^= 1<<(rand()%16);
    //tx_pkt_info ^= 1<<(rand()%16);

    //tx_pkt_pyld_hdr ^= 1<<(rand()%16);
    //tx_pkt_pyld_hdr ^= 1<<(rand()%16);
}

uint32_t ret0( uint32_t _, void *arg) { return 0;}

int _start() {
    seed = 0;
    print("Hello\n");
    add_hook(bcs_dmaTxEnableEir, eir_flood, NULL, NULL);
    add_hook(rbg_rand, NULL, ret0, NULL);
}

void _fini() {
    print("Goodbye cruel world\n");
    for (int i=0; i < installed_hooks; i++) {
        uninstall_hook(&hooks[i]);
    }
}
