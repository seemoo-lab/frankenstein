
//This falg can bes set to extract LMP messages over HCI
extern int diag_sendLmpPktFlag;

//file descriptor for ACL messages
int acl_fd = 0;

#define ACL_ROLE_MASTER 0
#define ACL_ROLE_SLAVE 1

int acl_role = ACL_ROLE_SLAVE;
//the snapshot I've taken had an open acl slave connection

int injected = 0;

void acl() {
    if (acl_fd == -1) return;

    if (( acl_role == ACL_ROLE_SLAVE && (pcx_btclk & 3) == 0b10 ) || 
        ( acl_role == ACL_ROLE_MASTER && (pcx_btclk & 3) == 0b00 ) ){


        print("Tx Done\n");
        sr_status =  0x1d8;
        phy_status = 0x4;
        bluetoothCoreInt_C();
        contextswitch();

        print("TxDone: ");
        print_ptr(tx_pkt_info & 0xffff);
        print(" | ");
        print_ptr(tx_pkt_pyld_hdr & 0xffff);
        print(" | ");
        print_var(tx_dma_data);
        hexdump(tx_dma_data, tx_dma_len);
        hexdump(0x370400, 32);
        print("\n");

        int pyld_hdr = tx_pkt_pyld_hdr << 2;
        write(acl_fd, &tx_pkt_info, 2);
        write(acl_fd, &pyld_hdr, 2);
        write(acl_fd, tx_dma_data, 512);
        print_var((tx_pkt_pyld_hdr >> 2) & 0x3ff)
    }

    //Rx Hdr Int
    if (( acl_role == ACL_ROLE_SLAVE && (pcx_btclk & 3) == 0b00 ) || 
        ( acl_role == ACL_ROLE_MASTER && (pcx_btclk & 3) == 0b10 ) ){
        print("Rx Hdr Done\n");
        sr_status =  0x1c8;
        phy_status = 0x3;

        pkt_hdr_status = pkt_log = 0;
        if ( read(acl_fd, &pkt_hdr_status, 2) == 0) exit(1);
        read(acl_fd, &pkt_log, 2);
        pkt_hdr_status |= 0x40000;
        pkt_log |= 0x40000;

        //if (rtx_dma_ctl == 1) {
        //    sr_status =  0x1d8;
        //    phy_status = 0x2;

        //    ////Acknowledge Packet ACL Specific?
        //    ////print_var(wait_for_ack)
        //    //if (wait_for_ack) {
        //    //    wait_for_ack = 0;

        //    //    pkt_hdr_status = tx_pkt_info | 0x40000;
        //    //    pkt_hdr_status |= 0x1 << 8; //ARQN
        //    //    pkt_hdr_status ^= 0x1 << 9; //SEQ

        //    //    pkt_log = tx_pkt_pyld_hdr;
        //    //    pkt_log = pkt_log << 2;
        //    //    if (tx_pkt_pyld_hdr == 0x11a && (pcx_btclk & 0xff) == 0)
        //    //        pkt_log = pkt_log | 0x40000;
        //    //}
        //    ////ACL Inject packet
        //    //else if(!injected) {
        //    //    pkt_hdr_status =  0x40000;
        //    //    pkt_hdr_status |= 0x0; //LT_ADDR
        //    //    pkt_hdr_status |= 0x3 << 3; //Type
        //    //    pkt_hdr_status |= 0x1 << 7; //Flow
        //    //    pkt_hdr_status |= 0x1 << 8; //ARQN
        //    //    pkt_hdr_status |= 0x1 << 9; //SEQ
        //    //    pkt_hdr_status |= 0xf00; //HEC
        //    //    pkt_log = 0x1f << 2 | 0x40000; //payload_hdr
        //    //    injected = 1;
        //    //} else {
        //    //    injected --;
        //    //}
        //}


        print_var(pkt_hdr_status);
        print_var(pkt_log);
        bluetoothCoreInt_C();
        contextswitch();
    }

    //Rx Interrupt
    //if(rtx_dma_ctl == 1 && (pcx_btclk & 3) == 0b01) {
    int len;
    //if((pcx_btclk & 3) == 0b01) {
    if (( acl_role == ACL_ROLE_SLAVE && (pcx_btclk & 3) == 0b01 ) || 
        ( acl_role == ACL_ROLE_MASTER && (pcx_btclk & 3) == 0b11 ) ){
        print("Rx Done\n");
        sr_status =  0x1c8;
        phy_status = 0x1;

        //len = (pkt_log >> 5) & 0x1f;
        len = (pkt_log >> 5) & 0x3ff;
        len = 32;
        print_var(len);

        if (rtx_dma_ctl != 3 && dmaActiveRxBuffer) {
            if (read(acl_fd, dmaActiveRxBuffer+4, len) < 1) exit(1);
            print_var(dmaActiveRxBuffer);
            //for (unsigned char i=0; i < 240; i++) dmaActiveRxBuffer[i] = i; 
            print("pcktdata (DMA): ");
            hexdump(dmaActiveRxBuffer, len);
            print("\n");
        }
        else {
            print("pcktdata: ");
            read(acl_fd, (void *)0x370000, len);
            hexdump(0x370000, len);
            print("\n");
        }

        bluetoothCoreInt_C();
        contextswitch();
    }
}

/*
void acl_over_tcp() {
    if (acl_fd == -1) return;

    if (( acl_role == ACL_ROLE_SLAVE && (pcx_btclk & 3) == 0b10 ) || 
        ( acl_role == ACL_ROLE_MASTER && (pcx_btclk & 3) == 0b00 ) ){

        print("Tx Done\n");
        sr_status =  0x1d8;
        phy_status = 0x4;
        bluetoothCoreInt_C();
        contextswitch();

        print("TxDone: ");
        hexdump(&tx_pkt_info, 4);
        print(" | ");
        hexdump(&tx_pkt_pyld_hdr, 2);
        print("\n");
    }

    //Rx Hdr Int
    if (( acl_role == ACL_ROLE_SLAVE && (pcx_btclk & 3) == 0b00 ) || 
        ( acl_role == ACL_ROLE_MASTER && (pcx_btclk & 3) == 0b10 ) ){
        print("Rx Hdr Done\n");
        sr_status =  0x1c8;
        phy_status = 0x3;

        if ( read(acl_fd, &pkt_hdr_status, 2) == 0) exit(1);
        read(acl_fd, &pkt_log, 2);
        pkt_hdr_status |= 0x40000;
        pkt_log |= 0x40000;

        if (rtx_dma_ctl == 1) {
            sr_status =  0x1d8;
            phy_status = 0x2;

        }

        print_var(pkt_hdr_status);
        print_var(pkt_log);
        bluetoothCoreInt_C();
        contextswitch();
    }

    //Rx Interrupt
    //if(rtx_dma_ctl == 1 && (pcx_btclk & 3) == 0b01) {
    int len;
    //if((pcx_btclk & 3) == 0b01) {
    if (( acl_role == ACL_ROLE_SLAVE && (pcx_btclk & 3) == 0b01 ) || 
        ( acl_role == ACL_ROLE_MASTER && (pcx_btclk & 3) == 0b11 ) ){
        print("Rx Done\n");
        sr_status =  0x1c8;
        phy_status = 0x1;

        //len = (pkt_log >> 5) & 0x1f;
        len = (pkt_log >> 5) & 0x3ff;
        len = 128;

        if (rtx_dma_ctl != 3 && dmaActiveRxBuffer) {
            if (read(0, dmaActiveRxBuffer, len) < 1) exit(1);
            print_var(dmaActiveRxBuffer);
            //for (unsigned char i=0; i < 240; i++) dmaActiveRxBuffer[i] = i; 
            print("pcktdata: ");
            hexdump(dmaActiveRxBuffer, len);
            print("\n");
        }
        else {
            print("pcktdata: ");
            read(0, 0x370000, len);
            hexdump(0x370000, len);
            print("\n");
        }

        bluetoothCoreInt_C();
        contextswitch();
    }
}
*/
