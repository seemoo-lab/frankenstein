int inq_fd = 0;

int timeout = 10;
void inquiry() {
    if (inq_fd == -1) return;

    //hci_tx_fd = -1;
    //hci_rx_fd = -1;
    //xmit_state_emu("gen/inq.exe");
    //if (timeout-- < 0) exit(0);

    
    if ((pcx_btclk & 3) == 0b10){
        print("Tx Done\n");
        sr_status =  0x1d8;
        phy_status = 0x4;
        bluetoothCoreInt_C();
        contextswitch();
    }

    if ((pcx_btclk & 3) == 0b00){
        print("Rx Hdr Done\n");
        sr_status =  0x1c8;
        phy_status = 0x3;

        read(inq_fd, &pkt_hdr_status, 2);
        read(inq_fd, &pkt_log, 2);
        pkt_hdr_status |= 0x40000;
        pkt_log |= 0x40000;

        //Eir inject test FHS
        /*
        if (pcx_btclk & 0x8 == 0) {
            sr_status =  0x1d8;
            phy_status = 0x2;

            pkt_hdr_status =  0x40000;
            pkt_hdr_status |= 0x0; //LT_ADDR
            pkt_hdr_status |= 0x2 << 3; //Type
            pkt_hdr_status |= 0x1 << 7; //Flow
            pkt_hdr_status |= 0x1 << 8; //ARQN
            pkt_hdr_status |= 0x1 << 9; //SEQ
            pkt_hdr_status |= 0xf00; //HEC
            pkt_log = 0xd336 | 0x40000; //payload_hdr
        }
        //Eir inject Eir
        if (pcx_btclk & 0x8) {
            sr_status =  0x1d8;
            phy_status = 0x2;

            pkt_hdr_status =  0x40000;
            pkt_hdr_status |= 0x0; //LT_ADDR
            pkt_hdr_status |= 0xa << 3; //Type
            pkt_hdr_status |= 0x1 << 7; //Flow
            pkt_hdr_status |= 0x1 << 8; //ARQN
            pkt_hdr_status |= 0x1 << 9; //SEQ
            pkt_hdr_status |= 0xf00; //HEC
            pkt_log = 0xf5c2 | 0x40000; //payload_hdr
        }
        /**/

        print_var(pkt_hdr_status);
        print_var(pkt_log);
        bluetoothCoreInt_C();
        contextswitch();
    }

    //Rx Interrupt
    if((pcx_btclk & 3) == 0b01) {
        print("Rx Done\n");
        sr_status =  0x1c8;
        phy_status = 0x1;

        if (rtx_dma_ctl != 3 && dmaActiveRxBuffer) {
            if (read(inq_fd, dmaActiveRxBuffer, 240) < 1) exit(1);
            print_var(dmaActiveRxBuffer);
            for (unsigned char i=0; i < 240; i++) dmaActiveRxBuffer[i] = i; 
            print("pcktdata: ");
            hexdump(dmaActiveRxBuffer, 240);
            print("\n");
        }
        else {
            print("pcktdata: ");
            read(inq_fd, (void *)0x370000, 16);
            hexdump(0x370000, 16);
            print("\n");
            //char fhs[] = "\x70\x21\xc9\x74\xaf\x83\xc0\x6c\xff\x5a\x48\x8d\x5a";
            //memcpy(0x370000, fhs, sizeof(fhs));
            //read(inq_fd, 0x370000 + 9, 2); //some bt addr part
            //read(inq_fd, 0x370000 + sizeof(fhs), 240);
            //hexdump(0x370000, 240);
        }

        bluetoothCoreInt_C();
        contextswitch();
    }

}
