int le_fd = 0;

int wib_rx_status;
int wib_pkt_log;

void adv() {
    if (le_fd == -1) return;

    if ((pcx_btclk & 3) == 0b10){
        print("Tx Done\n");
        sr_status =  0x1d8;
        phy_status = 0x4;
        bluetoothCoreInt_C();
        contextswitch();

        /*
        print("TxDone: ");
        hexdump(&tx_pkt_info, 4);
        print(" | ");
        hexdump(&tx_pkt_pyld_hdr, 2);
        print("\n");
        */
    }

    //Rx Hdr Int
    if ((pcx_btclk & 3) == 0b00){
        print("Rx Hdr Done\n");
        sr_status =  0x1c8;
        phy_status = 0x3;

        read(le_fd, &wib_rx_status, 4);
        read(le_fd, &wib_pkt_log, 4);

        bluetoothCoreInt_C();
        contextswitch();
    }

    //Rx Interrupt
    if((pcx_btclk & 3) == 0b01) {
        print("Rx Done\n");
        sr_status =  0x1c8;
        phy_status = 0x1;

        read(le_fd, (void *)0x370c00, 32);


        bluetoothCoreInt_C();
        contextswitch();
    }
}

void le_scan() {
    if ((pcx_btclk & 3) == 0b10){
        print("Tx Done\n");
        sr_status =  0x1d8;
        phy_status = 0x4;
        bluetoothCoreInt_C();
        contextswitch();
    }

    //Rx Hdr Int
    if ((pcx_btclk & 3) == 0b00){
        print("Rx Hdr Done\n");
        sr_status =  0x1c8;
        phy_status = 0x3;

        read(le_fd, &wib_rx_status, 4);
        read(le_fd, &wib_pkt_log, 4);

        bluetoothCoreInt_C();
        contextswitch();
    }

    //Rx Interrupt
    if((pcx_btclk & 3) == 0b01) {
        print("Rx Done\n");
        sr_status =  0x1c8;
        phy_status = 0x1;

        print_var(wib_rx_status)
        print_var(wib_pkt_log)
        read(le_fd, (void *)0x370c00, 256);

        bluetoothCoreInt_C();
        contextswitch();
    }
}

//#include <xmit_state_emu.h>
void le_conn() {
    //xmit_state_emu("gen/xmited_le");
    //hci_rx_fd = -1;
    //hci_tx_fd = -1;

    if ((pcx_btclk & 3) == 0b10){
        print("Tx Done\n");
        sr_status =  0x1d8;
        phy_status = 0x4;
        bluetoothCoreInt_C();
        contextswitch();
    }

    //Rx Hdr Int
    if ((pcx_btclk & 3) == 0b00){
        print("Rx Hdr Done\n");
        sr_status =  0x1c8;
        phy_status = 0x3;

        wib_rx_status = 0;
        read(le_fd, &wib_rx_status, 4);
        read(le_fd, &wib_pkt_log, 4);

        //LE heap BoF fix
        //wib_rx_status &= 0xffff;
        //if (wib_rx_status >= 0xfc00) wib_rx_status = 0xfc00 | (wib_rx_status & 0xff);
        //wib_rx_status |= wib_rx_status << 16;

        bluetoothCoreInt_C();
        contextswitch();
    }

    //Rx Interrupt
    if((pcx_btclk & 3) == 0b01) {
        print("Rx Done\n");
        sr_status =  0x1c8;
        phy_status = 0x1;

        print_var(wib_rx_status)
        print_var(wib_pkt_log)
        read(le_fd, (void *)0x370c00, 256);
        //for (int i=0; i < 0x100; i++) ((char *)0x370c00)[i] = (char)(i&0xff);

        bluetoothCoreInt_C();
        contextswitch();
    }
}
