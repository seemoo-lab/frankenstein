int page_fd = 0;

int page_idx = 0;


/*
    Accept any connection attempt
*/
void page() {
    //if (acl_fd == 0 || acl_fd == -1) acl_fd = tcp_connect(127,0,0,1,31338);

    switch(page_idx) {
        case 0:
            if ( (pcx_btclk & 3) != 0b10) page_idx = page_idx - 1 % 4;

        case 1:
            pkt_hdr_status = 0x04e98d;
            pkt_log = 0x2404e878;
            phy_status = 1;
            sr_status = 0xcb3a;
            break;
        case 2:
            pkt_hdr_status = 0x0438f2;
            pkt_log = 0x24040225;
            phy_status = 0x1;
            sr_status = 0xc99a;
            break;
        case 3:
            pkt_hdr_status = 0x04e0b5;
            pkt_log = 0x2404303e;
            phy_status = 5;
            sr_status = 0x227f;

            acl_role = ACL_ROLE_MASTER;
            break;
    }
    page_idx = page_idx + 1 % 4;

    bluetoothCoreInt_C();
    contextswitch();

    return;
}

void pagescan() {
    //bcs_info();
    if (page_fd == -1) return;
    //if (acl_fd == 0 || acl_fd == -1) acl_fd = tcp_connect(127,0,0,1,31337);
    acl_role = ACL_ROLE_SLAVE;

    read(page_fd, (void*)0x370000, 16);
    read(page_fd, &sr_status, 2);
    read(page_fd, &phy_status, 2);
    read(page_fd, &pkt_hdr_status, 2);
    read(page_fd, &pkt_log, 2);
    pkt_hdr_status |= 0x40000;
    pkt_log |= 0x40000;

    print_var(pkt_hdr_status);
    print_var(pkt_log);
    print_var(phy_status);
    print_var(sr_status);
    bluetoothCoreInt_C();
    contextswitch();

    return;
}

