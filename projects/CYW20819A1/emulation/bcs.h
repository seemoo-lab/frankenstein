#ifndef BCS_H
#define BCS_H

#include <frankenstein/threadx/threading.h>

#define HW_PHY_STATUS_RX_DONE 0x0001
#define HW_PHY_STATUS_RX_HEADER_DONE 0x0002
#define HW_PHY_STATUS_TX_DONE 0x0004
#define HW_PHY_STATUS_PROG_INT0 0x0008 //Slot11 + Timer + bcs_kernel
#define HW_PHY_STATUS_PROG_INT1 0x0010 //Slot01
#define HW_PHY_STATUS_PROG_INT2 0x0020
#define HW_PHY_STATUS_PROG_INT3 0x0040
#define HW_PHY_STATUS_WCS_COEX_INT 0x0100
#define HW_PHY_STATUS_WCS_COEX_DEFERRED 0x0200
#define HW_PHY_STATUS_PROG_INT_ALL 0x0078


extern char* dmaActiveRxBuffer;
char *tx_dma_data;
int tx_dma_len;


int wait_for_ack = 1;
void bcs_dma_hook(struct saved_regs *regs, void *arg) {
    int data, len;
    if ((int)arg & 2) {
        print("Eir ");
        data = regs->r0;
        len = regs->r1;
    }
    else {
        data = *(uint32_t *)(regs->r0 + 16);
        len = (*(uint32_t *)(regs->r0 + 10) >> 3 & 0x3ff);
    }
    if ((int)arg & 1) print ("Tx: ")
    else { 
        /*
        print("Rx: ");
        print_ptr(data);
        print(" | ");
        print_ptr(len);
        print("\n");
        */
        return;
    }

    /*
    hexdump(&pc_acscd_lo, 4);
    hexdump(&pc_acscd_hi, 4);
    print(" | ");
    */
    hexdump(&tx_pkt_info, 4);
    print(" | ");
    hexdump(&tx_pkt_pyld_hdr, 2);
    print(" | ");
    hexdump(data, len);
    print("\n");
    tx_dma_len = len;
    tx_dma_data = data;

    wait_for_ack = 1;

    /*
    Rx Test
    */
}

#ifdef EMULATED
void clear_phy_status(struct saved_regs *regs, void *arg) {
    int intmask = regs->r0;
    if (intmask & 0x7800) phy_status &= ~((intmask>>8) & 0x78);
    if (intmask & 0x400000) phy_status &= ~HW_PHY_STATUS_RX_HEADER_DONE;
    if (intmask & 0x400) phy_status &= ~HW_PHY_STATUS_RX_DONE;
    if (intmask & 1) phy_status &= ~HW_PHY_STATUS_TX_DONE;
    if (intmask & 0xe) sr_status &= ~((intmask>>1) & 0x7);
}

#endif

void print_bcs_list_entry(uint32_t *current) {
        print("-----------------------------------\n");
        print_var(current);
        print_var(current[-1]);
        print_var(current[0]); //next
        print_var(current[1]); //prev
        print_var(current[2]);
        print_var(current[3]);
        print_var(current[4]);
        print_var(current[5]); //end of struct?
        print_var(((char*)current)[0x10]);
        print_var(((char*)current)[0x11]);
}

extern int eci_status;
extern int eci_status_b;
void bcs_info() {
    uint32_t *current;
    if (tb) {
        print_var(tb);
        print_var(bcs_taskGetTaskType(tb));
    }

    //print_var(eci_status);
    //print_var(eci_status_b);
    //print_var(rtx_dma_ctl);
    print_var(dlist_count(taskTimerList));
    print_var(dlist_count(taskTransientStateList));
    print_var(dlist_count(taskReadyList));
    print_var(dlist_count(taskActiveList));
    print_var(dlist_count(slotCbEntryList));

    print("-----------------------------------\n");
    print("current_task\n");
    print_bcs_list_entry(tb);

    print("-----------------------------------\n");
    print("active_list\n");
    for (current = (uint32_t*) taskActiveList; current != &taskActiveList; current = current[0])
        print_bcs_list_entry(current);

    print("-----------------------------------\n");
    print("taskTransientStateList\n");
    for (current = (uint32_t*) taskTransientStateList; current != &taskTransientStateList; current = current[0])
        print_bcs_list_entry(current);

    print("-----------------------------------\n");
    print("taskReadyList\n");
    for (current = (uint32_t*) taskReadyList; current != &taskReadyList; current = current[0])
        print_bcs_list_entry(current);


    print("-----------------------------------\n");
    print("timer\n")
    current = (uint32_t*) taskTimerList;
    while (current != &taskTimerList) {
        print("-----------------------------------\n");
        print_var(current);
        print_var(current[-2]);
        print_var(current[-1]);
        print_var(current[0]); //next
        print_var(current[1]); //prev
        print_var(current[2]);
        print_var(current[3]);
        print_var(current[4]);
        print_var(current[5]);
        print_var(current[6]);
        print_var(current[7]);
        print_var(current[8]);
        print_var(current[9]); //maybe callback
        print_var(current[10]);
        print_var(current[11]);
        print_var(current[12]);
        print_var(current[13]);

        current = current[0];

    }

    print("-----------------------------------\n");
    print("slotcb\n")
    current = (uint32_t*) slotCbEntryList;
    while (current != &slotCbEntryList) {
        print("-----------------------------------\n");
        print_var(current);
        print_var(current[-1]);
        print_var(current[0]);
        print_var(current[1]);
        print_var(current[2]);
        print_var(current[3]);
        print_var(current[4]);
        print_var(current[5]);
        print_var(current[6]);
        current = current[0];
    }

}

/*
Advance bt clock by one tick (312.5 us)
*/

extern int pcx2_pbtclk;
extern int pcx2_btclk;
extern int dc_nbtc_pclk;

void bcs_advance_clock() {
    pcx_btclk ++; //*(int*) (0x31822c) += 1;
    pcx2_pbtclk ++;
    pcx2_btclk ++;
    dc_nbtc_clk ++; //*(int*) (0x318088) += 1;
    dc_x_clk ++;
    //dc_nbtc_pclk ++;
}



/*
Dummy task performing random actions
*/
void bcs_dummy() {
    read(0, 0x370000, 16);
    read(0, &sr_status, 2);
    read(0, &phy_status, 2);
    read(0, &pkt_hdr_status, 2);
    read(0, &pkt_log, 2);
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

#include "bcs/inq.h"
#include "bcs/acl.h"
#include "bcs/page.h"
#include "bcs/le.h"
void bcs_tick() {
    /*
    srstatus
        1 = fsmdone
        0x10 = lcuSubstate Active
            
    */

    bcs_advance_clock();

    //bcs_info();
    if (tb == pageScanTaskStorage)
        { print("tb = pageScan\n"); pagescan(); }
    //else if (tb == pageTaskStorage)
    //    {print("tb = page\n");  page(); }
    else if (tb == inqScanTaskStorage)
        print("tb = inqScan\n")
    //else if (tb == inqTaskStorage)
    else if (tb == pageTaskStorage)
        { print("tb = inq\n"); inquiry(); }
    else if (tb == g_tca_taskVars)
        { print("tb = tca\n"); bcs_dummy(); }
    else if (tb == 0x281068) //TODO
        { print("tb = acl\n"); acl(); }
    else if (tb == 0x22539c) //TODO
        { print("tb = conntask?\n"); bcs_dummy(); }
    else if (tb == afhRssiScanTaskStorage)
        { print("tb = afhRssiScan\n");}

    //LE
    else if (tb == bcsulp_advTaskStorage)
        { print("tb = adv\n"); adv();}
    else if (tb == bcsulp_scanTaskStorage)
        { print("tb = bcsulp_scan\n"); le_scan();}
    else if (tb == bcsulp_initTaskStorage)
        { print("tb = bcsulp_init\n"); le_scan();}//page_fd = 0; pagescan(); page_fd=-1;}
    else if (tb == 0x281618) //TODO
        { print("tb = le_conn\n"); le_conn();}
    else
        print_var(tb);


    //Slot01 / Slot11
    if ((pcx_btclk & 3) == 0b01){
        print("Slot01\n");
        sr_status =  (tb == 0x281068) ? 0x1d8 : 0x1c8; //TODO is that in ram?
        phy_status = 0x10;
        bluetoothCoreInt_C();
        contextswitch();
    }
    if ((pcx_btclk & 3) == 0b11){
        print("Slot11\n");
        sr_status =  (tb == 0x281068) ? 0x1d8 : 0x1c8;
        phy_status = 0x68;
        bluetoothCoreInt_C();
        contextswitch();
    }
    return;
}

void _dhmulp_getTxLcp();


void bcs_add_hooks() {
    #ifdef EMULATED
    add_hook(intctl_ClrPendingInt, clear_phy_status, NULL, NULL);
    #endif

    patch_return(btclk_DelayXus);
    patch_return(btclk_DelayXus+0x18); //label within that function that seems to get called, same offset in CYW20735 and CYW20819
    patch_return(btclk_AdvanceNatClk_clkpclkHWWA);
    patch_return(btclk_AdvanceNatClk_clkpclkHWWA+0x2e); //similar relative label
    patch_return(btclk_AdvanceSysClk_clkpclkHWWA);
    patch_return(btclk_AdvanceSysClk_clkpclkHWWA+0x3a);
    patch_return(_afhPipelineRssiScanTaskSlotInt);
    //patch_return(&_afhPipelineRssiScanTaskSlotInt);

    trace(bcs_dmaGetRxBuffer, 3, false);
    trace(bcs_dmaRxEnableEir, 2, false);
    trace(bcs_dmaTxEnableEir, 2, false);
    trace(bcs_dmaRxEnable, 2, true);
    trace(bcs_dmaTxEnable, 1, false);
    trace(bcs_dmaRxDisable, 0, true);
    trace(bcs_dmaGetRxBuffer, 1, true);
    trace(bcs_utilBbRxPyldHdr, 2, true);
    trace(bcs_dmaRxBufferRecycle, 1, false);
    trace(btclk_AdvanceNatClk_clkpclkHWWA, 1, false);

    trace(bcs_kernelTimerTick, 0, false); //called at 0x95693 0x40637
    trace(bcs_kernelRxHeaderDone, 0, false);
    trace(bcs_kernelRxDone, 0, false);
    trace(bcs_kernelSlotCbFunctions, 0, false);

    //Called quite often, therefore disabled
    //trace(bcs_isrFsmDoneInt, 0, false);
    //trace(bcs_isrSlot01Int, 0, false);
    //trace(bcs_isrSlot11Int, 0, false);
    //trace(bcs_isrTxDoneInt, 0, false);
    //trace(bcs_isrRxDoneInt, 0, false);
    //trace(bcs_isrRxHeaderDoneInt, 0, false);


    trace(bcs_pageTaskCreate, 3, false);
    trace(dhmulp_LcpTx, 3, false);
    trace(DHM_TxDataAvail,0,false);
    trace(dhmulp_getTxBuffer, 3, false);
    trace(DHM_GetBasebandTxData, 2, false);
    trace(bcs_utilBbRxPktHdrCheck, 2, false);
    trace(DHM_ACLAckRcvd, 1, false);
    trace(DHM_SetAclTxPktAckRcvd, 1, false);
    trace(DHM_isTxLmpListEmpty, 1, true);
    trace(DHM_GetBasebandRxBuffer, 2, false);
    trace(DHM_releaseTxLmpList, 4, false);
    trace(_dhmSlotCbFunc, 1, false);

    //acl
    trace(bcs_aclTaskCreate, 2, false);
    trace(_aclTaskSetupTxBuffer, 4, false);
    trace(_aclTaskRxHeaderDone, 1, false);
    trace(_aclTaskRxDone, 1, false);
    trace(_aclTaskLcuCmd, 1, false);
    trace(_aclTaskFsmSetup, 1, false);
    trace(_aclTaskProcessRxPacket, 1, false);
    trace(_aclTaskSwitch, 1, false);

    //eir
    trace(eir_handleRx, 1, false);
    trace(eir_handleTx, 1, false);

    trace(_inqTaskRxHeaderDone, 1, false);
    trace(_inqTaskRxDone, 1, false);

    trace(_dmaReqSend, 1, false);
    trace(dma_RequestTransfer, 1, false);

    add_hook(bcs_dmaRxEnable, bcs_dma_hook, NULL, 0);
    add_hook(bcs_dmaTxEnable, bcs_dma_hook, NULL, 1);
    add_hook(bcs_dmaRxEnableEir, bcs_dma_hook, NULL, 2);
    add_hook(bcs_dmaTxEnableEir, bcs_dma_hook, NULL, 3);
    trace(bcs_dmaIsTransferComplete, 2, false);

    trace(_pageTaskFsmDone, 3, false);
    trace(_pageScanTaskFsmDone, 3, false);
    trace(bcs_newConnTaskCreate, 3, false);

    //Methods are actually too short to set hooks
    //trace(bluerf_Wr, 2, false);
    //trace(bluerf_Rd, 1, true);
    trace(bpl_lcu_Cmd, 2, false);
    trace(bpl_lcu_setPHY, 4, false);
    trace(bcs_kernelBtProgIntEnable, 4, false);
    trace(bcs_kernelBtProgIntIsEnabled, 4, false);

    trace(bcs_pageTaskCreate, 3, false);
    trace(bcs_pageScanTaskCreate, 3, false);
    trace(bcs_SlotCbFunctions, 0, false);

    //LE
    trace(_advTaskRxDone, 3, false);
    trace(_scanTaskRxDone, 3, false);
    trace(bcsulp_passRxPktUp, 3, false);
    trace(bcsulp_procRxPayload, 2, false);
    trace(bcsulp_getPktLength, 2, true);
    trace(bcsulp_setupRxBuffer, 0, true);
    trace(bcsulp_returnRxBuffer, 0, false);
    trace(mmulp_allocACLUp, 1, true);
    trace(mmulp_allocACLDown, 1, true);
    trace(dhmulp_getRxBuffer, 1, true);
    //trace(_connTaskLcuCmd_addin, 3, true); //Does no longer exist in CYW20819A1
    trace(_connTaskLcuCmd, 3, true);
    trace(_connTaskSlotInt, 3, true);
    trace(mmulp_freeLEABuffer, 1, true);
    trace(dhmulp_returnRxBuffer, 1, false);
    trace(_dhmulp_getTxLcp, 2, true);

    //Inquiry
    trace(eir_eirInqFHS, 1, false);
    trace(eir_getReceivedEIR, 1, false);
    trace(bthci_event_SendInquiryResultEvent, 1, false);
    trace(lm_sendInqFHS, 1, false);
    trace(lm_handleInqFHS, 1, false);
    trace(lc_handleInqResult, 1, false);
    trace(inqfilter_isBdAddrRegistered, 2, false);
    trace(inqfilter_registerBdAddr, 2, false);

}
#endif
