#include <utils.h>
#include "common.h"
#include "queue.h"
//#include "wiced_utils.h"

int _patch_generateBranchWord(int patch_ptr, int func_ptr, int _, int flag);

int n = 32;
void test() {
    //print_var(rm_getConnFromBdAddress("\xbf\x56\x84\xc7\x95\xf8"));
    while(_tx_thread_execute_ptr == &g_pmu_idle_IdleThread) {
        check_and_handle_timers(312);
        if (_tx_thread_execute_ptr == &g_pmu_idle_IdleThread) {
            if (!n--) {print("Exit\n"); exit(1);}
            //print("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n");
            bcs_tick();
            //print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
        }
    }
}

void test_loop() {
    while(1) {
        check_and_handle_timers(312);
        if (!n--) {print("Exit\n"); exit(1);}
        //print("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\n");
        bcs_tick();
        //print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
        //print_var(_tx_thread_execute_ptr);
        contextswitch();
    }
}


#define sendlmp(conn, x) {char *buff; buff = lm_allocLmpBlock(); memcpy(buff+12,x,19); DHM_LMPTx(conn, buff);}

void dma_Interrupt();
void quad_quadInterrupt();
int dlist_cont(void *dlist);
void BtIntDone();
void _start() {
    patch_code();
    queue_add_hooks();
    taskTimerList = &taskTimerList;
    bcsProfilingData = 0;
    bcs_info();

    trace(uart_ReceiveDMADoneInterrupt,1,false);
    //dmacinttcstat = 0x10;
    dma_Interrupt();
    exit(1);

    /*
    pkt_hdr_status = 0x9b04 | 0x40000;
    pkt_log = 0x17;
    phy_status = 2;
    bluetoothCoreInt_C();
    phy_status = 1;
    bluetoothCoreInt_C();
    //idle = test;
    //cont();
    exit(0);
    */


    print_var(&taskActiveList)
    print_var(taskActiveList)
    print_var(*(uint32_t*)taskActiveList)
    print_var(**(uint32_t**)taskActiveList)
    print_var(&taskReadyList)
    print_var(taskReadyList)
    print_var(*(uint32_t*)taskReadyList)
    print_var(btclk_GetNatClk_slot(0));
    print_var(btclk_GetSysClk_slot(0));

    *(uint32_t*)0 = 0x42424242;
    *(uint32_t*)8 = 0x43434343;

    trace(slist_get, 2, false);
    //idle = test;
    idle_loop = test_loop;
    sendlmp(0x280f20, "\07AAAAAAAAAAA");

    //trace(btclk_GetSysClk_clk, 1, true);
    //trace(btclk_GetSysClk_slot, 1, true);
    hci_rx_fd = -1;
    cont();
    char c;
    //while(1){ bcs_kernelTimerTick(); bcs_info();read(0,&c,1);}


    //exit(1);

    /*
    ber_startBerPerTest("\xf8\x95\xc7\x84\x56\xbf");
    void *acl_conn = rm_getConnFromBdAddress("\xf8\x95\xc7\x84\x56\xbf");
    sendlmp(acl_conn, "abcdefgh");
    //bcs_kernelTimerTick();
    */
    //cont();
    /*
    exit(1);
    */

    /* //uart stuff
    print_var(_tx_thread_execute_ptr);
    print_var(_tx_thread_current_ptr);
    //queue_add_hooks();
    *(int*)(0x360084) = 0x9e;
    *(int*)(0x3600a8) = 4;
    interruptvector_PTU();
    print_var(_tx_thread_system_state);
    print_var(_tx_thread_execute_ptr);
    print_var(_tx_thread_current_ptr);

    cont();
    exit(1);

    print_var(g_pmu_idle_IdleThread.sp);
    *(uint32_t*)(g_pmu_idle_IdleThread.sp+92) = &_start;
    //*(uint32_t*)(g_pmu_idle_IdleThread.sp+92) |= 1;
            
    cont();
    */

    /*
    print_var(btclk_GetSysClk_slot(0x0));
    *(int*) (0x31822c) = *(int*) (0x31822c) + 2;
    *(int*) (0x318088) = *(int*) (0x318088) + 2;
    ////*(int*) (0x318200) = *(int*) (0x318200) + 10;
    print_var(btclk_GetSysClk_slot(0x0));
    //exit(1);
    while(msgqueue_GetNonblock(0x20a2dc));
    */


    //char target[] = "\xbf\x56\x84\xc7\x95\xf8";
    //ber_startBerPerTest(target);
    //memcpy(0x22eed0, target,6);
    //initBerTest();
    //int conn_id = createConnection();
    //DHM_ConnectionUp(conn_id);
    //int conn = rm_getConnFromBdAddress(target);
    //print_var(conn);
    //sendlmp(conn, "\x4a\x42\x0f\x00\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42");
    //print_var(taskTimerList);

    bcs_isrEnableProfiling = 0;
    //*(uint32_t*) 0x31822c = 0x204b; //seems to ble clock
    //*(uint32_t*) 0x32a004 = 0xfff6288e;
    //*(uint32_t*) 0x318084 = 0xcf;
    *(uint32_t*) 0x31400c = 0x1d8;
    *(uint32_t*) 0x314004 = 1;
    bluetoothCoreInt_C();
    *(uint32_t*) 0x314004 = 2;
    bluetoothCoreInt_C();
    *(uint32_t*) 0x314004 = 4;
    bluetoothCoreInt_C();


    //print_var(dlist_count(taskTimerList));
    //print_var(dlist_count(taskTransientStateList));
    //print_var(dlist_count(taskActiveList));
    //print_var(dlist_count(taskReadyList));
    exit(1);

    //bcs_kernelTimerTick();
    //exit(1);

    while(1) {
        bcs_kernelTimerTick();
        *(int*) (0x31822c) += 10;
        *(int*) (0x318088) += 10;
        *(int*) (0x318200) += 10;
        //print_var(taskTimerList);
        //print_var(dlist_count(taskTimerList));
    }
    exit(1);


    while(1) {
        char pkt[32];
        if (read(0, (void *)0x370c00,0xfc) == 0)
            break;
        bcs_isrRxDoneInt();
        //*(int*) (0x370c00) += 100;
        //bcs_kernelTimerTick();
        //lculp_bcsulpRxPkt(0x2828b0, 0xcc3, 0x370c00, 0x40);
        //_advTaskRxDone(0x2828b0, 0xcc3, 0x370c00, 0x40);
        //BtIntDone();
    }

    //cont();
   
    /*
    int t[2];
    *(int*) (0x31822c) += 1;
    btclk_GetSysClk_clkpclk(1,t);
    btclk_GetSysClk_clkpclk(1,t);
    print_var(t[0]);
    print_var(t[1]);
    */

    //    bcs_isrRxDoneInt(0xe000e000);

    exit(1);
    diag_sendLmpPktFlag = 0;


    //cont();

    struct queue_entry *queue_entry;


    struct timer_arg {
        void *ptr;
        void *ptr2;
        int i;
        int i2;
        void *mpaf_exec_timer_arg;
        int i3;
        int i4;
        int i5;
        int i6;
        void *mpaf_exec_timer_callback;
        char unknwn[];
    } *timer_arg;
    do {
        queue_entry = msgqueue_GetNonblock((void *)0x20a2dc);
        print_var(queue_entry);
        print_var(queue_entry->next);
        print_var(queue_entry->maybe_flags);
        print_var(queue_entry->sometimes_callback);
        print_var(queue_entry->callback_arg);
        //hexdump(queue_entry->unknwn, 0x20);

        //mpaf_execute_timer_cback
        if (queue_entry->sometimes_callback == (void *)0x0a1141) {
            //b *0x0a1140
            //1. calls 0x0020ff7c (r0=0x211424)
            //2. calls 0x000a11f8 (r0=0x20fd90)
            //3. calls 0x0020ffac (r0=0x211360)
            print("======================\n");
            timer_arg = queue_entry->callback_arg;
            print_var(timer_arg);
            print_var(timer_arg->ptr);
            print_var(timer_arg->ptr2);
            print_var(timer_arg->i);
            print_var(timer_arg->i2);
            print_var(timer_arg->ptr2);
            print_var( *(int*)(((int)timer_arg) + 0x10)); //callback_arg
            print_var( *(int*)(((int)timer_arg) + 0x24)); //callback
            print_var(timer_arg->i3);
            print_var(timer_arg->i4);
            print_var(timer_arg->i5);
            print_var(timer_arg->i6);
            print_var(timer_arg->mpaf_exec_timer_callback);

            hexdump(timer_arg->unknwn, 0x20);
            print("======================\n");

        }
    } while (queue_entry);

    void *buff; 
    while (buff = msgqueue_GetNonblock((void *)0x20ab1c)) {
        hexdump(buff, 19);

    }

    //exit(1);

    //NVRAM
    //patch_jump(0x0006e9ee, 0xdeadbeef); //siffy_write_then_read
    //patch_jump(0x00020914, 0xdeadbeef); //sfi_read_status
    //patch_jump(0x000209c6, 0xdeadbeef); //sfi_set_protect_level
    //patch_jump(0x16c5e, 0xdeadbeef); //mpaf_cfacCnfigVSWrite
    //patch_jump(0x5d010, 0xdeadbeef); //write_nvram_utility
    //patch_jump(0x210499, 0xdeadbeef); //write_nvram_utility

    //bthci_send messaage something
    //1ad19 (0x215f18) sub_...
    //0001acf8 (0x215f18)                   bthci_lm_thread_sendMessage
    //a151c (0x2, 0x24da5c                  mpaf_btu_acl_to_lower
    //44dd4( 0x24ab98                       l2c_link_send_to_lower
    //44edc (0x24ab98                       l2_link_check_send_pckt
    //a1f86 (0x6, 0x207861, 0x24da5c        L2CA_SendFixedChnlData
    //691b8 (0x207861, 0x24da5c             smp_send_msg_to_L2CAP
    //691ec(2, 0x207844, 4, f)              smp_send_cmd
    //5be14(0x207844, 0, 4, f)              smp_send_pair_rsp
    //5c862(0x207844, 0, 0x5c863, 0x137028) smp_proc_io_rsp
    //afb5c(0x207844, 14, 0)                smp_sm_event
    //5bb8a(????????????)                   smp_send_app_cback   


    //print_var(_patch_generateBranchWord(0x1230, 0x1234, 0x1234, 1));



    exit(0);
}
