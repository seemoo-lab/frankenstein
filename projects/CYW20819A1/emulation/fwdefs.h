/*
   This file defines commonly used functions and variables that are provided by the
   firmware and used within our patches.
*/
#ifndef FWDEFS_H
#define FWDEFS_H


#ifdef EMULATED
    typedef uint16_t wiced_result_t;
#endif

/*
NVRAM
*/
uint16_t wiced_hal_read_nvram( uint16_t vs_id, uint16_t data_length, uint8_t* p_data, wiced_result_t * p_status);
uint16_t wiced_hal_write_nvram( uint16_t vs_id, uint16_t data_length,  uint8_t* p_data, wiced_result_t * p_status);
void wiced_hal_delete_nvram( uint16_t vs_id, wiced_result_t * p_status);

void _send_acl_segment(int s, char *buff, int len);

/*
Queue
*/

void *msgqueue_GetNonblock(void *queue);
void *msgqueue_Get(void *queue);
//called by msgqueue_Get after queue event
void *msgqueue_PrivateGet(void *queue, int x);

void msgqueue_Put(void *queue, void *item);
void msgqueue_PutInFront(void *queue, void *item);

void *osapi_getQueueItem(void *queue);
void osapi_sendQueueItem(void *queue, void *item);
void osapi_sendQueueItemToFront(void *queue, void *item);

void *osapi_getQueueItem_tx(void *queue);
void osapi_sendQueueItem_tx(void *queue);
void osapi_sendQueueItemToFront_tx(void *queue, void *item);

void *_tx_queue_receive(void *tx_queue, void *item);
void _tx_queue_send(void *tx_queue, void *item);
void _tx_queue_front_send(void *tx_queue, void *item);
void _tx_event_flags_set(void *event_group, int a, int b);
void _tx_thread_system_resume(void *);
void _tx_thread_context_restore();

/*
slist
*/
void *slist_get(void *slist);
void *slist_tail(void *slist);
void *slist_front(void *slist);

void *slist_del_front(void *slist);
void *slist_del(void *slist); //XXX item?

void slist_add_after( void* slist, void *item);
void slist_add_front( void* slist, void *item);
void slist_add_tail( void* slist, void *item);
void slist_add_before( void* slist, void *item);


/*
Utils
*/
int rand();
int rbg_rand(int);

/*
Uart
*/
extern int sr_ptu_status_adr4;

void puart_write(char c);
void *btuartcommon_SendHCICommandBackToTransportThread(int);
//For some reason, this always send 0x19 before any hci packet
void uart_SendSynchHeaderBeforeAsynch(void *some_struct, char *data, int len, int x);
// thrd=0x249e58 lr=0x019265 uart_SendAsynch(0x249f70, 0x249e00, 0x01, 0x2117c8)
void uart_SendAsynch(void *uart_struct, char *data, int len, int x);
void uart_SendSynch(void *uart_struct, char *data, int len);
void btuarth4_getpti();
void uart_SetAndCheckReceiveAFF();
void uart_SetAndCheckTransmitAEF();
void btuarth4_InitiateTransmit_help();
void bttransport_SendMsgToThread();
void btu_hcif_hardware_error_evt();
void uart_RunTransmitStateMachine(void*);
void btuarth4_RunTxStateMachines(int, int, int, int);

void bthci_lm_thread_SendMessageToThread(void *msg);
void bthci_event_SendConnectionRequestEvent();

/*
Interrupt Vectors
*/
void interruptvector_PTU(); //uart
void interruptvector_DMA_DONE();
void interruptvector_WAKEUP();
void interruptvector_TIMER1_DONE();
void interruptvector_TIMER2_DONE();


extern int g_ptu_ISR;
extern int g_uart_DriverState;
void *uart_ReceiveSynch();
void *uart_ReceiveAsynch();
void *uart_ReceiveAsynchTerminate();
void btuarth4_getpti();
void btuarth4_RunRxStateMachines();
void btuarth4_HandleRXFullMsgDone();
void uart_RunReceiveStateMachine();
void uart_SetupForRXDMA(void *);
void bttransport_Main(void *driver_state);

void dma_StartTransfer();
void dma_RequestTransfer(int);

int mpaf_hci_EventFilter(void *);
extern int mpaf_flags;
extern int mpaf_suppress_hci_rx_to_host;
void mpaf_thread_PostMsgToHandler(void *, void *);


void *uart_TransmitDMADoneInterrupt();
void *uart_ReceiveDMADoneInterrupt();
void *uart_DirectWrite();
void *uart_DirectRead();

/*
    Hardware
*/
extern int pkt_hdr_status; //Rx
extern int pkt_log;

extern int tx_pkt_info;
extern int tx_pkt_pyld_hdr; //maybe acl header, length + 3 bits


extern int pc_acscd_lo; //Piconet Access Code
extern int pc_acscd_hi;

extern int dc_fhout;
extern int dc_ind_d_ptr;

/*
Exception
*/
void wdog_generate_hw_reset();
void dbfw_assert_fatal();

/*
Os
*/

struct thread_dvdn {
    uint32_t magic;
    uint32_t x1;
    uint32_t sp;
};

extern struct thread_dvdn g_pmu_idle_IdleThread;

extern int g_bthci_lm_thread_Thread;

void _tx_thread_system_suspend();
void _tx_thread_system_return(void);
void _tx_thread_suspend(void);
int osapi_waitEvent(void *dvdn, int mask, int x);
void interrupt_DisableInterrupts();
void interrupt_EnableInterrupts();

/*
Timer
*/
struct osapi_timer {
    void *next;
    void *callback;
    int maybe_type;
    int i2;
    void *mpaf_exec_timer_arg;
    int i3;
    uint32_t time_offset_low;
    uint32_t time_offset_high;
    int i6;
    int i7;
    char unknwn[];
};

void osapi_activateTimer(void *timer, uint32_t time_us);
void osapi_getTimerRemain(void *timer);
void *g_pmu_private_IdleMsgQueue;
void mpaf_osapi_timerCb(void *timer);
uint32_t clock_SystemTimeMicroseconds32();
uint32_t clock_SystemTimeMicroseconds64();
uint32_t clock_SystemTimeMicroseconds32_nolock();
uint32_t clock_SystemTimeMicroseconds64_nolock();
void clock_serviceTimers();
void clock_ResetTimer2();

extern struct osapi_timer *lm_osTimer;
uint32_t timer1value; //current system time

/*
Connection
*/
int createConnection();
void lm_HandleLmpBBAck();
void lm_HandleLmpReceivedPdu(int *i);
void lm_HandleLmpHostConnReqNotAccepted();
void lm_HandleLmpHostConnReqAccepted();
void *ber_startBerPerTest(char *);
void *rm_getConnFromBdAddress(char *);
void rm_setLocalBdAddr(char *);

/*
LM
*/

extern int lm_curCmd;
extern int lm_curCmdPayload; //XXX custom symbol

void lm_sendCmd(void *event);
void lm_sendCmdWithId(void *event);
void lm_handleCmd();
void lm_handleHciResetWithAclLinks();
int rm_getBBConnectedACLUsage();
void lm_LmpBBAcked(void *); //called if sent packet is acked

/*
bpl
*/
void bpl_lcu_Cmd(int, int);
void bpl_lcu_setPHY(int, int, int, int);
int lb;

/*
LMP
*/
extern int diag_sendLmpPktFlag;
void *rm_getACLConnPtr(int i);
void *rm_getDHMAclPtr(int i);
void *rm_allocateACLConnPtr(int i);
void *rm_allocateLTCH(int i);
void lm_LmpReceived(void *acl_conn, void *lmp_msg);
int DHM_LMPTx(int id, void *buff);
int DHM_TxDataAvail();
void DHM_releaseTxLmpList(int, int, int, int);
void *DHM_GetBasebandTxData(int, int);
void *DHM_GetBasebandRxBuffer(int, int);
void *DHM_BasebandRx(int, int, int);
void DHM_ACLAckRcvd(int);
void DHM_SetAclTxPktAckRcvd(int);
int DHM_isTxLmpListEmpty(void *adhm_acl);
void *DHM_getFrontTxLmp(void *adhm_acl);
void _dhmSlotCbFunc(void *x);

/*
ACL Task
*/
void _aclTaskSetupTxBuffer();
void _aclTaskLcuCmd();
void _aclTaskRxHeaderDone();
void _aclTaskRxDone();
void _aclTaskTxDone();
void _aclTaskFsmSetup();
void _aclTaskQosSlotIntCB();
void _aclTaskProcessRxPacket();
void _aclTaskSwitch();

/*
Inquiry
*/
void _inqTaskRxHeaderDone(int);
void _inqTaskRxDone(int);
void eir_handleTx(int);
void eir_handleRx(int);
void bcs_inqScanPauseNonBlock();
void bcs_inqScanPause();
void _inqTaskFsmDone(int, int);
void _inqTaskFsmSetup(int, int);
void eir_eirInqFHS(int);
void lm_sendInqFHS(int);
void lm_handleInqFHS(int);
void eir_getReceivedEIR(int, int);
void bthci_event_SendInquiryResultEvent(int);
void lc_handleInqResult(int);
void bcs_utilExtractFhsInfo(int);
void inqfilter_isBdAddrRegistered(int, int);
void inqfilter_registerBdAddr(int, int);
extern int eir_fhs;

/*
Page
*/
void _pageTaskFsmDone();
void _pageScanTaskFsmDone();
void bcs_newConnTaskCreate();
void bcs_pageScanTaskCreate();

/*
LE
*/
void _advTaskRxDone();
void _scanTaskRxDone();
void bcsulp_passRxPktUp();
void bcsulp_procRxPayload(int, int);
void bcsulp_progTxBuffer(int);
void bcsulp_getPktLength(int, int);
void bcsulp_fillTxBuffer(int dst, int src, int len);
void bcsulp_setupRxBuffer();
void bcsulp_returnRxBuffer(void);
void *mmulp_allocACLUp(int );
void *mmulp_allocACLDown(int );
int mmulp_freeLEABuffer(void *);
void *dhmulp_getRxBuffer(int);
void dhmulp_returnRxBuffer(void *);
void _connTaskLcuCmd_addin();
void _connTaskLcuCmd();
void _connTaskSlotInt();
void _connTaskRxDone();
void _connTaskRxHeaderDone();

/*
LCP
*/
extern void diag_logLcpPkt(int, int);


/*
clk
*/
int btclk_GetSysClk_slot(void *);
int btclk_GetSysClk_clk(void *);
int btclk_AdvanceNatClk_clkpclkHWWA(void *);
int btclk_AdvanceSysClk_clkpclkHWWA(void *, void *);

/*
bcs
*/
extern int bcsProfilingData;
extern int pcx_btclk;
extern int dc_nbtc_clk; //ca 1 unit pre 312us
extern int dc_x_clk; //ca 1 unit pre 312us
extern uint32_t *tb; //current task
extern int taskTimerList;
extern int slotCbEntryList;
extern int btProgIntStatus;
extern int taskTransientStateList;
extern int taskActiveList;
extern int taskReadyList;
extern void *taskEventGroup;
extern int phy_status;
extern int sr_status;
extern int sr_status_shadow;
extern int phy_status_shadow;
extern char rm_deviceInfo[];
extern char rm_deviceLocalName[];
void bcs_isrSlot11Int();
void bcs_isrSlot01Int();
void bcs_utilBbRxPktHdrCheck(int, int);
void bcs_dmaRxEnableEir(int, int);
void bcs_dmaTxEnableEir(int, int);
void bcs_dmaRxEnable(int, int);
void bcs_dmaTxEnable(int, int);
void *bcs_dmaRxDisable(int, int);
void bcs_dmaBlockEnable();
void bcs_dmaIsTransferComplete();
void *bcs_dmaGetRxBuffer();
void bcs_dmaRxBufferRecycle(void *);
void _dmaReqSend();
void bcs_SlotCbFunctions();
extern int dmacinttcclr;
extern int rtx_dma_ctl;
extern int dmacinttcstat;
extern int g_dma_ActiveChannels;

int bcs_taskGetTaskType(int);
void bcs_aclTaskCreate();
extern int bcs_isrEnableProfiling;
void BtIntDone();
extern int bcsDataToCrunch;
void pmu_idle_Main();
void *pmu_idle_MsgHandlersPoll();
void dbfw_proc_in_idle();
void bluetoothCoreInt_C();

void *bcs_isrRxDoneInt();
void *bcs_isrTxDoneInt();
void *bcs_timeline_CrunchData();
void *bcs_isrRxHeaderDoneInt();
void  bcs_isrFsmDoneInt();

void bcs_kernelSlotCbFunctions();
void bcs_kernelRxDone();
void bcs_kernelRxHeaderDone();
void bcs_kernelTimerTick();
void bcs_kernelBlock();
void bcs_kernelFsmSetup();
void bcs_kernelBtProgIntEnable();
void bcs_kernelBtProgIntIsEnabled();

void bcs_taskUnblock(int);
void bcs_SlotCbFunctions();
void *bcs_dmaGetRxBuffer();
int btclk_DelayXus(int us);
void bcs_utilBbRxPyldHdr();

void btclk_Wait4PclkChange(int, int);
void intctl_ClrPendingInt();
void *dhmulp_getTxBuffer();
void dhmulp_LcpTx();

void bluerf_Wr(void *addr, int val);
int bluerf_Rd(void *addr);

void eir_handleTx(int);
void _afhPipelineRssiScanTaskSlotInt();

/*
paging
*/
void bcs_pageTaskCreate();
void lc_pageStart(int);

extern int dc_n_pg;
extern int dc_pg_to;
extern int dc_pg_respto;


/*
HCI
*/
void bthci_processingHCIReset();
void bthci_processingHCIResetFlag();
void bthci_lm_thread_Reset();
void bthci_acl_Reset();
void bthci_event_AttemptToEnqueueEventToTransport();
void bthci_event_SendCommandCompleteEventWithStatus();
void bthci_cmd_lc_HandleCreate_Connection();
void bthci_cmd_lc_HandleDisconnect(char *);


/*
Callbacks
*/
extern int pageScanTaskStorage;
extern int inqScanTaskStorage;
extern int inqTaskStorage;
extern int g_tca_taskVars;
extern int afhRssiScanTaskStorage;
extern int pageTaskStorage;
extern int bcsulp_advTaskStorage;
extern int bcsulp_scanTaskStorage;
extern int bcsulp_initTaskStorage;



void bt_Reset();



#endif
