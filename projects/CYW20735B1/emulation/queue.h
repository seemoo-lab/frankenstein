#include <frankenstein/hook.h>

struct queue_access {
    void *thread;
    uint32_t queue;
    uint32_t lr;
};


struct queue_access queue_read[1024];
int queue_read_n = 0;
void queue_read_access(struct saved_regs *regs, void *arg) {
    for (int i = 0; i < queue_read_n; i++)
        if (    queue_read[i].thread == _tx_thread_current_ptr &&
                queue_read[i].queue == regs->r0 &&
                queue_read[i].lr == regs->lr ) return;

    //add access
    queue_read[queue_read_n].thread = _tx_thread_current_ptr;
    queue_read[queue_read_n].queue = regs->r0;
    queue_read[queue_read_n].lr = regs->lr;
    queue_read_n ++;

    //dump
    print("queue read thread=");
    print_ptr(_tx_thread_current_ptr);
    print(" queue=");
    print_ptr(regs->r0);
    print(" lr=");
    print_ptr(regs->lr);
    print("\n");
}

struct queue_access queue_write[1024];
int queue_write_n = 0;
void queue_write_access(struct saved_regs *regs, void *arg) {
    for (int i = 0; i < queue_write_n; i++)
        if (    queue_write[i].thread == _tx_thread_current_ptr &&
                queue_write[i].queue == regs->r0 &&
                queue_write[i].lr == regs->lr ) return;

    //add access
    queue_write[queue_write_n].thread = _tx_thread_current_ptr;
    queue_write[queue_write_n].queue = regs->r0;
    queue_write[queue_write_n].lr = regs->lr;
    queue_write_n ++;

    //dump
    print("queue write thread=");
    print_ptr(_tx_thread_current_ptr);
    print(" queue=");
    print_ptr(regs->r0);
    print(" lr=");
    print_ptr(regs->lr);
    print("\n");
}

struct queue_access slist_read[1024];
int slist_read_n = 0;
void slist_read_access(struct saved_regs *regs, void *arg) {
    for (int i = 0; i < slist_read_n; i++)
        if (    slist_read[i].thread == _tx_thread_current_ptr &&
                slist_read[i].queue == regs->r0 &&
                slist_read[i].lr == regs->lr ) return;

    //add access
    slist_read[slist_read_n].thread = _tx_thread_current_ptr;
    slist_read[slist_read_n].queue = regs->r0;
    slist_read[slist_read_n].lr = regs->lr;
    slist_read_n ++;

    //dump
    print("slist read thread=");
    print_ptr(_tx_thread_current_ptr);
    print(" slist=");
    print_ptr(regs->r0);
    print(" lr=");
    print_ptr(regs->lr);
    print("\n");
}

struct queue_access slist_write[1024];
int slist_write_n = 0;
void slist_write_access(struct saved_regs *regs, void *arg) {
    for (int i = 0; i < slist_write_n; i++)
        if (    slist_write[i].thread == _tx_thread_current_ptr &&
                slist_write[i].queue == regs->r1 &&
                slist_write[i].lr == regs->lr ) return;

    //add access
    slist_write[slist_write_n].thread = _tx_thread_current_ptr;
    slist_write[slist_write_n].queue = regs->r1;
    slist_write[slist_write_n].lr = regs->lr;
    slist_write_n ++;

    //dump
    print("slist write thread=");
    print_ptr(_tx_thread_current_ptr);
    print(" slist=");
    print_ptr(regs->r1);
    print(" lr=");
    print_ptr(regs->lr);
    print("\n");
}

void queue_add_hooks() {
    trace(msgqueue_Put, 2, false);
    trace(msgqueue_PutInFront, 2, false);
    trace(msgqueue_Get, 1, true);
    trace(msgqueue_GetNonblock, 1, true);

    add_hook(msgqueue_Get, &queue_read_access, NULL, NULL);
    add_hook(msgqueue_PrivateGet, &queue_read_access, NULL, NULL);
    add_hook(msgqueue_GetNonblock, &queue_read_access, NULL, NULL);
    add_hook(msgqueue_PrivateGet, queue_read_access, NULL, NULL);


    add_hook(msgqueue_Put, &queue_write_access, NULL, NULL);
    add_hook(msgqueue_PutInFront, &queue_write_access, NULL, NULL);

    add_hook(osapi_sendQueueItem, &queue_read_access, NULL, NULL);
    add_hook(osapi_getQueueItem, &queue_write_access, NULL, NULL);
    add_hook(osapi_sendQueueItemToFront, &queue_write_access, NULL, NULL);

    add_hook(osapi_getQueueItem_tx, &queue_read_access, NULL, NULL);
    add_hook(osapi_sendQueueItem_tx, &queue_write_access, NULL, NULL);
    add_hook(osapi_sendQueueItemToFront_tx, &queue_write_access, NULL, NULL);

    add_hook(_tx_queue_receive, &queue_read_access, NULL, NULL);
    add_hook(_tx_queue_send, &queue_write_access, NULL, NULL);
    add_hook(_tx_queue_front_send, &queue_write_access, NULL, NULL);


    //add_hook(slist_get, &slist_read_access, NULL, NULL);  //Too short + misaligned
    //add_hook(slist_tail, &slist_read_access, NULL, NULL); // Function too short
    add_hook(slist_front, &slist_read_access, NULL, NULL);

    add_hook(slist_add_after, &slist_write_access, NULL, NULL);
    add_hook(slist_add_front, &slist_write_access, NULL, NULL);
    add_hook(slist_add_tail, &slist_write_access, NULL, NULL);
    add_hook(slist_add_before, &slist_write_access, NULL, NULL);
}
