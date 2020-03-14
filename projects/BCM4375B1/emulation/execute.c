#include <frankenstein/utils.h>

#include <frankenstein/BCMBT/dynamic_memory.h>
#include <frankenstein/BCMBT/hci.h>
#include <frankenstein/threadx/threading.h>


void get_int();
void set_int();


void _tx_v7m_set_int(uint32_t);
uint32_t _tx_v7m_get_int();
void dbfw_assert_alert(int, int);

void some_fatal_error();


int _start() {
    hci_rx_fd = 0;
    hci_tx_fd = 1;

    patch_return(get_int)
    patch_return(set_int)
    patch_return(0x1779b2)
    patch_return(0x750)

    patch_return(_tx_v7m_set_int);
    patch_return(_tx_v7m_get_int);
    patch_jump(_tx_thread_system_return, _tx_thread_system_return_hook);

    jump_trace(dbfw_assert_alert, exit, 2, false);
    jump_trace(some_fatal_error, exit, 2, false);

    jump_trace(uart_DirectWrite, uart_DirectWrite_hook, 2, false);

    cont();
    exit(1);
}
