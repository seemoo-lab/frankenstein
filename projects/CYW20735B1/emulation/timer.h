#ifndef TIMER_H
#define TIMER_H
#include "bcs.h"

//dump osapi timers
void show_timers() {
    return;
    struct osapi_timer *timer = lm_osTimer;
    print("-------------------------\n");
    while (timer) {
        print_var(timer);
        print_var(timer->next);
        print_var(timer->callback);
        print_var(timer->maybe_type);
        print_var(timer->i2);
        print_var(timer->mpaf_exec_timer_arg);
        print_var(timer->i3);
        print_var(timer->time_offset_low);
        print_var(timer->time_offset_high);
        print_var(timer->i6);
        print_var(timer->i7);
        timer = timer->next;
        print("-------------------------\n");
    }
    //bcs_info();
}

//hwo many us to wait unti next timer
uint32_t next_timer_timestamp_us() {
    struct osapi_timer *timer = lm_osTimer;
    uint32_t current_time = clock_SystemTimeMicroseconds32_nolock();
    int32_t next_timer = lm_osTimer->time_offset_low - current_time;
    //print_var(current_time);
    //print_var(lm_osTimer->time_offset_low);
    //print_var(next_timer);
    return next_timer;
}


void check_and_handle_timers(uint32_t elapsed_time_us) {
    timer1value -= elapsed_time_us;
    if (next_timer_timestamp_us() < timer1value) return;
    print("\033[;31mTimer 2\033[;00m\n");
    show_timers();
    interruptvector_TIMER2_DONE();
    print("\033[;31mTimer 2 Done\033[;00m\n");
}


void add_timer_hooks() {
    trace(osapi_activateTimer, 2, false);
    trace(osapi_getTimerRemain, 1, true);
    trace(mpaf_osapi_timerCb, 1, false);
    //trace(clock_SystemTimeMicroseconds32, 1, false);
    //trace(clock_SystemTimeMicroseconds64, 1, true);
    //trace(clock_SystemTimeMicroseconds32_nolock, 1, false);
    //trace(clock_SystemTimeMicroseconds64_nolock, 1, true);
    trace(clock_serviceTimers,2 ,false);
    trace(mpaf_thread_PostMsgToHandler, 2, false);
    //trace(bcs_kernelTimerTick, 0 , false);
    trace(bcs_taskUnblock, 1, false);
}

#endif
