#ifndef __STATE_MACHINE_H__
#define __STATE_MACHINE_H__

typedef unsigned int state_type_t;
typedef int (*state_process)();

void *init_state_machine(state_process *processes, int state_num);
int enqueue_state_machine(void *state_machine, state_type_t state);
void destroy_state_machine(void *state_machine);
int get_current_state(void *state_machine);

#endif
