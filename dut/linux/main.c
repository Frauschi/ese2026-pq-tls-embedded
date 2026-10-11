#include <signal.h>

#include "ese_dut.h"

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    return ese_dut_run();
}
