#include "plugin_common.h"
#include "patch.h"
#include <unistd.h>

// Simplified GoldHEN offset detection
extern "C" int GOLDHEN_OFFSET = -1;

extern "C" bool check_for_goldhen() {
  if (GOLDHEN_OFFSET == -1) {
    // For newer GoldHEN versions use offset 90, for older use 0
    // We'll just use 0 for now (older/standard)
    GOLDHEN_OFFSET = 0;
  }
  return true;
}

extern "C" void sys_proc_rw(u64 Address, void *Data, u64 Length)
{
    if (!Address || !Length)
    {
        final_printf("No target (0x%lx) or length (%li) provided!\n", Address, Length);
        return;
    }

    // Use GoldHEN SDK function instead of direct syscall
    struct proc_rw rw;
    rw.address = Address;
    rw.data = Data;
    rw.length = Length;
    rw.write_flags = 1;
    sys_sdk_proc_rw(&rw);
}

extern "C" void sys_proc_ro(u64 Address, void *Data, u64 Length)
{
    if (!Address || !Length)
    {
        final_printf("No target (0x%lx) or length (%li) provided!\n", Address, Length);
        return;
    }

    // Use GoldHEN SDK function instead of direct syscall
    struct proc_rw rw;
    rw.address = Address;
    rw.data = Data;
    rw.length = Length;
    rw.write_flags = 0;  // read
    sys_sdk_proc_rw(&rw);
}
