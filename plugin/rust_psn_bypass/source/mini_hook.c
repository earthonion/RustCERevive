#include "mini_hook.h"
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>

// Function pointers for dynamically resolved functions
static int32_t (*_sceKernelMmap)(void *, size_t, int32_t, int32_t, int32_t, off_t, void **) = NULL;
static int32_t (*_sceKernelMunmap)(void *, size_t) = NULL;
static int (*_sceKernelMprotect)(const void *, size_t, int) = NULL;

// Initialize function pointers
static void mh_init_kernel_functions(void) {
    static int initialized = 0;
    if (initialized) return;

    // Resolve functions from libkernel
    int libkernel = 0x2001;  // libkernel module handle

    sys_dynlib_dlsym(libkernel, "sceKernelMmap", &_sceKernelMmap);
    sys_dynlib_dlsym(libkernel, "sceKernelMunmap", &_sceKernelMunmap);
    sys_dynlib_dlsym(libkernel, "sceKernelMprotect", &_sceKernelMprotect);

    initialized = 1;
}

void* mh_trampoline_of(mh_hook_t *h) { return h ? h->tramp_mem : NULL; }
int   mh_is_installed(mh_hook_t *h)  { return h && h->installed; }

// ---- Logging ---------------------------------------------------------------
void mh_log(const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    sceKernelDebugOutText(0, buf);
}

void mh_bind_thunk_slot(void **slot_addr, void *trampoline) {
    *slot_addr = trampoline;
}

// ---- Disassembly helper ----------------------------------------------------
size_t mh_calc_prologue_len(uintptr_t addr, size_t min_size) {
    size_t total = 0;
    while (total < min_size && total < MH_MAX_PROLOGUE) {
        hde64s hs;
        uint32_t len = hde64_disasm((void *)(addr + total), &hs);
        if (hs.flags & F_ERROR || len == 0) {
            mh_log("[mini_hook] HDE64 decode error.\n");
            return 0;
        }
        total += len;
    }
    return (total >= min_size) ? total : 0;
}

// ---- Internal: write absolute RIP-relative JMP stub ------------------------
// Encoding: FF 25 00 00 00 00  [qword target]
// Size: 14 bytes; write NOPs to pad if needed.
static void emit_abs_jmp_stub(uint8_t *dst, uint64_t target) {
    dst[0] = 0xFF; dst[1] = 0x25; dst[2] = 0; dst[3] = 0; dst[4] = 0; dst[5] = 0;
    memcpy(dst + 6, &target, sizeof(target));
}

// ---- Install ---------------------------------------------------------------
int mh_install(mh_hook_t *h) {
    // Initialize kernel functions
    mh_init_kernel_functions();

    if (!_sceKernelMmap || !_sceKernelMunmap) {
        mh_log("[mini_hook] kernel functions not resolved\n");
        return -1;
    }

    //if (!h || !h->target_addr || !h->user_impl) return -1;

    // After — allow wrapper (no user_impl) and thunk (both provided)
    if (!h || !h->target_addr ){//|| !h->user_thunk) {
        mh_log("[mini_hook] bad args: h=%p tgt=%p thunk=%p impl=%p\n",
           (void*)h, (void*)h->target_addr, h ? h->user_thunk : 0, h ? h->user_impl : 0);
        return -1;
    }
    if (h->installed) return 0;

    // 1) Determine how many bytes to steal
    // We need AT LEAST 14 bytes for absolute jump, but we can use a short jump (5 bytes)
    // to a secondary trampoline if the prologue is too short or contains problematic instructions

    // First try to steal exactly 14 bytes
    size_t stolen = mh_calc_prologue_len(h->target_addr, 14);

    // If that includes a CALL or JMP (which we can't easily relocate), try 11 bytes instead
    // and use a short JMP to a secondary absolute JMP
    if (stolen >= 11) {
        // Check if bytes 11-15 contain CALL (0xE8) or JMP (0xE9, 0xEB)
        uint8_t *code = (uint8_t*)h->target_addr;
        bool has_call_jmp = false;
        for (size_t i = 11; i < stolen && i < 16; i++) {
            if (code[i] == 0xE8 || code[i] == 0xE9 || code[i] == 0xEB) {
                has_call_jmp = true;
                mh_log("[mini_hook] Found CALL/JMP at offset %zu, reducing stolen bytes to avoid it\n", i);
                break;
            }
        }

        if (has_call_jmp) {
            // Steal only up to the CALL/JMP instruction
            stolen = mh_calc_prologue_len(h->target_addr, 11);
            if (stolen < 11) {
                mh_log("[mini_hook] Can't avoid CALL/JMP - prologue too short\n");
                return -2;
            }
        }
    }

    if (!stolen || stolen > MH_MAX_PROLOGUE) {
        mh_log("[mini_hook] invalid prologue size (%zu).\n", stolen);
        return -2;
    }
    h->stolen_len = stolen;

    // 2) Save original bytes
    memcpy(h->original, (void *)h->target_addr, stolen);

    // 3) Allocate executable trampoline page
    // Must allocate within ±2GB of target for RIP-relative relocation to work
    // Netflix code is typically in low memory (~0x00d00000), so use 0x20000000 as hint
    void *tramp = NULL;
    void *addr_hint = (void*)0x0000000020000000ULL;
    int ret = _sceKernelMmap(addr_hint, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, &tramp);
    if (ret < 0 || !tramp) {
        mh_log("[mini_hook] sceKernelMmap failed: ret=0x%X tramp=%p\n", ret, tramp);
        return -3;
    }
    mh_log("[mini_hook] Allocated trampoline at %p (hint was %p)\n", tramp, addr_hint);
    h->tramp_mem = tramp;

    // 4) Build trampoline: [stolen bytes] + [abs jmp back to target+stolen]
    uint8_t tramp_buf[MH_MAX_PROLOGUE + 14] = {0};
    memcpy(tramp_buf, h->original, stolen);

    // 4a) Relocate RIP-relative instructions
    // Scan through stolen bytes and fix any RIP-relative addressing
    size_t offset = 0;
    while (offset < stolen) {
        hde64s hs;
        uint32_t len = hde64_disasm((void *)(h->target_addr + offset), &hs);
        if (hs.flags & F_ERROR || len == 0) break;

        // Check if instruction has ModRM byte with RIP-relative addressing
        // ModRM: mod=00, rm=101 indicates [rip + disp32]
        if ((hs.flags & F_MODRM) && (hs.modrm & 0xC7) == 0x05) {
            // This is a RIP-relative instruction
            // Calculate original target address
            uint64_t insn_end = h->target_addr + offset + len;
            int32_t orig_disp = *(int32_t*)&h->original[offset + hs.len - 4];  // disp32 is last 4 bytes
            uint64_t target_addr = insn_end + orig_disp;

            // Calculate new displacement from trampoline
            uint64_t new_insn_end = (uint64_t)tramp + offset + len;
            int64_t new_disp64 = (int64_t)target_addr - (int64_t)new_insn_end;

            // Check if new displacement fits in 32 bits
            if (new_disp64 >= INT32_MIN && new_disp64 <= INT32_MAX) {
                int32_t new_disp = (int32_t)new_disp64;
                // Patch the displacement in the trampoline buffer
                memcpy(&tramp_buf[offset + hs.len - 4], &new_disp, 4);
                mh_log("[mini_hook] Relocated RIP-rel at offset %zu: orig_disp=0x%X target=0x%llX new_disp=0x%X\n",
                       offset, orig_disp, (unsigned long long)target_addr, new_disp);
            } else {
                // Displacement too large - can't relocate
                mh_log("[mini_hook] ERROR: Can't relocate RIP-rel at offset %zu - disp too large (%lld)\n",
                       offset, (long long)new_disp64);
                _sceKernelMunmap(tramp, 4096);
                return -5;
            }
        }

        offset += len;
    }

    uint64_t return_addr = (uint64_t)(h->target_addr + stolen);
    emit_abs_jmp_stub(tramp_buf + stolen, return_addr);

    // Write to trampoline
    memcpy(tramp, tramp_buf, stolen + 14);
    h->tramp_size = stolen + 14;

    // CRITICAL: On PPPwn, mmap doesn't properly set execute permissions
    // even when PROT_EXEC is specified. Must call mprotect explicitly.
    // Use kernel version, not libc version
    if (_sceKernelMprotect && _sceKernelMprotect(tramp, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        mh_log("[mini_hook] _sceKernelMprotect failed to set RWX!\n");
        _sceKernelMunmap(tramp, 4096);
        return -4;
    }

    // 5) Decide patch entry point:
    //    - Thunk mode: entry = user_thunk (assembly thunk does pre-work, tail-jumps to tramp)
    //    - Wrapper mode: entry = user_impl (C wrapper calls h->orig_fn to reach tramp/original)
    void* entry;
    if (h->user_thunk) {
        // ---- Thunk mode
        entry        = h->user_thunk;
        h->orig_fn   = tramp;             // still expose tramp as callable if someone wants it
        h->mode      = MH_MODE_THUNK;
    } else {
        // ---- Wrapper mode
        entry        = h->user_impl;      // patch jumps straight to user C function
        h->orig_fn   = tramp;             // user calls this to reach original
        h->mode      = MH_MODE_WRAPPER;
    }

    // 6) CRITICAL: Thunk mode - bind slot BEFORE patching, so thunk can execute immediately
    if (h->mode == MH_MODE_THUNK && h->thunk_slot) {
        // write the trampoline pointer into the slot
        *(volatile void**)h->thunk_slot = h->tramp_mem;
        mh_log("[mini_hook] Bound thunk slot %p -> trampoline %p\n",
               (void*)h->thunk_slot, h->tramp_mem);
    }

    // 7) Patch the target prologue with jmp to 'entry'
    uint8_t patch[MH_MAX_PROLOGUE] = {0};

    if (stolen >= 14) {
        // Use 14-byte absolute JMP
        emit_abs_jmp_stub(patch, (uint64_t)entry);
        if (stolen > 14) memset(patch + 14, 0x90, stolen - 14);
        mh_log("[mini_hook] Using 14-byte absolute JMP\n");
    } else if (stolen >= 5) {
        // Use 5-byte relative JMP: E9 <rel32>
        int64_t offset = (int64_t)entry - (int64_t)(h->target_addr + 5);
        if (offset >= INT32_MIN && offset <= INT32_MAX) {
            patch[0] = 0xE9;  // JMP rel32
            *(int32_t*)(patch + 1) = (int32_t)offset;
            if (stolen > 5) memset(patch + 5, 0x90, stolen - 5);
            mh_log("[mini_hook] Using 5-byte relative JMP (offset=%lld)\n", (long long)offset);
        } else {
            // Entry point too far - use two-stage trampoline
            // Stage 1: 5-byte JMP to secondary trampoline (at end of main trampoline page)
            // Stage 2: 14-byte absolute JMP to entry point

            void *secondary = (void*)((uintptr_t)tramp + 4096 - 14);  // Place at end of page

            // Build secondary trampoline: absolute JMP to entry
            uint8_t secondary_stub[14];
            emit_abs_jmp_stub(secondary_stub, (uint64_t)entry);
            memcpy(secondary, secondary_stub, 14);

            // Build patch: relative JMP to secondary
            offset = (int64_t)secondary - (int64_t)(h->target_addr + 5);
            if (offset >= INT32_MIN && offset <= INT32_MAX) {
                patch[0] = 0xE9;  // JMP rel32
                *(int32_t*)(patch + 1) = (int32_t)offset;
                if (stolen > 5) memset(patch + 5, 0x90, stolen - 5);
                mh_log("[mini_hook] Using two-stage trampoline: orig->%p->%p\n",
                       secondary, (void*)entry);
            } else {
                mh_log("[mini_hook] ERROR: Even secondary trampoline too far!\n");
                _sceKernelMunmap(tramp, 4096);
                return -6;
            }
        }
    } else {
        mh_log("[mini_hook] ERROR: Not enough bytes to patch (%zu)\n", stolen);
        _sceKernelMunmap(tramp, 4096);
        return -7;
    }

    mh_log("[mini_hook] Patching 0x%llx -> jump to 0x%llx (mode=%d, stolen=%zu bytes)\n",
           (unsigned long long)h->target_addr, (unsigned long long)entry, h->mode, stolen);

    sys_proc_rw(h->target_addr, patch, stolen);

    h->installed = true;
    mh_log("[mini_hook] Hook installed successfully!\n");
    return 0;
}

// ---- Remove ---------------------------------------------------------------
int mh_remove(mh_hook_t *h) {
    if (!h || !h->installed) return 0;

    // Restore original bytes
    sys_proc_rw(h->target_addr, h->original, h->stolen_len);

    // Unmap trampoline
    if (h->tramp_mem && _sceKernelMunmap) {
        _sceKernelMunmap(h->tramp_mem, 4096);
        h->tramp_mem = NULL;
    }
    h->orig_fn = NULL;
    h->installed = false;
    return 0;
}
