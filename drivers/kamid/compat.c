#include <linux/slab.h>
#include "comm.h"
#include "compat.h"
#include "memory.h"
#include "process.h"

extern long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg);
long dispatch_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    if (cmd == OP_INIT_KEY) {
        return dispatch_ioctl(filp, cmd, arg);
    }

    switch (cmd) {
        case OP_READ_MEM: {
            COPY_MEMORY32 __user *p32 = compat_ptr(arg);
            COPY_MEMORY cm64;
            compat_uptr_t buffer_ptr32;

            if (get_user(cm64.pid, &p32->pid) ||
                get_user(cm64.addr, &p32->addr) ||
                get_user(cm64.size, &p32->size))
                return -EFAULT;

            if (get_user(buffer_ptr32, &p32->buffer)) return -EFAULT;
            cm64.buffer = compat_ptr(buffer_ptr32);
            
            return dispatch_ioctl(filp, OP_READ_MEM, (unsigned long)&cm64);
        }
        case OP_WRITE_MEM: {
            COPY_MEMORY32 __user *p32 = compat_ptr(arg);
            COPY_MEMORY cm64;
            compat_uptr_t buffer_ptr32;

            if (get_user(cm64.pid, &p32->pid) ||
                get_user(cm64.addr, &p32->addr) ||
                get_user(cm64.size, &p32->size))
                return -EFAULT;
            
            if (get_user(buffer_ptr32, &p32->buffer)) return -EFAULT;
            cm64.buffer = compat_ptr(buffer_ptr32);

            return dispatch_ioctl(filp, OP_WRITE_MEM, (unsigned long)&cm64);
        }
        case OP_MODULE_BASE: {
            MODULE_BASE32 __user *p32 = compat_ptr(arg);
            MODULE_BASE mb64;
            compat_uptr_t name_ptr32;
            char name_buffer[256];
            char __user *user_name_ptr;

            if (get_user(mb64.pid, &p32->pid)) return -EFAULT;
            if (get_user(name_ptr32, &p32->name)) return -EFAULT;

            user_name_ptr = compat_ptr(name_ptr32);

            if (copy_from_user(name_buffer, user_name_ptr, sizeof(name_buffer) - 1) != 0) return -EFAULT;
            name_buffer[sizeof(name_buffer) - 1] = '\0';
            
            mb64.base = get_module_base(mb64.pid, name_buffer);

            if (put_user(mb64.base, &p32->base)) return -EFAULT;
            break;
        }
        default:
            return -EINVAL;
    }
    return 0;
}
