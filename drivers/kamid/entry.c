#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/capability.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "comm.h"
#include "memory.h"
#include "process.h"
#include "compat.h"

#define DEVICE_NAME "kamid"

static const char g_secret_key[] = "O4K48z4LOz7WwslW";
static bool g_is_verified = false;

bool is_driver_verified(void) {
    return g_is_verified;
}

int dispatch_open(struct inode *node, struct file *file) { return 0; }
int dispatch_close(struct inode *node, struct file *file) { return 0; }

long handle_module_base(unsigned long arg) {
    MODULE_BASE mb;
    char name_buffer[256];
    if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) != 0) return -EFAULT;
    if (copy_from_user(name_buffer, (void __user *)mb.name, sizeof(name_buffer) - 1) != 0) return -EFAULT;
    name_buffer[sizeof(name_buffer) - 1] = '\0';
    mb.base = get_module_base(mb.pid, name_buffer);
    if (copy_to_user((void __user *)arg, &mb, sizeof(mb)) != 0) return -EFAULT;
    return 0;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg) {
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;

    if (cmd != OP_INIT_KEY && !g_is_verified) {
        printk(KERN_WARNING "[+] Driver kamid: Access denied. Not authenticated.\n");
        return -EPERM;
    }

    switch (cmd) {
        case OP_INIT_KEY: {
            char user_key[sizeof(g_secret_key)];
            if (copy_from_user(user_key, (void __user *)arg, sizeof(user_key)) != 0) return -EFAULT;
            if (strncmp(user_key, g_secret_key, sizeof(g_secret_key)) == 0) {
                g_is_verified = true;
                printk(KERN_INFO "[+] Driver kamid: Authentication successful.\n");
            } else {
                g_is_verified = false;
                printk(KERN_ERR "[+] Driver kamid: Authentication failed.\n");
                return -EACCES;
            }
            break;
        }
        case OP_READ_MEM: {
            COPY_MEMORY cm;
            if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0) return -EFAULT;
            if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) return -EFAULT;
            break;
        }
        case OP_WRITE_MEM: {
            COPY_MEMORY cm;
            if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0) return -EFAULT;
            if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) return -EFAULT;
            break;
        }
        case OP_MODULE_BASE: {
            return handle_module_base(arg);
        }
        default:
            return -EINVAL;
    }
    return 0;
}

struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
    .compat_ioctl = dispatch_compat_ioctl,
};

struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &dispatch_functions,
};

int __init driver_entry(void) {
    int ret;
    printk(KERN_INFO "[+] Driver kamid: Memuat...\n");
    ret = misc_register(&misc);
    if (ret) {
        printk(KERN_ERR "[+] Driver kamid: Gagal mendaftarkan misc device, error %d\n", ret);
    } else {
        printk(KERN_INFO "[+] Driver kamid: Berhasil dimuat. Device: /dev/%s\n", DEVICE_NAME);
    }
    return ret;
}

void __exit driver_unload(void) {
    printk(KERN_INFO "[+] Driver kamid: Membongkar...\n");
    misc_deregister(&misc);
}

module_init(driver_entry);
module_exit(driver_unload);
MODULE_DESCRIPTION("Secure and Compatible Memory Access Driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("kamid (Revised)");