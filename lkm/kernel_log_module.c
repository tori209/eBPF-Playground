#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define LOG_PATH "/var/log/kernel_log.txt"

static int write_log(const char *msg) {
    struct file *file;
    loff_t pos = 0;
    
    file = filp_open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open log file\n");
        return PTR_ERR(file);
    }
    
    kernel_write(file, msg, strlen(msg), &pos);
    
    filp_close(file, NULL);
    return 0;
}

static int __init log_init(void) {
    printk(KERN_INFO "Kernel log module loaded\n");
    write_log("Kernel log module initialized\n");
    return 0;
}

static void __exit log_exit(void) {
    printk(KERN_INFO "Kernel log module unloaded\n");
    write_log("Kernel log module exited\n");
}

module_init(log_init);
module_exit(log_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A kernel module that writes logs to a file");

