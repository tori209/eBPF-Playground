#include <linux/fs.h>
#include <linux/uaccess.h>
#include <uapi/asm/ptrace.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#define LOG_PATH "/var/log/kernel_log.txt"

KFUNC_PROBE(vfs_open, const struct path *path, struct file *file) {
   struct file * log_file;
   loff_t pos = 0;

   log_file = filp_open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
   if (IS_ERR(log_file)) {
     bpf_trace_printk("OPEN ERROR");
     return 0;
   }

   bpf_trace_printk("GO");
   kernel_write(log_file, "opened", 7, &pos);

   filp_close(log_file, NULL);
   return 0;
}
"""
