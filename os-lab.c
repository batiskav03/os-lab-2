#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include<linux/proc_fs.h>
#include <linux/pid.h>






char ext_array[20] = "proc_array\n";
int pid_value;
struct task_struct *task;

static int open_proc(struct inode *inode, struct file *file);
static int release_proc(struct inode *inode, struct file *file);
static ssize_t read_proc(struct file *flip, char __user *buffer, size_t length, loff_t* offset);
static ssize_t write_proc(struct file *flip, const char *buf, size_t len, loff_t* off);

static struct proc_dir_entry *parent;
static struct proc_ops proc_fops = {
    .proc_open = open_proc,
    .proc_read = read_proc,
    .proc_write = write_proc,
    .proc_release = release_proc


};

static int open_proc(struct inode *inode, struct file *file) {
    pr_info("proc file opend.....\t");
    return 0;
}

static int release_proc(struct inode *inode, struct file *file) {
    pr_info("proc file released.....\n");
    return 0;
}

static ssize_t read_proc(struct file *flip, char __user *buffer, size_t length, loff_t* offset) {
    pr_info("proc file read.....\n");
    if (!pid_value) {
        pr_err("You dont insert pid");
        return length; //TODO: return ERR;
    }
    if (length) {
        length = 0;
    } else {
        length = 1;
        return 0;
    }
    

    return length;
}

static ssize_t write_proc(struct file *flip, const char *buf, size_t len, loff_t* off) {
    pr_info("proc file wrote.....\n");
    // copy_from_user(ext_array, buf, len);
    for (int i = 0; i < len; i++) {
        pr_info("%c",ext_array[i]);
    }
    return len;
}

static int __init hello_world_init(void) {
    pr_info("Hello, world!");
    parent = proc_mkdir("os-lab", NULL);
    proc_create("enter_pid", 0666, parent, &proc_fops);
    return 0;
}


void __exit hello_world_exit(void) {
    proc_remove(parent);
    pr_info("Bye!");
}

int notify_param(const char *val, const struct kernel_param *kp) {
    struct syscall_info info;
    u64 *args = &info.data.args[0];
    int res = param_set_int(val, kp);
    if (res == 0) {
        pr_info("Callback func called...");
        pr_info("New value of pid_value = %d", pid_value);
        return 0;
    }
    task = get_pid_task(find_vpid(pid_value), PIDTYPE_PID);
    res = task_current_syscall(task, &info);
    if (res == 0) {
        pr_info("Syscall successfully writen...");\
        if (info.data.nr < 0) 
            pr_info("%d 0x%llx 0x%llx\n",
			   info.data.nr, info.sp, info.data.instruction_pointer);
        else 
            pr_info("%d 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n",
		       info.data.nr,
		       args[0], args[1], args[2], args[3], args[4], args[5],
		       info.sp, info.data.instruction_pointer);

        return 0;
    }
    return -1;
}

const struct kernel_param_ops pid_ops = {
    .set = &notify_param,
    .get = &param_get_int,
};


module_param_cb(pid_value, &pid_ops, &pid_value, S_IRUGO|S_IWUSR );
module_init(hello_world_init);
module_exit(hello_world_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("EmbeTronicX <embetronicx@gmail.com>");
MODULE_DESCRIPTION("A simple hello world driver");
MODULE_VERSION("2:1.0");