#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/ptrace.h>
#include <asm/syscall.h>
#include <linux/sched/task_stack.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define HAVE_PROC_OPS
#endif

/* Buffer size */
#define PROCFS_MAX_SIZE 1024 
/* Name of procfs file */
#define PROCFS_NAME "custom_data"

/* Struct MACRO */
#define STRUCT_CPU_TIMER 0
#define STRUCT_SYSCALL_INFO 1

/* Proc directory */
static struct proc_dir_entry *our_proc_file;

/* Temp buffer */
static char procfs_buffer[PROCFS_MAX_SIZE];

/* Temp length */
static unsigned long procfs_buffer_size = 0; 

/* Custom struct to manage cpu_timer */
struct my_cpu_timer {
	struct timerqueue_node	node;
	struct timerqueue_head	*head;
	int		                pid;
	struct list_head	    *elist;
	int			            firing;
};

static int pid = 0;
static int struct_id = 0;

static int write_cpu_timer(struct task_struct *task, char __user *buffer,loff_t *offset, size_t buffer_length) {
    /* Declare structures */
    struct my_cpu_timer timer;
    int len = 0;

    /* Init values */
    timer.node = task->signal->real_timer.node;
    timer.head = &(task->posix_cputimers.bases[0].tqhead);
    timer.pid = pid;
    timer.elist = &(task->signal->posix_timers);
    timer.firing = task->posix_cputimers.timers_active > 0;

    /* String to input */
    len += sprintf(procfs_buffer,
                   "Expires is %lld\nHead link: %p\nPid: %d\n"
                   "List link: %p\nIs there firing cpu_timer: %d\n",
                   timer.node.expires, (void *) timer.head, timer.pid, (void *) timer.elist, timer.firing);

    /* Copy string to user space */
    if (*offset >= len || copy_to_user(buffer, procfs_buffer, len)) {
        pr_info("Can't copy to user space\n");
        return -EFAULT;
    }

    /* Return value */
    *offset += len;
    return len;
}

int write_syscall_info(struct task_struct *task, char __user *buffer,loff_t *offset, size_t buffer_length) {
    /* Declare structures */
    struct syscall_info info;
    int len = 0;
    unsigned long args[6] = { };

    /* Init values */
    struct pt_regs *regs = task_pt_regs(task);
    info.sp = user_stack_pointer(regs);
    info.data.instruction_pointer = instruction_pointer(regs);
    info.data.nr = syscall_get_nr(task, regs);
    if (info.data.nr != -1L){
        syscall_get_arguments(task, regs, args);
    }
    info.data.args[0] = args[0];
    info.data.args[1] = args[1];
    info.data.args[2] = args[2];
    info.data.args[3] = args[3];
    info.data.args[4] = args[4];
    info.data.args[5] = args[5];

    /* String to input */
    len += sprintf(procfs_buffer,
                   "Stack pointer is %lld\nInstruction pointer: %lld\n""Syscall executed is: %d\n"
                   "Array of syscall stack: \nl1: %llu\n2: %llu\n3: %llu\n4: %llu\n5: %llu\n6: %llu\n",
                   info.sp, info.data.instruction_pointer, info.data.nr,
                   info.data.args[0], info.data.args[1], info.data.args[2],
                   info.data.args[3], info.data.args[4], info.data.args[5]);

    /* Copy string to user space */
    if (*offset >= len || copy_to_user(buffer, procfs_buffer, len)) {
        pr_info("Can't copy to user space\n");
        return -EFAULT;
    }

    /* Return value */
    *offset += len;
    return len;
}

static ssize_t procfile_read(struct file *filePointer, char __user *buffer, size_t buffer_length, loff_t *offset) {
    if (buffer_length < PROCFS_MAX_SIZE){
        pr_info("Not enough space in buffer\n");
        return -EFAULT;
    }
	if (pid){
        struct task_struct *task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
        if (task == NULL){
            pr_info("Can't get task struct for this pid\n");
            return -EFAULT;
        }
        if (struct_id == STRUCT_CPU_TIMER) {
            return write_cpu_timer(task, buffer, offset, buffer_length);
        }
        if (struct_id == STRUCT_SYSCALL_INFO) {
            return write_syscall_info(task, buffer, offset, buffer_length);
        }
	}
	return -EFAULT;
} 

 

/* This function calls when user writes to proc file */

static ssize_t procfile_write(struct file *file, const char __user *buff, size_t len, loff_t *off) {
    int num_of_args, a, b;

    /* We don't need to read more than 1024 bytes */
    procfs_buffer_size = len;
    if (procfs_buffer_size > PROCFS_MAX_SIZE) 
        procfs_buffer_size = PROCFS_MAX_SIZE; 

    /* Copy data from user space */
    if (copy_from_user(procfs_buffer, buff, procfs_buffer_size)) {
        pr_info("Can't copy from user space\n");
        return -EFAULT;
    }

    /* Read args from input */
	num_of_args = sscanf(procfs_buffer, "%d %d", &a, &b);
    if (num_of_args != 2) {
        pr_info("Invalid number of args\n");
        return -EFAULT;
    }

    /* Copy args to program */
	struct_id = a;
    pid = b;

	pr_info("Struct id is: %d\n", struct_id);
	pr_info("Pid is: %d\n", pid);

    return procfs_buffer_size; 

} 

 

#ifdef HAVE_PROC_OPS 

static const struct proc_ops proc_file_fops = {
    .proc_read = procfile_read,
    .proc_write = procfile_write,
}; 

#else 

static const struct file_operations proc_file_fops = {
    .read = procfile_read,
    .write = procfile_write,
}; 

#endif 

 

static int __init procfs2_init(void) {
    /* Init proc file */
    our_proc_file = proc_create(PROCFS_NAME, 0644, NULL, &proc_file_fops);
    if (NULL == our_proc_file) {
        proc_remove(our_proc_file);
        pr_alert("Error:Could not initialize /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }
    pr_info("/proc/%s created\n", PROCFS_NAME);
    return 0;
} 

 

static void __exit procfs2_exit(void) {
    /* Delete proc file */
    proc_remove(our_proc_file);
    pr_info("/proc/%s removed\n", PROCFS_NAME);
} 

module_init(procfs2_init);
module_exit(procfs2_exit); 

MODULE_LICENSE("GPL");