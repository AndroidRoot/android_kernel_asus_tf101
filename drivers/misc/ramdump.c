/*
 * ASUS ram dump.
 */

#include <linux/module.h>
#include <linux/i2c.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <asm/io.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <linux/rtc.h>
#include <linux/syscalls.h>

MODULE_DESCRIPTION("Asus ram dump");
MODULE_LICENSE("GPL");

/***********kernel log ramdump test *****/
#define IRAM_CMD_ADDRESS 0x4001F000
#define IRAM_KERNEL_LOG_BUFFER	0x40020000
#define DATA_LOGS		"/data/logs"
#define DATA_LOGS_RAMDUMP	"/data/logs/ramdump"
#define DATA_MEDIA_RAMDUMP	"/data/media/ramdump"
#define DATA_LOGS_LAST_KMSG	"/data/logs/last_kmsg"


struct delayed_work ramdump_work;

static char rd_log_file[256];
static char rd_kernel_time[256];

struct timespec ts;
struct rtc_time tm;

static void ramdump_get_time(void){
	getnstimeofday(&ts);
	rtc_time_to_tm(ts.tv_sec, &tm);
	sprintf(rd_kernel_time, "%d-%02d-%02d-%02d%02d%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int ramdump_log_filename(void){
	struct file *fp;
	int err;
	mm_segment_t old_fs;
	fp = filp_open(DATA_LOGS , O_RDONLY, S_IRWXU|S_IRWXG|S_IRWXO);
	if (PTR_ERR(fp) == -ENOENT) {
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		err = sys_mkdir(DATA_LOGS,0777);
		if (err < 0) {
			set_fs(old_fs);
			return -ENOENT;
		}
		set_fs(old_fs);
		strcpy(rd_log_file, DATA_LOGS_RAMDUMP);
	} else {
		filp_close(fp,NULL);
		strcpy(rd_log_file, DATA_LOGS_RAMDUMP);
	}
	return 0;

}

static void ramdump_work_function(struct work_struct *dat){
	void __iomem *cmd_addr;
	void __iomem *test_addr;
	char *p;
	char temp[1024];
	char cmd[32];
	struct file *fp;
	int i;
	mm_segment_t old_fs;

	cmd_addr = ioremap(IRAM_CMD_ADDRESS,8);
	test_addr = ioremap(IRAM_KERNEL_LOG_BUFFER,8);

	strncpy(cmd, cmd_addr, 10);
	//printk(KERN_ERR "ramdump: cmd = %s\n", cmd);

	if(!strncmp(cmd, "kernel panic", 9)){
		printk(KERN_INFO "ramdump starting\n");

		if (ramdump_log_filename() < 0){
			printk(KERN_ERR "%s folder doesn't exist, and create fail !\n", DATA_LOGS);
			return ;
		}

		ramdump_get_time();
		strcat(rd_log_file, rd_kernel_time);
		strcat(rd_log_file,".log");

		old_fs = get_fs();
		set_fs(KERNEL_DS);

		p = (char *) test_addr;
		fp = filp_open(rd_log_file , O_APPEND | O_RDWR | O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
		if (PTR_ERR(fp) == -ENOENT){
			set_fs(old_fs);
			return ;
		}

		for (i = 0; i < 128; i++){
			memcpy(temp, p + (1024 * i), 1024);
			vfs_write(fp, temp, 1024, &fp->f_pos);
		}
		memset(cmd_addr, 0, 12);
		memset(test_addr, 0, 128*1024);

		filp_close(fp,NULL);
		set_fs(old_fs);
		printk(KERN_INFO "ramdump file: %s\n", rd_log_file);
	}
	printk(KERN_INFO "rd: finish\n");
}
static void last_kmsg_get_time(void){
	getnstimeofday(&ts);
	rtc_time_to_tm(ts.tv_sec, &tm);
	sprintf(rd_kernel_time, "%d-%02d-%02d-%02d%02d%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int last_kmsg_log_filename(void){
	struct file *fp;
	int err;
	mm_segment_t old_fs;
	fp = filp_open(DATA_LOGS , O_RDONLY, S_IRWXU|S_IRWXG|S_IRWXO);
	if (PTR_ERR(fp) == -ENOENT) {
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		err = sys_mkdir(DATA_LOGS,0777);
		if (err < 0) {
			set_fs(old_fs);
			return -ENOENT;
		}
		set_fs(old_fs);
		strcpy(rd_log_file, DATA_LOGS_LAST_KMSG);
	} else {
		filp_close(fp,NULL);
		strcpy(rd_log_file, DATA_LOGS_LAST_KMSG);
	}
	return 0;

}

extern unsigned int boot_reason;
bool  is_panic( void )
{
	void __iomem *cmd_addr;

	cmd_addr = ioremap(IRAM_CMD_ADDRESS,8);
	if( !strncmp(cmd_addr,"kernel panic", 9)){
		memset(cmd_addr, 0, 12);
		return true;
	}

	return false;
}

static void last_kmsg_work_function(struct work_struct *dat)
{
	#define SWR_SYS_RST_STA  (1<<13)
	#define WDT_SYS_RST_STA  (1<<12)
	char *buffer;
	struct file *fp;
	struct file *fp_proc;
	mm_segment_t old_fs;
	ssize_t result;

	printk(KERN_INFO "dump last_kmsg starting\n");

	buffer=kmalloc(SZ_1M, GFP_KERNEL);
	if(!buffer){
		printk(KERN_ERR "last_kmsg_work_function:alloc buffer fail!\n");
		return;
	}

	if (last_kmsg_log_filename() < 0){
		printk(KERN_ERR "%s folder doesn't exist, and create fail !\n", DATA_LOGS);
		kfree(buffer);
		return ;
	}

	last_kmsg_get_time();
	strcat(rd_log_file, rd_kernel_time);
	if (boot_reason==WDT_SYS_RST_STA)
		strcat(rd_log_file,".log_wdt");
	else if (boot_reason==SWR_SYS_RST_STA &&  is_panic())
		strcat(rd_log_file,".log_panic");
	#ifdef CONFIG_DEBUG_SLAB
	else if (boot_reason==SWR_SYS_RST_STA )
		strcat(rd_log_file,".log_reboot");
	else
		strcat(rd_log_file,".log_hwreset");
	#endif

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	fp_proc = filp_open("/proc/last_kmsg" , O_APPEND | O_RDWR | O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if (PTR_ERR(fp_proc) == -ENOENT){
		printk(KERN_INFO "last_kmsg_work_function:last_kmsg is empty!\n");
		set_fs(old_fs);
		kfree(buffer);
		return ;
	}

	fp = filp_open(rd_log_file , O_APPEND | O_RDWR | O_CREAT, S_IRWXU|S_IRWXG|S_IRWXO);
	if (PTR_ERR(fp) == -ENOENT){
		filp_close(fp_proc,NULL);
		set_fs(old_fs);
		kfree(buffer);
		return ;
	}

	result=vfs_read(fp_proc, buffer, SZ_1M, &fp_proc->f_pos);
	if( result < 0 ){
		printk(KERN_INFO "last_kmsg_work_function:read last_kmsg fail!\n");
	}else{
		result=vfs_write(fp, buffer, result, &fp->f_pos);
		if( result < 0 )
			printk(KERN_INFO "last_kmsg_work_function:write last_kmsg fail!\n");
	}

	filp_close(fp_proc,NULL);
	filp_close(fp,NULL);
	set_fs(old_fs);
	kfree(buffer);
	printk(KERN_INFO "last_kmsg file: %s\n", rd_log_file);
	return;
}

static int __init rd_init(void){
	#ifdef RAMDUMP
	INIT_DELAYED_WORK_DEFERRABLE(&ramdump_work,  ramdump_work_function);
	#else
	printk(KERN_INFO " rd_init: last_kmsg_work_function\n");
	INIT_DELAYED_WORK_DEFERRABLE(&ramdump_work,  last_kmsg_work_function);
	#endif
	schedule_delayed_work(&ramdump_work, 15*HZ);
	return 0;
}

static void __exit rd_exit(void){

}


module_init(rd_init);
module_exit(rd_exit);


