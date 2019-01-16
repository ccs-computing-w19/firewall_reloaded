#include <linux/module.h> //For all modules
#include <linux/kernel.h> //For KERN_INFO

int init_module(void) {
	printk(KERN_INFO "Hello world 1.\n");
	return 0; // return status, tells if module is loaded
}

void cleanup_module(void) {
	printk(KERN_INFO "Goodbye world 1.\n");
}

