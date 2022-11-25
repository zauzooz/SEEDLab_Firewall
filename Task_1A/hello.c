// hello.c
#include <linux/kerel_level.h>
#include <linux/module.h>
#include <linux/kernel.h>

int initialization(void)
{
    printk(KERN_INFO "Hello World!\n");
    return 0;
}
void cleanup(void)
{
    printk(KERN_INFO "Bye-bye World!.\n");
}

// print "Hello World" when module is loaded
module_init(initialization); 

// print "Bye-byte World" when module is removed
module_exit(cleanup);

// remember adding this line
MODULE_LICENSE("GPL");