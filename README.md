
```
sudo docker-compose -f Labsetup/docker-compose.yml build
```

# Task 1: Implement a Simple firewall

## Loadable a kernel module

```c
// hello.c
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

```

## Compling a kernel module

Repare a Makefile file, type ```make``` command to run.

```Makefile
obj-m += hello.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

```shell
make
```

```shell
$ sudo insmod hello.ko  (inserting a module)
$ lsmod | grep hello    (list modules)
$ sudo rmmod hello      (remove the module)
$ dmesg                 (check the messages)
```

### Task 1B

seedFilter.c

```C
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>

unsigned int printInfo(void *priv, struct sk_buff *skb, 
                        const struct nf_hook_state *state)
{
    struct iphdr *iph;
    char *hook;

    switch (state->hook)
    {
        case NF_INET_PRE_ROUTING:
            printk("***PRE ROUTING")
            break;
        case NF_INET_LOCAL_IN:
            printk("***LOCAL IN");
            break;
        case NF_INET_FORWARD:
            printk("***FORWARDING");
            break;
        case NF_INET_POST_ROUTING:
            printk("***POST ROUTING");
            break;
        case NF_IP_LOCAL_OUT:
            printk("***LOCAL OUT");
            break;
        default:
            printk("unknown");
            break;
    }
    
    iph = ip_hdr(skb);
    printk("   %pI4 --> %pI4", &(iph->saddr), &(iph->daddr));
    return NF_ACCEPT;
}

unsigned int blockUDP(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph; // #include <linux/ip.h>
    struct udphdr *udph; // #include <linux/udp.h>
    u32 ip_addr;
    char ip[16] = "8.8.8.8";

    // convert the IPv4 address from dotted decimal to a 32-bit number
    in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

    iph = ip_hdr(skb);
    if (iph->protocol == IPPROTO_UDP)
    {
        udph = udp_hdr(skb);
        if (iph->daddr == ip_addr && ntohs(udph->dest) == 53)
        {
            printk(KERN_DEBUG "*** Dropping %pI4 (UDP), port %d\n", &(iph->daddr), 53);
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops hook1, hook2;

int registerFilter(void)
{
    printk(KERN_INFO "Registering filters.\n");

    // hook1
    hook1.hook = printInfo; // function name
    hook1.hooknum = NF_INET_LOCAL_IN; // hook number
    hook1.pf = PF_INET;
    hook1.priority = NF_IP_PRI_FIRST; // #include <linux/netfilter_ipv4.h>
    nf_register_net_hook(&init_net, &hook1); // attact hook to netfilter

    // hook2
    hook2.hook = blockUDP;
    hook2.hooknum = NF_INET_POST_ROUTING;
    hook2.pf = PF_INET;
    hook2.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook2);

    return 0;
}

void removeFilter(void)
{
    printk(KERN_INFO "The filters are being removed.\n");
    nf_unregister_net_hook(&init_net, &hook1);
    nf_unregister_net_hook(&init_net, &hook2);
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
```

### Task 1B: prevent ping

```C

```

### Task 1B: prevent telnet

