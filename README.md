# SEEDLab: Firewall

Team 124C41:

|Name              |                 ID|
|-----------------:|------------------:|
|Nguyen Ngoc Tai   |20521858           |
|Tran Tri Duc      |20520454           |
|Huynh The Hao     |20521291           |
|Le Thanh Dat      |20521169           |

Build topology:

```
sudo docker-compose -f Labsetup/docker-compose.yml build
```

# Task 1: Implement a Simple firewall

## Task 1.A: Implement a Simple Kernel Module

Step1: Loadable a kernel module

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

Step2: Compling a kernel module

- Repare a Makefile file.

```Makefile
obj-m += hello.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

- Type ```make``` command to run.

```shell
make
```

Step3: Folowing these command:

```shell
$ sudo insmod hello.ko  (inserting a module)
$ lsmod | grep hello    (list modules)
$ sudo rmmod hello      (remove the module)
$ dmesg                 (check the messages)
```

## Task 1.B: Implement a Simple Firewall Using Netfilter

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

### Task 1.B: prevent ping

```C

```

### Task 1.B: prevent telnet

```C

```

# Task 2: Experimenting with Stateless Firewall Rules

### Task 2.A: Protecting the Router

To ping from host A to seed-router:

[]()

At the seed-router, set a rule :

```shell
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
iptables -P OUPUT DROP
iptables -P INPUT DROP

```

Now, try to ping from host A to seed-router:

[]()

### Task 2.B: Protecting the Internal Network

In this task, we will set up firewall rules on the **router** to protect the internal network 192.168.60.0/24.

We need to enforce the following restrictions on the ICMP traffic:
1. Outside hosts cannot ping internal hosts.

2. Outside hosts can ping the router.

3. Internal hosts can ping outside hosts.

4. All other packets between the internal and external networks should be blocked.

Following my rules:

```
iptables -A FORWARD -p icmp --icmp-type echo-reply -d 192.168.60.0/24 -j ACCEPT
iptables -A FORWARD -p icmp --icmp-type echo-request -s 192.168.60.0/24 -j ACCEPT
iptables -A FORWARD -p icmp -d 192.168.60.0/24 -j DROP
iptables -A FORWARD -j DROP
```

Before appling rules:

- Host A pings to host 1, host 2 and host 3:

[]()

[]()

[]()

- Host A pings to router (2 interface):

[]()

[]()

- Host A telnet to host 1, host 2 and host 3:

[]()

[]()

[]()

- Host 1, host 2 and host 3 ping to host A:

[]()

[]()

[]()

- Host 1, host 2 and host 3 telnet to host A:

[]()

[]()

[]()

After appling rules:

- Host A pings to host 1, host 2 and host 3:

[]()

[]()

[]()

- Host A pings to router (2 interface):

[]()

[]()

- Host A telnet to host 1, host 2 and host 3:

[]()

[]()

[]()

- Host 1, host 2 and host 3 ping to host A:

[]()

[]()

[]()

- Host 1, host 2 and host 3 telnet to host A:

[]()

[]()

[]()

Refresh iptables of router:

```shell
iptables -F
iptables -A FORWARD -j ACCEPT
```

### Task 2.C: Protecting Internal Servers

In this task, we want to protect the TCP servers inside the internal network (192.168.60.0/24)

We would like to achieve the following objectives:

1. All the internal hosts run a telnet server (listening to port 23). Outside hosts can only access the telnetserver on 192.168.60.5, not the other internal hosts.

2. Outside hosts cannot access other internal servers.

3. Internal hosts can access all the internal servers.

4. Internal hosts cannot access external servers.

5. In this task, the connection tracking mechanism is not allowed. It will be used in a later task.

Following my rules:

```shell
iptables -A FORWARD -p tcp --dport 23 -d 192.168.60.5 -j ACCEPT
iptables -A FORWARD -p tcp --dport 23 ! -d  192.168.60.5 -j DROP
```

Before appling rules:

- Host A telnets to host 1, host 2 and host 3:

[]()

[]()

[]()

- Host 1, host 2 and host 3 telnet to host A:

[]()

[]()

[]()

After appling rules:

- Host A telnets to host 1, host 2 and host 3:

[]()

[]()

[]()

- Host 1, host 2 and host 3 telnet to host A:

[]()

[]()

[]()

Refresh iptables of router:

```shell
iptables -F
```

# Task 3: Connection Tracking and Stateful Firewall

## Task 3.A: Experiment with the Connection Tracking

- ICMP connection state is kept in 29s.

[]()

- UDP connection state is kept in 28s.

[]()

- TCP connection state is kept in 431998s.

[]()

## Task 3.B: Setting Up a Stateful Firewall

We would like to achieve the following objectives

1. All the internal hosts run a telnet server (listening to port 23). Outside hosts can only access the telnetserver on 192.168.60.5, not the other internal hosts.
2. Outside hosts cannot access other internal servers.
3. Internal hosts can access all the internal servers.
4. Internal hosts can access external servers.
5. In this task, the connection tracking mechanism is allowed.

Following my rules:

```shell
iptables -A FORWARD -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp -i eth0 --dport 23 --syn -m conntrack --ctstate NEW -d 192.168.60.5 -j ACCEPT
iptables -A FORWARD -p tcp -i eth1 --dport 23 --syn -m conntrack --ctstate NEW -j ACCEPT
iptables -P FORWARD DROP

```

Before applying rules:

- Host A telnets to host 1, host 2 and host 3:

[]()

[]()

[]()

- Host 1, host 2 and host 3 telnet to host A:

[]()

[]()

[]()

After applying rules:

- Host A telnets to host 1, host 2 and host 3:

[]()

[]()

[]()

- Host 1, host 2 and host 3 telnet to host A:

[]()

[]()

[]()

Refresh iptables of router:

```shell
iptables -F
iptables -P FORWARD ACCEPT
```

# Task 4: Limiting Network Traffic

# Task 5: Load Balancing