#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

unsigned int blockICMP(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcphd;
    u32 ip_addr;
    char ip[16] = "192.168.233.130";

    in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

    iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_TCP)
    {
        tcphd = tcp_hdr(skb);
        if (iph->daddr == ip_addr && ntohs(tcphd->dest) == 23)
        {
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops hook1;

int registerFilter(void)
{

    hook1.hook = blockICMP;
    hook1.hooknum = NF_INET_PRE_ROUTING;
    hook1.pf = PF_INET;
    hook1.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook1);

    return 0;
}

void removeFilter(void)
{
    nf_unregister_net_hook(&init_net, &hook1);
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");