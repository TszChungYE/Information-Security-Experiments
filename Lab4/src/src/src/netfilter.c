#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>

#define IPADDRESS(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

static char *ip_addr_rule = "8.8.8.8";
static struct nf_hook_ops *nf_blockicmppkt_ops = NULL;
static struct nf_hook_ops *nf_blockipaddr_ops = NULL;
static unsigned int nf_blockipaddr_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if (!skb) return NF_ACCEPT;
	char *str = (char *)kmalloc(16, GFP_KERNEL);
	struct iphdr *iph = ip_hdr(skb;);
	u32 sip = ntohl(iph->saddr);
	sprintf(str, "%u.%u.%u.%u", IPADDRESS(sip));
	if(!strcmp(str, ip_addr_rule)) {
		printk(KERN_INFO "Dropping ip packet to: %s\n", str);
		return NF_DROP;
	}
	return NF_ACCEPT;
}
static unsigned int nf_blockicmppkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if(!skb) return NF_ACCEPT;
	struct iphdr *iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_ICMP) {
		printk(KERN_INFO "Dropping ICMP packet \n");
		return NF_DROP;
	}
	return NF_ACCEPT;
}
static int __init nf_minifirewall_init(void) {
	nf_blockicmppkt_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_blockicmppkt_ops != NULL) {
		nf_blockicmppkt_ops->hook = (nf_hookfn*)nf_blockicmppkt_handler;
		nf_blockicmppkt_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_blockicmppkt_ops->pf = NFPROTO_IPV4;
		nf_blockicmppkt_ops->priority = NF_IP_PRI_FIRST;
		nf_register_net_hook(&init_net, nf_blockicmppkt_ops);
	}
	nf_blockipaddr_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_blockipaddr_ops != NULL) {
		nf_blockipaddr_ops->hook = (nf_hookfn*)nf_blockipaddr_handler;
		nf_blockipaddr_ops->hooknum = NF_INET_PRE_ROUTING;
		nf_blockipaddr_ops->pf = NFPROTO_IPV4;
		nf_blockipaddr_ops->priority = NF_IP_PRI_FIRST + 1;
		nf_register_net_hook(&init_net, nf_blockipaddr_ops);
	}
	return 0;
}
static void __exit nf_minifirewall_exit(void) {
	if(nf_blockicmppkt_ops != NULL) {
		nf_unregister_net_hook(&init_net, nf_blockicmppkt_ops);
		kfree(nf_blockicmppkt_ops);
	}
	if (nf_blockipaddr_ops  != NULL) {
		nf_unregister_net_hook(&init_net, nf_blockipaddr_ops);
		kfree(nf_blockipaddr_ops);
	}
	printk(KERN_INFO "Exit");
}
module_init(nf_minifirewall_init);
module_exit(nf_minifirewall_exit);
MODULE_LICENSE("GPL");