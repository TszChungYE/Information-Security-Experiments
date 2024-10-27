//#include <linux/init.h>
//#include <linux/module.h>
//#include <linux/kernel.h>
//#include <linux/netfilter.h>
//#include <linux/netfilter_ipv4.h>
//#include <linux/ip.h>
//#include <linux/tcp.h>
//#include <linux/udp.h>
//#include <linux/string.h>
//#include <linux/slab.h>  // for kmalloc and kfree
//
//#define IPADDRESS(addr) \
//	((unsigned char *)&addr)[3], \
//	((unsigned char *)&addr)[2], \
//	((unsigned char *)&addr)[1], \
//	((unsigned char *)&addr)[0]
//
//static char *ip_addr_rule = "202.116.64.8";
//static char *proxy_server_ip = "192.168.1.140";
//static struct nf_hook_ops *nf_blockicmppkt_ops = NULL;
//static struct nf_hook_ops *nf_blockipaddr_ops = NULL;
//static struct nf_hook_ops *nf_forbidden_http_ops = NULL;
//static struct nf_hook_ops *nf_forbidden_ssh_ops = NULL;
//
//static unsigned int nf_blockipaddr_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
//{
//	if (!skb) return NF_ACCEPT;
//	char *str = (char *)kmalloc(16, GFP_KERNEL);
//	struct iphdr *iph = ip_hdr(skb);
//	u32 sip = ntohl(iph->saddr);
//	sprintf(str, "%u.%u.%u.%u", IPADDRESS(sip));
//	if (!strcmp(str, ip_addr_rule)) {
//		printk(KERN_INFO "Dropping ip packet from: %s\n", str);
//		kfree(str);
//		return NF_DROP;
//	}
//	kfree(str);
//	return NF_ACCEPT;
//}
//
//static unsigned int nf_blockicmppkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
//{
//	if (!skb) return NF_ACCEPT;
//	struct iphdr *iph = ip_hdr(skb);
//	if (iph->protocol == IPPROTO_ICMP) {
//		printk(KERN_INFO "Dropping ICMP packet \n");
//		return NF_DROP;
//	}
//	return NF_ACCEPT;
//}
//
//
//// 过滤访问代理服务器Web服务的钩子函数
//static unsigned int forbidden_http_only_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
//{
//    struct iphdr *iph = ip_hdr(skb);
//    struct tcphdr *tcp = (void *)iph + iph->ihl * 4;
//
//    // 检查目的IP地址和端口，以确定是否为HTTP请求到代理服务器
//    if (iph->daddr == htonl(0xc0a8018c) && // 192.168.1.140
//        tcp->dest == htons(80)) { // HTTP端口
//        // 丢弃数据包
//        printk(KERN_INFO "Dropping HTTP packet to proxy server\n");
//        return NF_DROP;
//    }
//
//    return NF_ACCEPT;
//}
//
//
//static unsigned int forbidden_ssh_from_out_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
//{
//    struct iphdr *iph = ip_hdr(skb);
//    struct tcphdr *tcp = (void *)iph + iph->ihl * 4;
//
//    // 检查目的IP地址和端口，以确定是否为SSH请求到正常用户主机
//    if (iph->daddr == htonl(0xc0a801f1) && // 192.168.1.241
//        tcp->dest == htons(22)) { // SSH端口
//        // 检查源IP地址，如果不是正常用户主机的IP，则丢弃
//        if (iph->saddr != htonl(0xc0a801f1)) { // 192.168.1.241
//            printk(KERN_INFO "Dropping SSH packet from external IP to 192.168.1.241\n");
//            return NF_DROP;
//        }
//    }
//
//    return NF_ACCEPT;
//}
//
//static int __init nf_minifirewall_init(void)
//{
//	// ICMP packet blocking hook
//	nf_blockicmppkt_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
//	if (nf_blockicmppkt_ops != NULL) {
//		nf_blockicmppkt_ops->hook = (nf_hookfn *)nf_blockicmppkt_handler;
//		nf_blockicmppkt_ops->hooknum = NF_INET_PRE_ROUTING;
//		nf_blockicmppkt_ops->pf = NFPROTO_IPV4;
//		nf_blockicmppkt_ops->priority = NF_IP_PRI_FIRST;
//		nf_register_net_hook(&init_net, nf_blockicmppkt_ops);
//	}
//
//	// IP address blocking hook
//	nf_blockipaddr_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
//	if (nf_blockipaddr_ops != NULL) {
//		nf_blockipaddr_ops->hook = (nf_hookfn *)nf_blockipaddr_handler;
//		nf_blockipaddr_ops->hooknum = NF_INET_PRE_ROUTING;
//		nf_blockipaddr_ops->pf = NFPROTO_IPV4;
//		nf_blockipaddr_ops->priority = NF_IP_PRI_FIRST + 1;
//		nf_register_net_hook(&init_net, nf_blockipaddr_ops);
//	}
//
//	// HTTP traffic blocking hook
//	nf_forbidden_http_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
//	if (nf_forbidden_http_ops != NULL) {
//		nf_forbidden_http_ops->hook = (nf_hookfn *)forbidden_http_only_handler;
//		nf_forbidden_http_ops->hooknum = NF_INET_PRE_ROUTING;
//		nf_forbidden_http_ops->pf = NFPROTO_IPV4;
//		nf_forbidden_http_ops->priority = NF_IP_PRI_FIRST + 2;
//		nf_register_net_hook(&init_net, nf_forbidden_http_ops);
//	}
//
//	// SSH traffic blocking hook
//	nf_forbidden_ssh_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
//	if (nf_forbidden_ssh_ops != NULL) {
//		nf_forbidden_ssh_ops->hook = (nf_hookfn *)forbidden_ssh_from_out_handler;
//		nf_forbidden_ssh_ops->hooknum = NF_INET_PRE_ROUTING;
//		nf_forbidden_ssh_ops->pf = NFPROTO_IPV4;
//		nf_forbidden_ssh_ops->priority = NF_IP_PRI_FIRST + 3;
//		nf_register_net_hook(&init_net, nf_forbidden_ssh_ops);
//	}
//
//	return 0;
//}
//
//static void __exit nf_minifirewall_exit(void)
//{
//	if (nf_blockicmppkt_ops != NULL) {
//		nf_unregister_net_hook(&init_net, nf_blockicmppkt_ops);
//		kfree(nf_blockicmppkt_ops);
//	}
//	if (nf_blockipaddr_ops != NULL) {
//		nf_unregister_net_hook(&init_net, nf_blockipaddr_ops);
//		kfree(nf_blockipaddr_ops);
//	}
//	if (nf_forbidden_http_ops != NULL) {
//		nf_unregister_net_hook(&init_net, nf_forbidden_http_ops);
//		kfree(nf_forbidden_http_ops);
//	}
//	if (nf_forbidden_ssh_ops != NULL) {
//		nf_unregister_net_hook(&init_net, nf_forbidden_ssh_ops);
//		kfree(nf_forbidden_ssh_ops);
//	}
//	printk(KERN_INFO "Exit\n");
//}
//
//module_init(nf_minifirewall_init);
//module_exit(nf_minifirewall_exit);
//MODULE_LICENSE("GPL");


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

static char *ip_addr_rule = "202.116.64.8";
static char *proxy_ip = "192.168.1.140";
static char *user_host_ip = "192.168.1.241";
static struct nf_hook_ops *nf_blockicmppkt_ops = NULL;
static struct nf_hook_ops *nf_blockipaddr_ops = NULL;
static struct nf_hook_ops *nf_forbidden_http_only_ops = NULL;
static struct nf_hook_ops *nf_forbidden_ssh_from_out_ops = NULL;

static unsigned int nf_blockipaddr_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if (!skb) return NF_ACCEPT;
	char *str = (char *)kmalloc(16, GFP_KERNEL);
	struct iphdr *iph = ip_hdr(skb);
	u32 sip = ntohl(iph->saddr);
	sprintf(str, "%u.%u.%u.%u", IPADDRESS(sip));
	if(!strcmp(str, ip_addr_rule)) {
		printk(KERN_INFO "Dropping IP packet to: %s\n", str);
		return NF_DROP;
	}
	return NF_ACCEPT;
}

static unsigned int nf_blockicmppkt_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if(!skb) return NF_ACCEPT;
	struct iphdr *iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_ICMP) {
		printk(KERN_INFO "Dropping ICMP packet\n");
		return NF_DROP;
	}
	return NF_ACCEPT;
}

static unsigned int nf_forbidden_http_only_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if (!skb) return NF_ACCEPT;
	struct iphdr *iph = ip_hdr(skb);
	
	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = NULL;
		tcph = tcp_hdr(skb);
		
		u32 dip = ntohl(iph->daddr);
		
		char *str1 = (char *)kmalloc(16, GFP_KERNEL);
		sprintf(str1, "%u.%u.%u.%u", IPADDRESS(dip));
		printk(KERN_INFO"%s\n",str1);
		if(!strcmp(str1, proxy_ip))
		{
			if(ntohs(tcph->dest)==80)
			{
				printk(KERN_INFO "Dropping HTTP packet");
				kfree(str1);
				return NF_DROP;
			}
		}
		kfree(str1);
		
//		if (ntohl(iph->daddr) == 0xc0a8018c && ntohs(tcph->dest) == 80) { // 192.168.1.140:80
//			printk(KERN_INFO "Dropping HTTP packet to 192.168.1.140\n");
//			return NF_DROP;
//		}
	}
	return NF_ACCEPT;
}

static unsigned int nf_forbidden_ssh_from_out_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if (!skb) return NF_ACCEPT;
	struct iphdr *iph = ip_hdr(skb);

	if (iph->protocol == IPPROTO_TCP) 
	{
		struct tcphdr *tcph = NULL;
		tcph = tcp_hdr(skb);
		
		u32 dip = ntohl(iph->daddr);
		u32 sip = ntohl(iph->saddr);
	
		char *str2 = (char *)kmalloc(16, GFP_KERNEL);
		sprintf(str2, "%u.%u.%u.%u", IPADDRESS(dip));
		printk(KERN_INFO"%s\n",str2);
		
		char *str3 = (char *)kmalloc(16, GFP_KERNEL);
		sprintf(str3, "%u.%u.%u.%u", IPADDRESS(sip));
		printk(KERN_INFO"%s\n",str3);
		
		if (ntohs(tcph->dest) == 22) 
		{
			if(!strcmp(str2, user_host_ip) && !strcmp(str3, user_host_ip))
			{
				kfree(str2);
				kfree(str3);
				return NF_ACCEPT;
			}
			kfree(str2);
			kfree(str3);
			printk(KERN_INFO "Dropping external SSH packet\n");
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}

static int __init nf_minifirewall_init(void) {
	nf_blockicmppkt_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_blockicmppkt_ops != NULL) {
		nf_blockicmppkt_ops->hook = (nf_hookfn*)nf_blockicmppkt_handler;
		nf_blockicmppkt_ops->hooknum = NF_INET_LOCAL_OUT;
		nf_blockicmppkt_ops->pf = NFPROTO_IPV4;
		nf_blockicmppkt_ops->priority = NF_IP_PRI_FIRST;
		nf_register_net_hook(&init_net, nf_blockicmppkt_ops);
	}
	nf_blockipaddr_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_blockipaddr_ops != NULL) {
		nf_blockipaddr_ops->hook = (nf_hookfn*)nf_blockipaddr_handler;
		nf_blockipaddr_ops->hooknum = NF_INET_LOCAL_OUT;
		nf_blockipaddr_ops->pf = NFPROTO_IPV4;
		nf_blockipaddr_ops->priority = NF_IP_PRI_FIRST + 1;
		nf_register_net_hook(&init_net, nf_blockipaddr_ops);
	}
	nf_forbidden_http_only_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_forbidden_http_only_ops != NULL) {
		nf_forbidden_http_only_ops->hook = (nf_hookfn*)nf_forbidden_http_only_handler;
		nf_forbidden_http_only_ops->hooknum = NF_INET_LOCAL_OUT;
		nf_forbidden_http_only_ops->pf = NFPROTO_IPV4;
		nf_forbidden_http_only_ops->priority = NF_IP_PRI_FIRST + 2;
		nf_register_net_hook(&init_net, nf_forbidden_http_only_ops);
	}
	nf_forbidden_ssh_from_out_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_forbidden_ssh_from_out_ops != NULL) {
		nf_forbidden_ssh_from_out_ops->hook = (nf_hookfn*)nf_forbidden_ssh_from_out_handler;
		nf_forbidden_ssh_from_out_ops->hooknum = NF_INET_LOCAL_OUT;
		nf_forbidden_ssh_from_out_ops->pf = NFPROTO_IPV4;
		nf_forbidden_ssh_from_out_ops->priority = NF_IP_PRI_FIRST + 3;
		nf_register_net_hook(&init_net, nf_forbidden_ssh_from_out_ops);
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
	if (nf_forbidden_http_only_ops  != NULL) {
		nf_unregister_net_hook(&init_net, nf_forbidden_http_only_ops);
		kfree(nf_forbidden_http_only_ops);
	}
	if (nf_forbidden_ssh_from_out_ops  != NULL) {
		nf_unregister_net_hook(&init_net, nf_forbidden_ssh_from_out_ops);
		kfree(nf_forbidden_ssh_from_out_ops);
	}
	printk(KERN_INFO "Exit\n");
}

module_init(nf_minifirewall_init);
module_exit(nf_minifirewall_exit);
MODULE_LICENSE("GPL");
