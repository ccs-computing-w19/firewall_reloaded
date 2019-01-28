#include <linux/module.h> //For all modules
#include <linux/kernel.h> //For KERN_INFO
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/moduleparam.h> //Allows cmdl args
#include <linux/init.h>
#include <linux/stat.h>
#define AUTHOR "Garrett Lee <gjlee@ucsb.edu>"
#define DESC "Basic firewall using netfilter framework"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);

static struct nf_hook_ops hk;

static char *option = "a"; 
static char *ip = "8.8.8.8";

module_param(option, charp, 0);
MODULE_PARM_DESC(option, "Designates whether an ip or port is to be blocked");
module_param(ip, charp, 0);
MODULE_PARM_DESC(ip, "IP to be blocked");

unsigned int inet_addr(char *ip) {
	int a,b,c,d;
	sscanf(ip,"%d.%d.%d.%d", &a,&b,&c,&d);
	char arr[4];
	arr[0] = a;
	arr[1] = b;
	arr[2] = c;
	arr[3] = d;
	return *(unsigned int*)arr;
}

unsigned int nf_hook_fn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct ethhdr *eth;
	struct iphdr *ip_head;
	eth = (struct ethhdr *)skb_mac_header(skb);
	ip_head = (struct iphdr *)skb_network_header(skb);
	printk(KERN_INFO "Source MAC: %pM, Dest. MAC %pM\n", eth->h_source, eth->h_dest);
	printk(KERN_INFO "Source IP: %pI4\n", &ip_head->saddr);
	if (ip_head->saddr==inet_addr(ip)){ //inet_addr converts from dotted decimal form to host byte order
		printk(KERN_INFO "Rejecting packet with IP: %pI4\n",&ip_head->saddr);
		return NF_DROP;
	}
	return NF_ACCEPT;
}

int init_module(void) {
	printk(KERN_INFO "Option received is %s\n", option);
	printk(KERN_INFO "IP received is %s\n", ip);
	hk = (struct nf_hook_ops) {
		.hook = nf_hook_fn,
		.hooknum = NF_INET_PRE_ROUTING,
		.pf = PF_INET,
		.priority = NF_IP_PRI_FIRST
	};
	nf_register_net_hook(&init_net,&hk);

	return 0; // return status, tells if module is loaded
}

void cleanup_module(void) {
	nf_unregister_net_hook(&init_net, &hk); //disconnect our func handler
}

