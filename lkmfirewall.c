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
static char *ip = "127.0.0.1";

module_param(option, charp, 0);
MODULE_PARM_DESC(option, "Designates whether an ip or port is to be blocked");
module_param(ip, charp, 0);
MODULE_PARM_DESC(ip, "IP to be blocked");

unsigned int nf_hook_ex(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	printk(KERN_INFO "Packet dropped\n");
	return NF_DROP;
}

int init_module(void) {
	printk(KERN_INFO "Option received is %s\n", option);
	printk(KERN_INFO "IP received is %s\n", ip);
	hk = (struct nf_hook_ops) {
		.hook = nf_hook_ex,
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

