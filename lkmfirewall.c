#include <linux/module.h> //For all modules
#include <linux/kernel.h> //For KERN_INFO
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#define AUTHOR "Garrett Lee <gjlee@ucsb.edu>"
#define DESC "Basic firewall using netfilter framework"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);

static struct nf_hook_ops hk;

unsigned int nf_hook_ex(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	return NF_DROP;
}

int init_module(void) {
	hk = (struct nf_hook_ops) {
		.hook = nf_hook_ex,
		.hooknum = NF_INET_PRE_ROUTING,
		.pf = PF_INET,
		.priority = NF_IP_PRI_FIRST
	};
	nf_register_hook(&hk);


	return 0; // return status, tells if module is loaded
}

void cleanup_module(void) {
	nf_unregister_hook(&hk); //disconnect our func handler
}

