#include <linux/module.h> //For all modules
#include <linux/kernel.h> //For KERN_INFO
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/moduleparam.h> //Allows cmdl args
#include <linux/init.h>
#include <linux/stat.h>
#define AUTHOR "Garrett Lee <gjlee@ucsb.edu>"
#define DESC "Basic firewall using netfilter framework"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);

static struct nf_hook_ops hk;

static char *ip = 0; //Defaults to None
static int port = 0; //Defaults to None

module_param(ip, charp, 0);
MODULE_PARM_DESC(ip, "IP to be blocked");
module_param(port, int, 0);
MODULE_PARM_DESC(int, "Port to be blocked");

unsigned int inet_addr(char *ip) { 

	int a,b,c,d;
	sscanf(ip,"%d.%d.%d.%d", &a,&b,&c,&d); //Parses for numbers between decimals
	
	char arr[4];
	arr[0] = a;
	arr[1] = b;
	arr[2] = c;
	arr[3] = d;
	return *(unsigned int*)arr; //Returns host byte order of IP addr
}

unsigned int nf_hook_fn(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	 
	struct ethhdr *eth;
	struct iphdr *ip_head;
	struct tcphdr *tcp = NULL;
	eth = (struct ethhdr *)skb_mac_header(skb);
	ip_head = (struct iphdr *)skb_network_header(skb);
	 
	printk(KERN_INFO "Source MAC: %pM, Dest. MAC %pM\n", eth->h_source, eth->h_dest);
	printk(KERN_INFO "Source IP: %pI4\n", &ip_head->saddr);

	if (ip) {

		if (ip_head->saddr==inet_addr(ip)){ //Checks for matching IP address
			printk(KERN_INFO "Rejecting packet with IP: %pI4\n",&ip_head->saddr);
			return NF_DROP; //Drops the packet
		}

		if (ip_head->protocol == IPPROTO_TCP) { //Checks if protocol is TCP
			tcp = (struct tcphdr*)skb_transport_header(skb); //Puts data into a tcp header so we can look at L4 info
		}
	}

	if (port) {

		if (tcp && tcp->dest==port) {
			printk(KERN_INFO "Rejecting packet to port: %d", port);
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

int init_module(void) {

	printk(KERN_INFO "IP received is %s\n", ip);
	printk(KERN_INFO "Port received is %d\n", port);
	 
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

