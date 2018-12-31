#include <linux/kernel.h>
#include "fw.h"
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>  
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>                  
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/in6.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#define CONFIG_NF_DEFRAG_IPV4 1

#define __BIG_ENDIAN_BITFIELD



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arad Inbar");
static struct nf_hook_ops NF_IP_FORWARD_packet_drop;
static struct nf_hook_ops NF_IP_Local_in_packet_drop;
static struct nf_hook_ops NF_IP_Local_out_packet_drop;
static struct nf_hook_ops NF_IP_PRE_ROUTING_packet_drop;
static int major_number;
static int Major3;
static int Major4;
static int Save_port;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;
static struct device* sysfs_device2 = NULL;
static int count_num_of_rules_in_static_table =0;
static int count_num_of_rules_in_connection_table =0;
static int count_num_of_logs=0;
static unsigned int is_fw_active =1;
static int is_table_of_rules_empty=1;
static rule_t * array_of_rules = NULL;
static connection_t * array_of_connection = NULL ;
static int Major;
static struct class*  Fw_log_Class  = NULL; 
static struct device* Fw_log_Device = NULL;
static struct class*  Fw  = NULL; 
static struct device* Fw_conn_tab_Device = NULL;
static struct device* Fw_proxy_conn_Device = NULL;
char * buffer_index;
int leng;


struct Node{
	log_row_t log;
	int log_num ;
	struct Node * next;
};

 struct Log_List{
	 struct Node * Head ;
};

struct Log_List * log_list =NULL;

struct Log_List * make_list()
{
	struct Log_List * lst = NULL ;
	lst = (struct Log_List *) kmalloc(sizeof(struct Log_List),GFP_ATOMIC);
	lst->Head=NULL;
	return lst;
};

struct Node * create_node(log_row_t log , int log_num)
{
	struct Node * newnode =NULL;
	newnode = (struct Node *) kmalloc(sizeof(struct Node),GFP_ATOMIC);
	newnode->log=log;
	newnode->log_num=log_num;
	newnode->next=NULL;
	return newnode;
};

int add_node_to_list(struct Log_List * lst ,struct  Node * newnode)
{
	if (lst->Head==NULL)
	{
		lst->Head=newnode;
		return 1;
	};
	struct Node * temp = NULL;
	temp = lst->Head;
	while (temp->next!=NULL)
		temp=temp->next;
	temp->next=newnode;
	return 1;
};

log_row_t get_log_from_list(int i)
{
	if (log_list!=NULL)
	{
		struct Node * temp = log_list->Head;
		while (temp!=NULL)
		{
			if (temp->log_num==i)
				return temp->log;
			temp=temp->next;
		};
	};
};


int add_count_to_list(int i)
{
	if (log_list!=NULL)
	{
		struct Node * temp = log_list->Head;
		while (temp!=NULL)
		{
			if (temp->log_num==i)
			{
				temp->log.count++;
				return 1;
			};
			temp=temp->next;
		};
	};
	return 0;
};

int update_log_action(int i,log_row_t newlog)
{
	if (log_list!=NULL)
	{
		struct Node * temp = log_list->Head;
		while (temp!=NULL)
		{
			if (temp->log_num==i)
			{
				temp->log.action=newlog.action;
				temp->log.count++;
				return 1;
			};
			temp=temp->next;
		};
	};
	return 0;
};



int my_open(struct inode *_inode, struct file *_file)
{ 
	return 0;
}

char * convert_to_time_str(unsigned long  timestamp1)
{
	char  time_str[30];
	struct tm result;
	rtc_time_to_tm(timestamp1, &result);
	scnprintf(time_str,30,"%04d/%02d/%02d %02d:%02d:%02d",result.tm_year+1900, result.tm_mon + 1, result.tm_mday, result.tm_hour, result.tm_min, result.tm_sec);
	return time_str;
};

char * transalte_Protocol(char prot)
{
	if (prot=='1')
		return "ICMP ";
	if (prot=='6')
		return "TCP ";
	if (prot=='17')
		return "UDP ";
	if (prot=='255')
		return "other ";
	if (prot=='143')
		return "any ";	
};

char * transalte_action(char action)
{
	//printk("comapre %d\n",action==0);
	if (action=='0')
		return "DROP ";
	if (action=='1')
		return "ACCEPT ";
};

char * transalte_reason(int reason)
{
	char  *ret =kmalloc(sizeof(char)*5,GFP_ATOMIC);
	if (reason==-1)
		return "FW_INACTIVE  ";
	if (reason==-2)
		return "NO_MATCHING_RULE ";
	if (reason==-4)
		return "XMAS_PACKET  ";
	if (reason==-6)
		return "ILLEGAL_VALUE ";
	if (reason==-100)
		return "CONNECTION_TABLE ";
	if (reason==-200)
		return "CONNECTION_TABLE ";
	scnprintf(ret,5,"%d",reason);
	return ret; 
};



//save log_row_t struct to a string log.
char * get_log(log_row_t log)
{
	char  time_str[30];
	char * Transalted_log=transalte_reason(log.reason);
	strncpy(time_str,convert_to_time_str(log.timestamp),30);
	char str_log[220];
	scnprintf(str_log,220,"%s %pI4   %pI4  %u     %u         %s     %c     %s     %s   %u\n",time_str,&(log.src_ip),&(log.dst_ip),log.src_port,log.dst_port,transalte_Protocol(log.protocol),log.hooknum,transalte_action(log.action),Transalted_log,log.count); 
	if (Transalted_log==NULL)
		kfree(Transalted_log);
	return str_log;
};



ssize_t my_read(struct file *filp, char *buff, size_t length, loff_t *offp)
{
	int i=0;
	int len = count_num_of_logs*220 ;
	if (count_num_of_logs==0)
		return 0;
	char current_log[220]="";
	char * Tottal_log = (char *) kmalloc(sizeof(char)*count_num_of_logs*220 +1,GFP_ATOMIC);
	strncpy(Tottal_log,"",sizeof(Tottal_log));
	for (i;i<count_num_of_logs;i++)
		strncat(Tottal_log,get_log(get_log_from_list(i)),220);
	copy_to_user(buff,Tottal_log,strlen(Tottal_log));   
	kfree(Tottal_log);    
	return 220*count_num_of_logs;
}


static struct file_operations fops = {
	.owner = THIS_MODULE
};	

static struct file_operations fops2 = {
	.owner = THIS_MODULE,
	.open = my_open,
	.read = my_read
};

int Add_Direction(char * str)
{
	if (strcmp(str,"any")==0)
	{
		array_of_rules[count_num_of_rules_in_static_table-1].direction=DIRECTION_ANY;
		return 1;
	};
	if (strcmp(str,"in")==0)
	{
		array_of_rules[count_num_of_rules_in_static_table-1].direction=DIRECTION_IN;
		return 1;
	};
	if (strcmp(str,"out")==0)
	{
		array_of_rules[count_num_of_rules_in_static_table-1].direction=DIRECTION_OUT;
		return 1;
	};
	return -6;
};

int Add_ip_and_subnet(char * str,	__be32 * IP ,__be32 * prefix_mask,__u8 * prefix_size)
{
	char * ip;
	int res1;
	char temp1[20];
	strncpy(temp1,str,16);
	str=temp1;
	if (strcmp(temp1,"any")!=0)
	{
		ip=strsep(&str,"/");
		if (ip!=NULL)
			*IP = in_aton(ip);
		if (str!=NULL)
		{
			int n = sscanf(str,"%d", &res1);
			if (n==1)
			{
				*prefix_size=res1;
				if (res1==8)
					*prefix_mask = in_aton("255.0.0.0");
				if (res1==16)
					*prefix_mask = in_aton("255.255.0.0");
				if (res1==24)
					*prefix_mask = in_aton("255.255.255.0");
				if (res1==32)
					*prefix_mask = in_aton("255.255.255.255");
			};
		};
		
	}
	else
	{
		ip="0.0.0.0";
		*IP = in_aton(ip);
		*prefix_mask = in_aton("0.0.0.0");
		*prefix_size=0;
	};
	
};

void Add_protocol(char * protocol)
{
	if (strcmp(protocol,"ICMP")==0)
		array_of_rules[count_num_of_rules_in_static_table-1].protocol=PROT_ICMP;
	else if (strcmp(protocol,"TCP")==0)
		array_of_rules[count_num_of_rules_in_static_table-1].protocol=PROT_TCP;
	else if (strcmp(protocol,"UDP")==0)
		array_of_rules[count_num_of_rules_in_static_table-1].protocol=PROT_UDP;
	else if (strcmp(protocol,"any")==0)
		array_of_rules[count_num_of_rules_in_static_table-1].protocol=PROT_ANY;
	else 
		array_of_rules[count_num_of_rules_in_static_table-1].protocol=PROT_OTHER;
};

void Add_port(char * str , __be16 * port)
{
	int res2;
	if (strcmp(str,"any")!=0)
	{
		if (str[0]=='>')
			*port = 1023;
		else
		{
			kstrtoint(str, 10, &res2);
			*port = res2;
		};
	}
	else 	
		*port = 0;
};

void Add_ack(char * Ack_status)
{
	if (strcmp(Ack_status,"yes")==0)
		array_of_rules[count_num_of_rules_in_static_table-1].ack=ACK_YES;
	else if (strcmp(Ack_status,"no")==0)
		array_of_rules[count_num_of_rules_in_static_table-1].ack=ACK_NO;
	else if (strcmp(Ack_status,"any")==0)
		array_of_rules[count_num_of_rules_in_static_table-1].ack=ACK_ANY;
};

void Add_action(char* action)
{
	if (strcmp(action,"accept")==0)
		array_of_rules[count_num_of_rules_in_static_table-1].action=NF_ACCEPT;
	else if (strcmp(action,"drop")==0)
		array_of_rules[count_num_of_rules_in_static_table-1].action=NF_DROP;
};

//parsing a string rule and saving the rule to the array of rules.
int addrule(char * rule)
{
	count_num_of_rules_in_static_table++;
	array_of_rules=(rule_t *) krealloc(array_of_rules,sizeof(rule_t)*count_num_of_rules_in_static_table,GFP_ATOMIC );
	if (!array_of_rules)
		return -1;
	strncpy(array_of_rules[count_num_of_rules_in_static_table-1].rule_name,strsep(&rule," "),sizeof(array_of_rules[count_num_of_rules_in_static_table-1].rule_name));	
	Add_Direction(strsep(&rule," "));
	Add_ip_and_subnet(strsep(&rule," "),&array_of_rules[count_num_of_rules_in_static_table-1].src_ip ,&array_of_rules[count_num_of_rules_in_static_table-1].src_prefix_mask,&array_of_rules[count_num_of_rules_in_static_table-1].src_prefix_size);
	Add_ip_and_subnet(strsep(&rule," "),&array_of_rules[count_num_of_rules_in_static_table-1].dst_ip ,&array_of_rules[count_num_of_rules_in_static_table-1].dst_prefix_mask,&array_of_rules[count_num_of_rules_in_static_table-1].dst_prefix_size);
	Add_protocol(strsep(&rule," "));
	Add_port(strsep(&rule," "),&array_of_rules[count_num_of_rules_in_static_table-1].src_port);
	Add_port(strsep(&rule," "),&array_of_rules[count_num_of_rules_in_static_table-1].dst_port);	
	Add_ack(strsep(&rule," "));
	Add_action(strsep(&rule," "));	
	return 0;
}

void build_table_of_rules(const char * buf)
{
	if (count_num_of_rules_in_static_table!=0)
		return;
	char rule[100];
	int add_rule_result;
	char * line;
	line = strsep(&buf,"\n");
	while (line!=NULL)
	{
		strncpy(rule,line,sizeof(rule));
		if (buf!=NULL)
			add_rule_result=addrule(rule);
		line = strsep(&buf,"\n");
	};
};



//save rule_t struct to a string rule.
char * get_rule(rule_t rule)
{
	char str_rule[100];
	scnprintf(str_rule,100,"%s %u %pI4/%u %pI4/%u %u %u %u %u %u\n",rule.rule_name,rule.direction,&(rule.src_ip),rule.src_prefix_size,&(rule.dst_ip),rule.dst_prefix_size,rule.protocol,rule.src_port,rule.dst_port,rule.ack,rule.action); 
	return str_rule;

};

//returns a string which contains all the rules from the static rule table.
char * get_table_of_rules()
{
	int i=0;
	char rules[MAX_RULES*100]="";
	for (i;i<count_num_of_rules_in_static_table;i++)
		strncat(rules,get_rule(array_of_rules[i]),100);
	return rules;
};

//save connection_t struct to a string.
char * get_connection_rule(connection_t rule)
{
	char str_rule[130];
	char  time_str[30];
	strncpy(time_str,convert_to_time_str(rule.time_of_creation),30);
	scnprintf(str_rule,130," %pI4 %pI4 %u %u %s %s\n",&(rule.src_ip),&(rule.dst_ip),rule.src_port,rule.dst_port,rule.state,time_str); 
	return str_rule;

};


//returns a string which contains all the rules from the static rule table.
char * get_table_of_connetion()
{
	int i=0;
	char conn_rules[MAX_RULES*130]="";
	for (i;i<count_num_of_rules_in_connection_table;i++)
		strncat(conn_rules,get_connection_rule(array_of_connection[i]),130);
	printk(KERN_INFO "conn rules is : %s\n",conn_rules); 
	return conn_rules;
};


__u8 check_for_chrismes_packet(struct tcphdr* tcph)
{
	if ((tcph->psh==1) && (tcph->urg==1) && (tcph->fin))
		return 1;
	return 0;
};

unsigned long get_time_now()
{
	struct timeval time;
	unsigned long local_time;
	do_gettimeofday(&time);
	local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
	return local_time;

};

//save the packets fields into a new struct.
packet_t * get_packet_details(struct iphdr* iph,const struct net_device *in, const struct net_device *out,struct sk_buff *skb)
{
	packet_t * new_packet = (packet_t *) kmalloc(sizeof(packet_t),GFP_ATOMIC);
	new_packet->timestamp=get_time_now();
	strcpy(new_packet->status,"Regular");
	if (in->name == NULL)
	{
		if(strcmp(out->name,IN_NET_DEVICE_NAME)==0 )
			new_packet->direction=DIRECTION_IN;
		else if(strcmp(out->name,OUT_NET_DEVICE_NAME)==0 )
			new_packet->direction=DIRECTION_OUT;
	}
	if (in->name != NULL)
	{	
		if(strcmp(in->name,IN_NET_DEVICE_NAME)==0 )
			new_packet->direction=DIRECTION_IN;
		else if(strcmp(in->name,OUT_NET_DEVICE_NAME)==0 )
			new_packet->direction=DIRECTION_OUT;
	};
	new_packet->src_ip = iph->saddr;
	new_packet->dst_ip = iph->daddr;
	new_packet->protocol= iph->protocol;
	new_packet->is_chrismes=0;
	new_packet->syn=-1;
	new_packet->fin=-1;
	new_packet->rst=-1;
	if ((iph->protocol==IPPROTO_TCP)&&(in->name==NULL))
	{
		skb_linearize(skb);
		struct tcphdr* tcph = (struct tcphdr *) (skb_transport_header(skb));
		new_packet->src_port=ntohs(tcph->source);
		new_packet->dst_port=ntohs(tcph->dest);
		new_packet->ack=tcph->ack + 1;
		new_packet->syn=tcph->syn;
		new_packet->fin=tcph->fin;
		new_packet->rst=tcph->rst;
		new_packet->is_chrismes = check_for_chrismes_packet(tcph);
		
	}
	else if (iph->protocol==IPPROTO_TCP)
	{
		skb_linearize(skb);
		struct tcphdr* tcph = (struct tcphdr *) (skb_transport_header(skb)+20);
		new_packet->src_port=ntohs(tcph->source);
		new_packet->dst_port=ntohs(tcph->dest);
		new_packet->ack=tcph->ack + 1;
		new_packet->syn=tcph->syn;
		new_packet->fin=tcph->fin;
		new_packet->rst=tcph->rst;
		new_packet->is_chrismes = check_for_chrismes_packet(tcph);
		
	}
	else if (iph->protocol==IPPROTO_UDP)
	{
		struct udphdr* udph = udp_hdr(skb);
		new_packet->src_port=ntohs(udph->source);
		new_packet->dst_port=ntohs(udph->dest);
		new_packet->ack=1;
	}
	else
	{
		new_packet->src_port=0;
		new_packet->dst_port=0;
		new_packet->ack=1;
	};
	return new_packet;
};

int does_packet_match_to_static_rule(rule_t rule,packet_t * new_packet)
{
	
	if ((new_packet->direction != rule.direction) && (rule.direction!=DIRECTION_ANY))
		return -1;
	if (((ntohl(new_packet->src_ip) & ntohl(rule.src_prefix_mask) )!= (ntohl(rule.src_ip) & ntohl(rule.src_prefix_mask))) && (rule.src_ip!=in_aton("0.0.0.0")))
		return -1;
	if (((ntohl(new_packet->dst_ip) & ntohl(rule.dst_prefix_mask ))!= (ntohl(rule.dst_ip) & ntohl(rule.dst_prefix_mask))) && (rule.dst_ip!=in_aton("0.0.0.0")))
		return -1;
	if ((new_packet->protocol != rule.protocol) && (rule.protocol!=143))
		return -1;
	if ((new_packet->src_port != rule.src_port) && (rule.src_port!=0))
		return -1;
	if ((new_packet->dst_port != rule.dst_port) && (rule.dst_port!=0))
		return -1;
	if ((new_packet->ack != rule.ack) && (rule.ack!=3))
		return -1;
	return 1; 
};

//search direct match in the connection table.
int search_regular_match(connection_t rule , packet_t * new_packet,int i)
{	
	
	if (new_packet->src_ip != rule.src_ip)
	{
			
		return -1;
	};
	if (new_packet->dst_ip != rule.dst_ip)
	{	
		
		return -1;
	};
	if (new_packet->src_port != rule.src_port)
	{

		return -1;
	};
	if (new_packet->dst_port != rule.dst_port) 
	{	
		
		return -1;	
	};
	return i;
};

//search the other direction match in the connection table.
int search_reversed_match(connection_t rule , packet_t * new_packet,int j)
{	
	
	if (new_packet->src_ip != rule.dst_ip)
		return -1;
	if (new_packet->dst_ip != rule.src_ip)
		return -1;
	if (new_packet->src_port != rule.dst_port)
		return -1;
	if (new_packet->dst_port != rule.src_port) 
		return -1;	
	return j;
};	
		
		
int Add_rule_to_connection_table(int rule_number, packet_t * new_packet)
{
	//check if we are illegal packet or chrismes packet. 
	if ((rule_number < 0) && (rule_number != -2))
		return -1;
	//check if the rule is found and passed at the static table.
	if (rule_number != -2)
	{	
		if (array_of_rules[rule_number].action == NF_DROP)
			return -1;
	};
	//if its not a new packet we dont add it to the connection table.
	if (new_packet->syn!=1)
		return -1;
	//passed all checks , adding new rule.
	count_num_of_rules_in_connection_table++;
	array_of_connection=(connection_t *) krealloc(array_of_connection,sizeof(connection_t)*count_num_of_rules_in_connection_table,GFP_ATOMIC );
	if (!array_of_connection)
		return -1;
	array_of_connection[count_num_of_rules_in_connection_table-1].src_ip = new_packet->src_ip;
	array_of_connection[count_num_of_rules_in_connection_table-1].dst_ip = new_packet->dst_ip;
	array_of_connection[count_num_of_rules_in_connection_table-1].src_port = new_packet->src_port;
	array_of_connection[count_num_of_rules_in_connection_table-1].dst_port = new_packet->dst_port;
	memset(array_of_connection[count_num_of_rules_in_connection_table-1].state,'\0',sizeof(array_of_connection[count_num_of_rules_in_connection_table-1].state));
	char temp[20];
	if ((new_packet->syn==1) && (new_packet->ack==1))
		strcpy(array_of_connection[count_num_of_rules_in_connection_table-1].state,"Syn sent");
	else if ((new_packet->syn==1) && (new_packet->ack==2))
		strcpy(array_of_connection[count_num_of_rules_in_connection_table-1].state,"Syn-ack sent");
	array_of_connection[count_num_of_rules_in_connection_table-1].time_of_creation=get_time_now();
	printk("%u\n",array_of_connection[count_num_of_rules_in_connection_table-1].time_of_creation);
	return 1;
}; 

//scan the static rule table for a match.
int Find_match_in_static_table(packet_t * new_packet)
{
	if (is_fw_active==0)
		return -1;
	if (new_packet->is_chrismes==1)
		return -4;
	int i=0;
	int rule_num_match_to_packet;
	for (i;i<count_num_of_rules_in_static_table;i++)
	{
		rule_num_match_to_packet=does_packet_match_to_static_rule(array_of_rules[i],new_packet);
		if (rule_num_match_to_packet==1)
			return i;
	}
	return -2;
};

int  policy_enforcer(int rule_num)
{
	//rule found in the static rule table.
	if (rule_num > -1 )
		return array_of_rules[rule_num].action;	
	//firewall is inactive.
	if (rule_num == -1)	
		return NF_ACCEPT;
	//no matching rule in the static rule table.
	if (rule_num == -2)	
		return NF_ACCEPT;	
	//chrismes packet detects.
	if (rule_num == -4)
		return NF_DROP;	
	//aprooved by the connction table.
	if( rule_num == -100)
		return NF_ACCEPT;
	//not aprooved by the connction table.
	if (rule_num == -200)
		return NF_DROP;
};

int logcmp(log_row_t log1 , log_row_t log2)
{
	if (log1.protocol!=log2.protocol)
		return -1;
	if (log1.src_ip!=log2.src_ip)
		return -1;
	if (log1.dst_ip!=log2.dst_ip)
		return -1;
	if (log1.src_port!=log2.src_port)
		return -1;
	if (log1.dst_port!=log2.dst_port)
		return -1;
	if (log1.hooknum!=log2.hooknum)
		return -1;
	if (log1.action!=log2.action)
		return -1;
	if (log1.reason!=log2.reason)
		return -1;
	return 0;
};
	
int log_search(log_row_t  newlog)
{
	int i=0;
	if (log_list==NULL)
		return -1;
	for (i;i<count_num_of_logs;i++)
	{
		int log_cmp_result=logcmp(get_log_from_list(i),newlog);
		if (log_cmp_result==0)
		{
			add_count_to_list(i);
			return 1;
		};
		if (log_cmp_result==-2)
		{
			//update_log_action(i,newlog);
			return 2;
		};
	};
	return 0;
};
			

void Add_to_log_list(packet_t * new_packet ,struct sk_buff * skb , int action, unsigned int hooknum,int rule_num)
{
		
		log_row_t newlog;
		newlog.timestamp=new_packet->timestamp;
		scnprintf(&newlog.protocol,4,"%u",new_packet->protocol);
		scnprintf(&newlog.action,4,"%u",action);
		scnprintf(&newlog.hooknum,4,"%u",hooknum);
		newlog.src_ip=new_packet->src_ip;
		newlog.dst_ip=new_packet->dst_ip;
		newlog.src_port=new_packet->src_port;
		newlog.dst_port=new_packet->dst_port;
		newlog.reason=rule_num;
		int search_log=log_search(newlog);
		if (search_log!=1)
		{
			newlog.count=1;
			count_num_of_logs++;
			struct Node * newnode = create_node(newlog,count_num_of_logs-1);
			if (log_list==NULL)
			{
				log_list = make_list();
				add_node_to_list(log_list,newnode);
				return;
			};
			add_node_to_list(log_list,newnode);
		};	
          
};
	
void clear_table_of_rules()
{
	count_num_of_rules_in_static_table=0;
	if (array_of_rules!=NULL)
		array_of_rules=(rule_t *) krealloc(array_of_rules,0,GFP_ATOMIC );
};

int clear_list_of_logs()
{
	count_num_of_logs=0;
	if (log_list==NULL)
		return 0;
	struct Node * current1 = NULL;
	struct Node * next1 = NULL;
	current1 = log_list->Head;
	next1= log_list->Head;
	while (current1!=NULL)
	{
		next1=current1->next;
		kfree(current1);
		current1=next1;
	};
	log_list->Head = NULL;
	return 1;
};
	

int check_for_local_ip(struct iphdr* iph)
{
	if ((ntohl(iph->saddr) & ntohl(in_aton("255.0.0.0")) == 127 ) && (ntohl(iph->daddr) & ntohl(in_aton("255.0.0.0")) == 127 ) )
		return 1;
	return 0;
};

char * table_chooser(packet_t * new_packet)
{
	if (new_packet->protocol!=PROT_TCP)
		return "static_table";
	//ACK_NO in our reprsentaion is 1. 
	if (new_packet->ack==1)
		return "static_table";
	if (new_packet->syn==1)
		return "static_table";
	return "connection_table";
};

int delete_rules_from_connection_table()
{
	int i;
	int count=0;
	int index=0;
	
	//first marking the rules do delete if the timeout passed.
	for (i=0;i<count_num_of_rules_in_connection_table;i++)
	{
		if (strcmp(array_of_connection[i].state,"delete")==0)
			count++;
			
		else if ((get_time_now() - array_of_connection[i].time_of_creation > 25) &&  ( (strstr(array_of_connection[i].state,"Syn")!=NULL)))
		{
			count++;
			strcpy(array_of_connection[i].state,"delete");
		}
		
		else if ((get_time_now() - array_of_connection[i].time_of_creation > 60) &&  ( (strstr(array_of_connection[i].state,"fin")!=NULL)))
		{
			count++;
			strcpy(array_of_connection[i].state,"delete");
		};
		
		
	};
	
	if (count==0)
		return 0;
		
	connection_t * temp= (connection_t *) kmalloc(sizeof(connection_t)*(count_num_of_rules_in_connection_table-count),GFP_ATOMIC );
	for (i=0; i<count_num_of_rules_in_connection_table;i++)
	{
		if (strcmp(array_of_connection[i].state,"delete")!=0)
		{
			temp[index]=array_of_connection[i];
			index++;
		};
	};	
	array_of_connection=(connection_t *) krealloc(array_of_connection,0,GFP_ATOMIC );
	array_of_connection=temp;
	count_num_of_rules_in_connection_table-=count;
	return 1;
};


//check which action should be done according to the connection table and modify if needed.
int get_and_modify_connection_table(int i , int j,packet_t * new_packet)
{
	//rules not found
	if ((i<0) || (j<0))
		return -200;
	if (new_packet->fin==1)
	{
			printk(KERN_INFO "before everything i %s\n",array_of_connection[i].state);
			printk(KERN_INFO "before everything j %s\n",array_of_connection[j].state);
	};	
	//if rst flag detected we close the connection.
	if (new_packet->rst ==1)
	{
		strcpy(array_of_connection[i].state,"delete");
		strcpy(array_of_connection[j].state,"delete");
		delete_rules_from_connection_table();
		return -100;
	};	
	
	//this packet is the third packet in the 3-way handshake.
	if ((strcmp(array_of_connection[i].state,"Syn sent")==0) && (strcmp(array_of_connection[j].state,"Syn-ack sent")==0))
	{
		strcpy(array_of_connection[i].state,"Established");
		strcpy(array_of_connection[j].state,"Established");
		return -100;
	};
	// if the connection is Established we shell aprove the packet.
	if ((strcmp(array_of_connection[i].state,"Established")==0) && (strcmp(array_of_connection[j].state,"Established")==0))
	{
		//from Established state when we getting the fin flag, we start closing the connection.
		if (new_packet->fin==1)
			strcpy(array_of_connection[i].state,"Fin sent");
		else if (strcmp(new_packet->status,"Regular")!=0)
		{
			printk(KERN_INFO "%s\n",new_packet->status);
			strcpy(array_of_connection[i].state,new_packet->status);
		}
		return -100;
	};
	
	// if the connection is Block by the proxy we change the state according to the packet.
	if ((strcmp(array_of_connection[i].state,"proxy_http_block")==0) && (strcmp(array_of_connection[j].state,"Established")==0))
	{
		// if the connection is Block by the proxy and we get fin - we start closing the connection.
		if (new_packet->fin==1)
		{
			strcpy(array_of_connection[i].state,"Fin sent");
			return -100;
		};
		 if (strcmp(new_packet->status,"Regular")==0)
			strcpy(array_of_connection[i].state,"Established");

		return -100;
	};
	
	// if the connection is Block by the proxy we change the state according to the packet.
	if ((strcmp(array_of_connection[i].state,"proxy_ftp_block")==0) && (strcmp(array_of_connection[j].state,"Established")==0))
	{
		// if the connection is Block by the proxy and we get fin - we start closing the connection.
		if (new_packet->fin==1)
		{
			strcpy(array_of_connection[i].state,"Fin sent");
			return -100;
		};
		 if (strcmp(new_packet->status,"Regular")==0)
			strcpy(array_of_connection[i].state,"Established");

		return -100;
	};
	
	if ((strcmp(array_of_connection[i].state,"Established")==0) &&(strcmp(array_of_connection[j].state,"proxy_http_block")==0))
	{
		// if the connection is Block by the proxy and we get fin - we start closing the connection.
		if (new_packet->fin==1)
			strcpy(array_of_connection[i].state,"Fin sent");
			return -100;
	};
	
	if ((strcmp(array_of_connection[i].state,"Established")==0) &&(strcmp(array_of_connection[j].state,"proxy_ftp_block")==0))
	{
		// if the connection is Block by the proxy and we get fin - we start closing the connection.
		if (new_packet->fin==1)
			strcpy(array_of_connection[i].state,"Fin sent");
			return -100;
	};
	
	if ((strcmp(array_of_connection[i].state,"Established")==0) && (strcmp(array_of_connection[j].state,"Fin sent")==0))
	{
		
		//from Established state when we getting the fin flag, we start closing the connection.
		if (new_packet->fin==1)
			strcpy(array_of_connection[i].state,"Fin-ack sent");
		return -100;

	};	
	
	if ((strcmp(array_of_connection[i].state,"proxy_http_block")==0) && (strcmp(array_of_connection[j].state,"Fin sent")==0))
	{
		//from Established state when we getting the fin flag, we start closing the connection.
		if (new_packet->fin==1)
			strcpy(array_of_connection[i].state,"Fin-ack sent");
		return -100;
	};	
	
	if ((strcmp(array_of_connection[i].state,"proxy_ftp_block")==0) && (strcmp(array_of_connection[j].state,"Fin sent")==0))
	{
		//from Established state when we getting the fin flag, we start closing the connection.
		if (new_packet->fin==1)
			strcpy(array_of_connection[i].state,"Fin-ack sent");
		return -100;
	};	
		
	
	//we need to close the connection - this this the last part of the fin-ack handshake.
	if ((strcmp(array_of_connection[i].state,"Fin sent")==0) && (strcmp(array_of_connection[j].state,"Fin-ack sent")==0))
	{
			if (new_packet->fin==0)
			{
				strcpy(array_of_connection[i].state,"delete");
				strcpy(array_of_connection[j].state,"delete");
				delete_rules_from_connection_table();
				return -100;
			};
	};
	//we need to close the connection - this this the last part of the fin-ack handshake.
	if ((strcmp(array_of_connection[i].state,"Fin-ack sent")==0) && (strcmp(array_of_connection[j].state,"Fin sent")==0))
	{
			if (new_packet->fin==0)
			{
				strcpy(array_of_connection[i].state,"delete");
				strcpy(array_of_connection[j].state,"delete");
				delete_rules_from_connection_table();
				return -100;
			};
	};					
		
	if ((strcmp(array_of_connection[i].state,"Established")!=0) && (strcmp(array_of_connection[j].state,"Established")==0))
	{

		if (strcmp(new_packet->status,"Regular")!=0)
		{
			strcpy(array_of_connection[i].state,new_packet->status);
		}
		if (new_packet->fin==1)
		{
			printk(KERN_INFO "what i need %s\n",array_of_connection[i].state);
			strcpy(array_of_connection[i].state,"Fin sent");
			return -100;
		};
			
	};
		
	if ((strcmp(array_of_connection[i].state,"Established")!=0) && (strcmp(array_of_connection[j].state,"Fin sent")==0))
	{

		if (new_packet->fin==1)
		{
			strcpy(array_of_connection[i].state,"Fin-ack sent");
			return -100;
		};
			
	};	
			
		
	if (new_packet->fin==1)
	{
			strcpy(array_of_connection[i].state,"Fin sent");
			
	};		
	return -100;
};
	

	
	
int Find_match_in_connection_table(packet_t * new_packet)
{
	if (is_fw_active==0)
		return -1;
	if (new_packet->is_chrismes==1)
		return -4;
	int i=0;
	int j=0;
	int rgeular_rule_match=-1;
	int reserved_rule_match=-1;
	//search for match in the connection table.
	for (i;i<count_num_of_rules_in_connection_table;i++)
	{	
		if (search_regular_match(array_of_connection[i],new_packet,i)>-1)
		{
			rgeular_rule_match =i;
			break;
		};
	};
	//search for match for the other side of the connection in the connection table.
	for (j;j<count_num_of_rules_in_connection_table;j++)
	{	
		if (search_reversed_match(array_of_connection[j],new_packet,j)>-1)
		{
			reserved_rule_match =j;
			break;
		};
	};
	
	//check which action to do according to the findings.
	return get_and_modify_connection_table(rgeular_rule_match,reserved_rule_match,new_packet);
};

//scannig for a match between new packet to rule at the connection table;
int scan_connection_table(packet_t * NEW_packet)
{
	int i;
	int match_num=-1;
	for (i=0;i<count_num_of_rules_in_connection_table;i++)
	{	
		if (search_regular_match(array_of_connection[i],NEW_packet,i)>-1)
		{
			match_num =i;
			break;
		};
	};
	return match_num;
};

//scannig for a match between new packet to the opposit direction rule at the connection table;
int scan_reversed_connection_table(packet_t * NEW_packet)
{
	int i;
	int match_num=-1;
	for (i=0;i<count_num_of_rules_in_connection_table;i++)
	{	
		if (search_reversed_match(array_of_connection[i],NEW_packet,i)>-1)
		{
			match_num =i;
			break;
		};
	};
	return match_num;
};



unsigned int hook_func_forward(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,
			const struct net_device *out,int (*okfn)(struct sk_buff *))
{
	int rule_num_match_to_packet;
	int action;
	char * which_table;
	int add_connection_rule;
	struct iphdr* iph = ip_hdr(skb);
	
	if (check_for_local_ip(iph)==1)
		return NF_ACCEPT;
	packet_t * New_Packet =  get_packet_details(iph,in,out,skb);
	//decide where to route the packet - the static or connection table.
	which_table = table_chooser(New_Packet);
	
	if (strcmp(which_table,"static_table")==0)
	{
		rule_num_match_to_packet = Find_match_in_static_table(New_Packet);
		//for new Tcp connection we need to add new connection to the connection table if we passed the static rule table.
		if (New_Packet->syn==1) 
		{
			//adding new packet to the connection table only if is not exists yet.
			if (scan_connection_table(New_Packet)==-1)
				Add_rule_to_connection_table(rule_num_match_to_packet,New_Packet);
		};
	};	
	if (strcmp(which_table,"connection_table")==0)
	{
		//elimnating timed-out rules from connection table.
		delete_rules_from_connection_table();
		rule_num_match_to_packet = Find_match_in_connection_table(New_Packet);
	};
	action =  policy_enforcer(rule_num_match_to_packet);
	Add_to_log_list(New_Packet,skb,action,hooknum,rule_num_match_to_packet);
	return action;	
}

//compute ip_checksum
static unsigned short compute_checksum(unsigned short *addr, unsigned int count) 
{
	register unsigned long sum = 0;
	while (count > 1)
	{
		sum += * addr++;
		count -= 2;
	}
    //if any bytes left, pad the bytes and add
   if(count > 0)
   {
		sum += ((*addr)&htons(0xFF00));
   }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16)
  {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
};

/* set tcp checksum: given IP header and tcp segment */
void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload)
{
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header 
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
}

//scann the connection table and return tupple of ip and source - for masking the proxy.
source_tuple * return_source_tuple_proxy_to_client(__be32 dst_ip2,__be16 dst_port2)
{	
	source_tuple * ret = (source_tuple *) kmalloc(sizeof(source_tuple),GFP_ATOMIC );
	int i;
	for (i=0;i<count_num_of_rules_in_connection_table;i++)
	{	
		if ((dst_ip2 == array_of_connection[i].src_ip) && (dst_port2 == array_of_connection[i].src_port)) 
		{
			ret->src_ip=array_of_connection[i].dst_ip;
			ret->src_port=array_of_connection[i].dst_port;		
			
			return ret;
		};	
	};
	return NULL;
};

//scann the connection table and return tupple of ip and source - for masking the proxy.
source_tuple * return_source_tuple_proxy_to_server(__be32 dst_ip2,__be16 dst_port2)
{	
	source_tuple * ret = (source_tuple *) kmalloc(sizeof(source_tuple),GFP_ATOMIC );
	int i;
	for (i=0;i<count_num_of_rules_in_connection_table;i++)
	{	
		if ((dst_ip2 == array_of_connection[i].dst_ip) && (dst_port2 == array_of_connection[i].dst_port)) 
		{
			ret->src_ip=array_of_connection[i].src_ip;
			ret->src_port=array_of_connection[i].src_port;		
			return ret;
		};	
	};
	return NULL;
};

unsigned int hook_func_local_out(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,
			const struct net_device *out,int (*okfn)(struct sk_buff *))
{
	unsigned char * payloadData=0;
	int offset;
	int len;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	int tcplen;
	if (!skb)
		return NF_ACCEPT;
	ip_header = (struct iphdr *)skb_network_header(skb);
	if (!ip_header)
		return NF_ACCEPT;
	if (ip_header->protocol != 6) //non TCP packet
	{
		return NF_ACCEPT;
	}
	tcp_header = (struct tcphdr *)(skb_transport_header(skb)); 
	if (!tcp_header)
		return NF_ACCEPT;
		
	if ((tcp_header->source == htons(10001)) || (tcp_header->source == htons(10003))) //http packet
	{	
		//changing of routing
		source_tuple * ret ;
		
		ret = return_source_tuple_proxy_to_client((ip_header->daddr),htons(tcp_header->dest));
		if (ret==NULL)
		{
			
			return NF_ACCEPT;
		}
		ip_header->saddr = (ret->src_ip);
		tcp_header->source =  htons(ret->src_port);
       // correct the IP checksum

		ip_header->check = 0;
		ip_send_check (ip_header);

		//correct the TCP checksum
	
		offset = skb_transport_offset(skb);
		len = skb->len - offset;
		tcp_header->check = 0;
		tcp_header->check  = ~csum_tcpudp_magic((ip_header->saddr), (ip_header->daddr), len, IPPROTO_TCP, 0);
		int rule_num_match_to_packet;
		int action;
		char * which_table;
		int add_connection_rule;
		packet_t * New_Packet =  get_packet_details(ip_header,in,out,skb);
		//decide where to route the packet - the static or connection table.
		which_table = table_chooser(New_Packet);
		
		if (strcmp(which_table,"static_table")==0)
		{
			rule_num_match_to_packet = Find_match_in_static_table(New_Packet);
			//for new Tcp connection we need to add new connection to the connection table if we passed the static rule table.
			if (New_Packet->syn==1) 
			{
			//adding new packet to the connection table only if is not exists yet.
			if (scan_connection_table(New_Packet)==-1)
				Add_rule_to_connection_table(rule_num_match_to_packet,New_Packet);
			};
		};	
		if (strcmp(which_table,"connection_table")==0)
		{
			//elimnating timed-out rules from connection table.
			delete_rules_from_connection_table();
			rule_num_match_to_packet = Find_match_in_connection_table(New_Packet);
		};
		action =  policy_enforcer(rule_num_match_to_packet);
		Add_to_log_list(New_Packet,skb,action,hooknum,rule_num_match_to_packet); 
		
		return NF_ACCEPT;
	}

	if ((tcp_header->dest == htons(80)) || (tcp_header->dest == htons(21))) //http packet
	{	
		
		//changing of routing
		source_tuple * ret ;
		ret = return_source_tuple_proxy_to_server((ip_header->daddr),htons(tcp_header->dest));
		if (ret==NULL)
			return NF_ACCEPT;
		ip_header->saddr = (ret->src_ip);
		tcp_header->source =  htons(ret->src_port);
       // correct the IP checksum

		ip_header->check = 0;
		ip_send_check (ip_header);

		//correct the TCP checksum
	
		offset = skb_transport_offset(skb);
		len = skb->len - offset;
		tcp_header->check = 0;
		tcp_header->check  = ~csum_tcpudp_magic((ip_header->saddr), (ip_header->daddr), len, IPPROTO_TCP, 0);	
		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}
	


unsigned int hook_func_local_in(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,
			const struct net_device *out,int (*okfn)(struct sk_buff *))
{
	return NF_ACCEPT;
}

//for http and ftp we redirecting the packets to the usper space for deep pcket inspection.
unsigned int hook_func_pre_routing(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,
			const struct net_device *out,int (*okfn)(struct sk_buff *))
{
	unsigned char * payloadData=0;
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	int tcplen;
	if (!skb)
		return NF_ACCEPT;
	ip_header = (struct iphdr *)skb_network_header(skb);
	if (!ip_header)
		return NF_ACCEPT;
	if (ip_header->protocol != 6) //non TCP packet
	{
		return NF_ACCEPT;
	}
	tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20); //for incoming packets use +20
	if (!tcp_header)
		return NF_ACCEPT;
	
	if ((tcp_header->dest == htons(80)) || (tcp_header->dest == htons(21)) || (tcp_header->source == htons(20)))  //http or ftp  packet from the client side
	{
		int rule_num_match_to_packet;
		int action;
		char * which_table;
		int add_connection_rule;
		struct iphdr* iph = ip_hdr(skb);
		packet_t * New_Packet =  get_packet_details(iph,in,out,skb);
		//decide where to route the packet - the static or connection table.
		which_table = table_chooser(New_Packet);
		if (strcmp(which_table,"static_table")==0)
		{
			rule_num_match_to_packet = Find_match_in_static_table(New_Packet);
			//for new Tcp connection we need to add new connection to the connection table if we passed the static rule table.
			if (New_Packet->syn==1) 
			{
			//adding new packet to the connection table only if is not exists yet.
			if (scan_connection_table(New_Packet)==-1)
				Add_rule_to_connection_table(rule_num_match_to_packet,New_Packet);
			};
		};	
		if (strcmp(which_table,"connection_table")==0)
		{
			//elimnating timed-out rules from connection table.
			delete_rules_from_connection_table();
			rule_num_match_to_packet = Find_match_in_connection_table(New_Packet);
		};
		action =  policy_enforcer(rule_num_match_to_packet);
		Add_to_log_list(New_Packet,skb,action,hooknum,rule_num_match_to_packet);
		ip_header->daddr = in_aton("10.0.1.3");
		tcp_header->dest = htons(10001);//proxy lisetning to http on port 10001
		if (tcp_header->source == htons(20)) 
			tcp_header->dest = htons(10003);//proxy lisetning to http on port 10001
		tcplen = (skb->len - ((ip_header->ihl )<< 2));
        tcp_header->check=0;
        tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,csum_partial((char*)tcp_header, tcplen,0));
        skb->ip_summed = CHECKSUM_NONE; //stop offloading
        ip_header->check = 0;
        ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
		
		return NF_ACCEPT;
	};
	if ((tcp_header->source == htons(80)) || (tcp_header->source == htons(21)) )  //http or ftp  packet from the client side
	{

		struct iphdr* iph = ip_hdr(skb);
		ip_header->daddr = in_aton("10.0.2.3");
		tcp_header->dest = htons(10002);
		//if (tcp_header->source == htons(20))
		//	tcp_header->dest = htons(10003);
		tcplen = (skb->len - ((ip_header->ihl )<< 2));
        tcp_header->check=0;
        tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,csum_partial((char*)tcp_header, tcplen,0));
        skb->ip_summed = CHECKSUM_NONE; //stop offloading
        ip_header->check = 0;
        ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
		return NF_ACCEPT;
	};
	
	return NF_ACCEPT;
	
}



ssize_t active_display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u",is_fw_active);
}

ssize_t active_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	if ((strcmp(buf,"0")==0) || (strcmp(buf,"0")==1))
		 kstrtoint(buf,10,&is_fw_active); 
	return count;	
}

ssize_t rules_size_display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u",count_num_of_rules_in_static_table);
}



ssize_t log_size_display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE, "%u",count_num_of_logs);
}


ssize_t log_clear_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	if (strcmp(buf,"clear_log")==0)
		clear_list_of_logs();
	return count;	
}

ssize_t conn_tab_display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	delete_rules_from_connection_table();
	return scnprintf(buf, PAGE_SIZE,"%s",  get_table_of_connetion());
}

ssize_t rules_table_display(struct device *dev, struct device_attribute *attr, char *buf)	//sysfs show implementation
{
	return scnprintf(buf, PAGE_SIZE,"%s",  get_table_of_rules());
}

ssize_t rules_table_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{
	if (strcmp(buf,"clear_rules")==0)
		clear_table_of_rules();
	else
	{
		build_table_of_rules(buf);
	};
	return count;	

};

ssize_t proxy_conn_modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)	//sysfs store implementation
{


		int reg;
		int rev;
		int res2;
		unsigned int res3;
		packet_t * new_packet = (packet_t *) kmalloc(sizeof(packet_t),GFP_ATOMIC);
		char * temp;
		temp=strsep(&buf," ");
		new_packet->src_ip=in_aton(strsep(&buf," "));
		new_packet->dst_ip=in_aton(strsep(&buf," "));
		kstrtoint(strsep(&buf," "), 10, &res2);
		res3=res2;
		new_packet->src_port=(res3);
		kstrtoint(strsep(&buf," "), 10, &res2);
		res3=res2;
		new_packet->dst_port=(res3);
		strcpy(new_packet->status,strsep(&buf," "));
		new_packet->is_chrismes=0;
		new_packet->syn=-2;
		new_packet->fin=-2;
		new_packet->rst=-2;
		reg=scan_connection_table(new_packet);
		rev=scan_reversed_connection_table(new_packet);
		get_and_modify_connection_table(reg,rev,new_packet);
		return count;	

};

//The attribute for the  sysfs attribute - active
static DEVICE_ATTR(active, S_IRWXO , active_display,active_modify);

//The attribute for the  sysfs attribute - rules_size
static DEVICE_ATTR(rules_size, S_IROTH , rules_size_display, NULL);

//The attribute for the  sysfs attribute - rules_table
static DEVICE_ATTR(rules_table, S_IRWXO , rules_table_display, rules_table_modify);

//The attribute for the  sysfs attribute - log_size
static DEVICE_ATTR(log_size, S_IROTH , log_size_display, NULL);

//The attribute for the  sysfs attribute - log_clear
static DEVICE_ATTR(log_clear, S_IWOTH , NULL, log_clear_modify);

//The attribute for the  sysfs attribute - conn_tab
static DEVICE_ATTR(conn_tab, S_IROTH , conn_tab_display, NULL);

//The attribute for the  sysfs attribute - proxy_conn
static DEVICE_ATTR(proxy_conn, S_IWOTH , NULL, proxy_conn_modify);


int init_module(void)
{
	//create forward hook
	NF_IP_FORWARD_packet_drop.hook = hook_func_forward;
	NF_IP_FORWARD_packet_drop.hooknum = 2;
	NF_IP_FORWARD_packet_drop.pf = PF_INET;
	NF_IP_FORWARD_packet_drop.priority = NF_IP_PRI_CONNTRACK_CONFIRM ;
	nf_register_hook(&NF_IP_FORWARD_packet_drop);
	
	//create local out hook
	NF_IP_Local_out_packet_drop.hook = hook_func_local_out;
	NF_IP_Local_out_packet_drop.hooknum = 3;
	NF_IP_Local_out_packet_drop.pf = PF_INET;
	NF_IP_Local_out_packet_drop.priority = NF_IP_PRI_CONNTRACK_CONFIRM ;
	nf_register_hook(&NF_IP_Local_out_packet_drop);
	
	//create local in hook
	NF_IP_Local_in_packet_drop.hook = hook_func_local_in;
	NF_IP_Local_in_packet_drop.hooknum = 1;
	NF_IP_Local_in_packet_drop.pf = PF_INET;
	NF_IP_Local_in_packet_drop.priority = NF_IP_PRI_CONNTRACK_CONFIRM ;
	nf_register_hook(&NF_IP_Local_in_packet_drop);
	
	//create pre routing hook
	NF_IP_PRE_ROUTING_packet_drop.hook = hook_func_pre_routing;
	NF_IP_PRE_ROUTING_packet_drop.hooknum = 0;
	NF_IP_PRE_ROUTING_packet_drop.pf = PF_INET;
	NF_IP_PRE_ROUTING_packet_drop.priority = NF_IP_PRI_CONNTRACK_CONFIRM;
	nf_register_hook(&NF_IP_PRE_ROUTING_packet_drop);
	


	//create the fw char device
	major_number = register_chrdev(0, "fw_rules", &fops);
	if (major_number < 0)
		return -1;
		
		
	//create sysfs class
	sysfs_class = class_create(THIS_MODULE, "fw");
	if (IS_ERR(sysfs_class))
	{
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}
	
	//create the sysfs device - fw_rules
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "fw_rules");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}

	
	//create The log char device
    Major = register_chrdev(0, "fw_log", &fops2);
	if (Major < 0) 
	{
	  printk(KERN_ALERT "Registering log char device failed with %d\n", Major);
	  return Major;
	}
	

   // Register the log device driver
   Fw_log_Device = device_create(sysfs_class, NULL, MKDEV(Major, 0), NULL, "fw_log");
   if (IS_ERR(Fw_log_Device))
   {               
      class_destroy(sysfs_class);           
      unregister_chrdev(Major, "fw_log");
      return PTR_ERR(Fw_log_Device);
   }
   
   	//create The conn_tab device
    Major3 = register_chrdev(0, "fw", &fops);
	if (Major3 < 0) 
	{
	  printk(KERN_ALERT "Registering conn_tab device failed with %d\n", Major3);
	  return Major3;
	}
	

   // Register the conn_tab device driver
   Fw_conn_tab_Device = device_create(sysfs_class, NULL, MKDEV(Major3, 0), NULL, "fw");
   if (IS_ERR(Fw_conn_tab_Device))
   {               
      class_destroy(sysfs_class);           
      unregister_chrdev(Major3, "fw");
      return PTR_ERR(Fw_conn_tab_Device);
   }
   


	
	//create sysfs file attribute for the first attribute - active
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_active.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}
	
	
	//create sysfs file attribute for the second attribute - rules_size 	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules_size.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}
	
	//create sysfs file attribute for the third attribute - rules_table 	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules_table .attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_rules");
		return -1;
	}
	

   //create sysfs file attribute for the  attribute - log size
   if (device_create_file(Fw_log_Device, (const struct device_attribute *)&dev_attr_log_size.attr))
   {
	   device_destroy(sysfs_class, MKDEV(major_number, 0));
	   class_destroy(sysfs_class);
	   unregister_chrdev(Major, "fw_log");
	   return -1;
   }
	
	
   //create sysfs file attribute for the  attribute - log clear
   if (device_create_file(Fw_log_Device, (const struct device_attribute *)&dev_attr_log_clear.attr))
   {
	   device_destroy(sysfs_class, MKDEV(major_number, 0));
	   class_destroy(sysfs_class);
	   unregister_chrdev(Major, "fw_log");
	   return -1;
   }
	
  //create sysfs file attribute for the  attribute - conn_tab
   if (device_create_file(Fw_conn_tab_Device, (const struct device_attribute *)&dev_attr_conn_tab.attr))
   {
	   device_destroy(sysfs_class, MKDEV(Major3, 0));
	   class_destroy(sysfs_class);
	   unregister_chrdev(Major3, "fw");
	   return -1;
   }
   
   //create sysfs file attribute for the  attribute - proxy_conn
   if (device_create_file(Fw_conn_tab_Device, (const struct device_attribute *)&dev_attr_proxy_conn.attr))
   {
	   device_destroy(sysfs_class, MKDEV(Major3, 0));
	   class_destroy(sysfs_class);
	   unregister_chrdev(Major3, "fw");
	   return -1;
   }
   
	return 0;
}

void cleanup_module(void)
{
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_active.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules_size.attr);
	device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules_table.attr);
	device_remove_file(Fw_log_Device, (const struct device_attribute *)&dev_attr_log_size.attr);
	device_remove_file(Fw_log_Device, (const struct device_attribute *)&dev_attr_log_clear.attr);
	device_remove_file(Fw_log_Device, (const struct device_attribute *)&dev_attr_conn_tab.attr);
	device_remove_file(Fw_log_Device, (const struct device_attribute *)&dev_attr_proxy_conn.attr);
	device_destroy(sysfs_class, MKDEV(major_number, 0));
	device_destroy(sysfs_class, MKDEV(Major, 0));
	device_destroy(sysfs_class, MKDEV(Major3, 0));           
	class_destroy(sysfs_class);
	unregister_chrdev(major_number, "fw_rules");	
	unregister_chrdev(Major,"fw_log");
	unregister_chrdev(Major3,"fw");
	nf_unregister_hook(&NF_IP_FORWARD_packet_drop);
	nf_unregister_hook(&NF_IP_Local_out_packet_drop);
	nf_unregister_hook(&NF_IP_Local_in_packet_drop); 
	nf_unregister_hook(&NF_IP_PRE_ROUTING_packet_drop); 

}


