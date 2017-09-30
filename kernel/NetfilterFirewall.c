#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <net/sock.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/if_arp.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/if_ether.h>

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/netfilter_bridge.h>

// const variables  define
#define CDEV_NAME "NetfilterFirewall"
#define CLASS_NAME "fp"
#ifndef __FW_INCLUDE__
#define __FW_INCLUDE__

// log file, don't change, it seems I can't use LOG_FILE_PATH,
// but use /var/log/myfilter in my code
#define LOG_FILE_PATH "/var/log/myfilter";

// actions defined
#define FW_ADD_RULE 0
#define FW_DEL_RULE 1
#define FW_CLEAR_RULE 2

// filter rules struct define
typedef struct Node{
  unsigned int sip;
  unsigned int dip;
  unsigned short sport;
  unsigned short dport;
  unsigned short protocol;
  unsigned short sMask;
  unsigned short dMask;
  bool isPermit;
  bool isLog;
  struct Node *next;          //单链表的指针域
}Node,*NodePointer;

#endif

// module message
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fengpeng");
MODULE_DESCRIPTION("My char driver");
MODULE_VERSION("1.0.0");

// file_operations options, device operation
static long netfilter_cdev_ioctl( struct file *file, unsigned int cmd, unsigned long arg);
static int netfilter_cdev_open(struct inode *inode, struct file *file);
static int netfilter_cdev_release(struct inode *inode, struct file *file);

// define rules control funcitons
void addRule(struct Node *newnode);
void deleteRule(struct Node *);
void clearRule(void);

// list operation functions
void initList(void);
int findNodeFilterMatch(Node *tnode);

// ip string to number, number to string...maybe I should use standard fanction
unsigned int get_uint_ip_addr(char *str);
char *get_string_ip_addr(unsigned int ip, char *sp, unsigned int len);

// get protocol string
char *getProtocolString(unsigned int protocol, char *sp, unsigned short len);
char *getPortString(unsigned short port, char *sp, unsigned short len);

// write a log
void  writeLog(Node *packageNode,Node *ruleNode);

/* variable define */
static int major_number;
// static struct class*  cdevClass  = NULL;    // 设备驱动类结构体指针
// static struct device* cdevDevice = NULL;    // 设备驱动设备结构体指针
static NodePointer lheader,ltail; // rule list header pointer and tail pointer, lheader->next is the first node, not lheader
static struct cdev netfilter_cdev;

// hook function
unsigned int hook_func(unsigned int hooknum,
               struct sk_buff *skb,
               const struct net_device *in,
               const struct net_device *out,
               int (*okfn)(struct sk_buff *));

// 字符设备选项拿出需要的字段并且绑定相应的操作函数
struct file_operations netfilter_cdev_fops = {
  .owner = THIS_MODULE,
  .unlocked_ioctl = netfilter_cdev_ioctl, // before 2.6 is .ioctl
  .open = netfilter_cdev_open,
  .release = netfilter_cdev_release
};

// hook函数选项设置
struct nf_hook_ops hook_options_entry = {
  .hook = hook_func,
  .hooknum = NF_INET_PRE_ROUTING ,
  .owner = THIS_MODULE,
  .pf = PF_INET,
  .priority = NF_IP_PRI_FIRST
};

struct nf_hook_ops hook_options_out = {
  .hook = hook_func,
  .hooknum = NF_INET_POST_ROUTING ,
  .owner = THIS_MODULE,
  .pf = PF_INET,
  .priority = NF_IP_PRI_FIRST
};

/* 字符设备操作函数,cmd is a number */

// 打开设备0
static int netfilter_cdev_open(struct inode *inode, struct file *file)  {
  printk(KERN_INFO "prompt: Device has been opened!");
  return 0;
}

// 设备释放
static int netfilter_cdev_release(struct inode *inode, struct file *file)  {
  printk(KERN_INFO "prompt: Closed!\n");
  return 0;
}

// ioctrl
static long netfilter_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)  {
  long ret = 0;
  Node tnode;
  copy_from_user(&tnode,(struct Node *)arg, sizeof(struct Node));
  switch(cmd) {
    case FW_ADD_RULE:
      // printk("\n------\nconnect and transport message test----\nsip:%d",tnode.sip);
      // printk("dip:%u",tnode.dip);
      // printk("sport:%u",tnode.sport);
      // printk("dport:%u",tnode.dport);
      // printk("protocol:%u",tnode.protocol);
      // printk("sMask:%u",tnode.sMask);
      // printk("dMask:%u",tnode.dMask);
      // printk("isPermit:%d",tnode.isPermit);
      // printk("isLog:%d",tnode.isLog);
      // add a rule
      // printk("Get command FW_ADD_RULE");
      printk("\nGet command FW_ADD_RULE!\n");
      addRule(&tnode);
      break;
    case FW_DEL_RULE:
      printk("\nGet command FW_DEL_RULE\n");
      deleteRule(&tnode);
      break;
    case FW_CLEAR_RULE:
      printk("\nGet command FW_CLEAR_RULE\n");
      clearRule();
    default:
      // nothing
      break;
  }

  return ret;
}

/*
 * hook函数，也就是包判断分发处理函数
 */
/*
 * hook函数，也就是包判断分发处理函数
 */
unsigned int hook_func(unsigned int hooknum,
               struct sk_buff *skb,
               const struct net_device *in,
               const struct net_device *out,
               int (*okfn)(struct sk_buff *)) {

  printk("\nIn the hook function.");
  unsigned int ret = NF_ACCEPT; // default policy

  // struct ethhdr *eth = ethhdr(skb);
  struct iphdr *iph = ip_hdr(skb);

  // set a node, just need to define ip,port and protocol
  if(!skb || !iph) {
     return ret;
  }

  // checked if is a ip packet
  // if(eth->h_proto != htons(ETH_P_IP)) {
  //     printk("Not a IP packet.");
  //     return ret;
  // }

  // check ip version
  if(iph->version != 4) {
      printk("Not IPv4.");
      return ret;
  }

  Node tnode = {0,0,0,0,0,0,0,false,false,NULL};

  // get ip
  tnode.sip = iph->saddr;
  tnode.dip = iph->daddr;

  // get protocol and port
  tnode.protocol = 0;
  struct tcphdr *tcph; // Transport header
  struct udphdr *udph;
  switch(iph->protocol) {
    case IPPROTO_TCP:
      tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));
      tnode.sport = ntohs(tcph->source);
      tnode.dport = ntohs(tcph->dest);
      tnode.protocol = IPPROTO_TCP;
      break;
    case IPPROTO_UDP:
      udph = (struct udphdr *)(skb->data + (iph->ihl * 4));
      tnode.sport = ntohs(udph->source);
      tnode.dport = ntohs(udph->dest);
      tnode.protocol = IPPROTO_UDP;
      break;

    case IPPROTO_ICMP:

      tnode.protocol = IPPROTO_ICMP;
      tnode.sport = 0;
      tnode.dport = 0;
      break;
    default:
        //
        break;
  }

  // not tcp or udp protocol
  if(tnode.protocol != IPPROTO_TCP && tnode.protocol != IPPROTO_UDP && tnode.protocol != IPPROTO_ICMP){
    return ret;
  }

  // filter, try to find one
  int index = findNodeFilterMatch(&tnode);
  if(index < 0) { // not found, means use default rule NF_ACCEPT;
    return ret;
  } else {
    printk("find a rule");
  }
  // after test ,it is ok to find a rule! 

  // after test, the next section has something wrong, cause the computer dump
  // seems unbelieveable, it seems not problem!
  /* judge if permit */
  printk("before for");
  Node *p = lheader;
  int i = 0;
  for(i = 0; i <= index; i++) {
    p = p->next;
  }

  printk("after for");

  if(!p->isPermit) {
    ret = NF_DROP;
  }

  /* judge if need to write a log, we need node p,that why findNodeFilterMatch return index but not bool */
  if(p->isLog) {
      writeLog(&tnode,p);
  }

  return ret;
}

/*
 * write a log
 */
void writeLog(Node *packageNode,Node *ruleNode) {
   struct file *file = NULL;
   char buf[500];
   int len = 0;

   // log file open, why can't use LOG_FILE_NAME ?
   file = filp_open("/var/log/myfilter",O_RDWR | O_APPEND | O_CREAT,0644);
   if(IS_ERR(file)){
      printk("Error while openning the log file \"/var/log/myfilter\".");
      return;
   }

   /* write time */
   struct timex  txc;
   struct rtc_time tm;
   do_gettimeofday(&(txc.time));
   rtc_time_to_tm(txc.time.tv_sec,&tm);
   sprintf(buf,"UTC time :%d-%d-%d %d:%d:%d ",tm.tm_year+1900,tm.tm_mon, tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec);

   // get package message
   // get ip as string
   char sip[20],dip[20];
   get_string_ip_addr(packageNode->sip,sip,20);
   get_string_ip_addr(packageNode->dip,dip,20);

   // get port as string
   char sport[10],dport[10];
   getPortString(packageNode->sport,sport,10);
   getPortString(packageNode->dport,dport,10);

   // get protocol string
   char protocol[15];
   getProtocolString(packageNode->protocol,protocol,15);

   len = strlen(buf);
   sprintf(buf + len,"package(sip,dip,sport,dport,protocol):%s,%s,%d,%d,%s",sip,dip,packageNode->sport,packageNode->dport,protocol);

   /* get match rule message */
   get_string_ip_addr(ruleNode->sip,sip,20);
   get_string_ip_addr(ruleNode->dip,dip,20);
   getPortString(ruleNode->sport,sport,10);
   getPortString(ruleNode->dport,dport,10);
   getProtocolString(ruleNode->protocol,protocol,15);

   char filterAction[20];
   if(ruleNode->isPermit) {
       sprintf(filterAction,"actions:%s","Permit!");
   } else {
       sprintf(filterAction,"actions:%s","Reject!");
   }

   len = strlen(buf);
   sprintf(buf + len,"\nfilter rule(sip,dip,sport,dport,protocol):%s,%s,%s,%s,%s  %s\n\n\0",sip,dip,sport,dport,protocol,filterAction);

   /* write log message */
   mm_segment_t old_fs = get_fs();
   set_fs(KERNEL_DS);
   file->f_op->write(file, buf, strlen(buf), &file->f_pos);
   set_fs(old_fs);
   filp_close(file, NULL);
   file = NULL;
   printk("Successful write a log!");
   return;
}

/*
 * function: get protocol string
 * para: protocol, return value save addr pointer, str max len.
 */
// string ip to unsigned ip number
unsigned int get_uint_ip_addr(char *str) {
    int a,b,c,d;
    char arr[4];
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return *(unsigned int*)arr;
}

// unsigned int ip number to string
char *get_string_ip_addr(unsigned int ip,char *sp,unsigned int len) {
    char buf[len];
    unsigned t = 0x000000ff;

    if(ip == 0) { // ANY
      sprintf(buf,"%s","ANY");
    } else {
      sprintf(buf,"%d.%d.%d.%d",ip & t,(ip >> 8) & t,(ip >> 16) & t,(ip >> 24) & t);
    }
    strncpy(sp,buf,len);
    return sp;
}

// unsigned short port to string
char *getPortString(unsigned short port, char *sp, unsigned short len) {
    char buf[len];

    if(port == 0) {
        sprintf(buf,"%s","ANY");
    } else {
        sprintf(buf,"%d",port);
    }

    strncpy(sp,buf,len);
    return sp;
}

char *getProtocolString(unsigned int protocol, char *sp, unsigned short len) {
    switch(protocol) {
        case IPPROTO_TCP:
           strncpy(sp,"IPPROTO_TCP",len);
           break;
        case IPPROTO_UDP:
           strncpy(sp,"IPPROTO_UDP",len);
           break;
           
        case IPPROTO_ICMP:
            strncpy(sp,"IPPROTO_ICMP",len);
           break;
           
        default:
            // NOTHING TO DO
          break;
    }
    return sp;
}

/*** rules operation,node operation is not complete the same as rule operation ***/
/*
 * add a rule in the rule list
 */
void  addRule(Node *newnode){
    Node *t;
    t = (Node *)kmalloc(sizeof(Node),0);
    memcpy(t,newnode,sizeof(struct Node));
    t->next = NULL;

  if(lheader->next == NULL && ltail->next == NULL) {
    lheader->next = t;
    ltail->next = t;
  } else {
    ltail->next->next = t;
    ltail->next = t;
  }
}

/*
 * delete a rule
 */
void  deleteRule(Node *tnode){
    // not any node, just return
    if(lheader->next == NULL && ltail->next == NULL) {
        return;
    }

    Node *p = lheader;
    Node *pre = p;
    bool finded = false;
    while(p && p->next != NULL){
      pre = p;
      p = p->next;

      // compare 9 element, one not equal, continue to next
      if(p->sip != tnode->sip || p->dip != tnode->dip) {
        continue;
      }

      if(p->sport != tnode->sport || p->dport != tnode->dport) {
        continue;
      }

      if(p->protocol != tnode->protocol) {
        continue;
      }

      if(p->sMask != tnode->sMask || p->dMask != tnode->dMask) {
        continue;
      }

      if(p->isLog != tnode->isLog || p->isPermit != tnode->isPermit) {
        continue;
      }

      // notice one delete
      printk("delete notice: sip:%d,dip:%d,sport:%d,dport:%d,protocol:%d",p->sip,p->dip,p->sport,p->dport,p->protocol);
      printk("sMask:%d,dMask:%d,isPermit:%s,isLog:%s\n",p->sMask,p->dMask,p->isPermit ? "true" : false,p->isLog ? "true" : "false");
      finded = true;
      break;
    }

    if(!finded) {
      return;
    }

    // p is the first one
    if(pre->next == lheader->next) {
      lheader->next = NULL;
      ltail->next = NULL;
    } else if(ltail->next == pre->next) { // the last one, and not the first one
      ltail->next = pre;
      pre->next = NULL;
    } else { // not the first or the last
      pre->next = p->next;
    }

    kfree(p);
}

/*
 * clear rules
 */
void  clearRule(void) {
    Node *p = lheader;
    Node *t = NULL;
    while(p && p->next != NULL){
        p = p->next;
        t = p->next;
        kfree(p);

        p = t;
    }
    lheader->next = NULL;
    ltail->next = NULL;
}

// init rule list
void initList(void) {
  lheader = (Node *)kmalloc(sizeof(Node),0);   //申请头结点空间
  ltail = (Node *)kmalloc(sizeof(Node),0);
  lheader->next = NULL;
  ltail = lheader;
}

/*
 * judge if match one rule while filter a package
 */
int findNodeFilterMatch(Node *tnode){

  Node *p = lheader;
  // rule node
  unsigned int sip,dip;
  unsigned short sport,dport;
  unsigned short smask,dmask;

  // get tnode element
  unsigned int tsip = tnode->sip,tdip = tnode->dip;
  unsigned short tsport = tnode->sport,tdport = tnode->dport;
  unsigned short tprotocol = tnode->protocol;

  int counter = -1;
  bool finded = false;
  unsigned int t1 = 0,t2 = 0;

  // find a match rule and the permit flag is deny,
  // if not found, return NF_ACCEPT.
  while(p->next != NULL) {

      p = p->next;
      counter++;
      finded = false;
      // checked sip
      sip = p->sip;
      dip = p->dip;
      smask = p->sMask;
      dmask = p->dMask;
      sport = p->sport;
      dport = p->dport;

    t1 = (sip >> (32 - smask)) << (32 - smask);
    t2 = (tsip >> (32 - smask)) << (32 - smask);
    if(tsip != sip && sip != 0 && (smask <= 0 || (smask > 0 && (t2 & t1) != t1))) { // not equal, not ANY,is subnetmask but not include
       continue;
    }

    // dip judge
    t1 = (dip >> (32 - dmask)) << (32 -dmask);
    t2 = (tdip >> (32 - dmask)) << (32 - dmask);
    if(tdip != dip && dip != 0 && (dmask <= 0 || (dmask > 0 && (t2 & t1) != t1))) {
       continue;
    }

    // check protocol
    if(tprotocol != p->protocol && p->protocol != 0) {
      continue;
    }

    // if is ICMP, not need to check port
    if(tprotocol == IPPROTO_ICMP) {
      finded = true;
      break;
    }

    // check sport
    if(tsport != sport && sport != 0) { // not equal, not ANY
       continue;
    }

    // check dport
    if(tdport != dport && dport !=0 ){
       continue;
    }

    // pass 5 items check
    finded = true;
    break;
  }

  return finded ? counter : -1;
}

/*
 * dev init, 
 */
static int __init my_netfilter_init(void) {

  int ret,err;
  dev_t devno,devno_m;

  ret = alloc_chrdev_region(&devno,0,1,"NetfilterFirewall");
  if(ret < 0) {
    return ret;
  }
  major_number = MAJOR(devno);

  devno_m = MKDEV(major_number,0);
  cdev_init(&netfilter_cdev,&netfilter_cdev_fops);
  // netfilter_cdev.ops = &netfilter_cdev_fops;

  err = cdev_add(&netfilter_cdev,devno_m,1);
  if(err != 0) {
    printk("Error in cdev_add.");
  }

  nf_register_hook(&hook_options_entry);
  nf_register_hook(&hook_options_out);
  initList();

  printk(KERN_INFO "prompt: Aha! Register successful! \nMain Device Number is %d\n", major_number);
  return 0;
}
  // major_number =  register_chrdev(0, CDEV_NAME, &netfilter_cdev_fops);
  // if(major_number < 0) {
  //   printk(KERN_ALERT "prompt: Too sad! Failed to register the device.\n");
  //   return major_number;
  // }

  // // 注册设备驱动
  // cdevDevice = device_create(cdevClass, NULL, MKDEV(major_number, 0), NULL, CDEV_NAME);
  // if (IS_ERR(cdevDevice)){               // 如果有错误，清理环境
  //   class_destroy(cdevClass);
  //   unregister_chrdev(major_number, CDEV_NAME);
  //   printk(KERN_ALERT "Crying!Failed to create device.\n");
  //   return PTR_ERR(cdevDevice);
  // }

  // nf_register_hook(&hook_options_entry);
  // ng_register_hook(&hook_options_out);
  // // init rule list
  // initList();

  // printk(KERN_INFO "prompt: Aha! Register successful! \nMain Device Number is %d\n", major_number);
  // return 0;


/*
 * dev clear.
 */
static void __exit my_netfilter_exit(void) {

  nf_unregister_hook(&hook_options_entry);
  nf_unregister_hook(&hook_options_out);
  cdev_del(&netfilter_cdev);
  unregister_chrdev_region(MKDEV(major_number,0),1);
  printk(KERN_INFO "prompt: WOW! exit!\n");
  // unregister_chrdev(major_number, CDEV_NAME);            // 注销主设备号
  // device_destroy(cdevClass, MKDEV(major_number, 0));      // 移除设备
  // class_unregister(cdevClass);                            // 注销设备类
  // class_destroy(cdevClass);
  // nf_unregister_hook(&hook_options_entry);
  // nf_unregister_hook(&hook_options_out)
  // cdev_del(&netfilter_cdev);
  // printk(KERN_INFO "prompt: WOW! exit!\n");
}

module_init(my_netfilter_init); // insmod module
module_exit(my_netfilter_exit); // rmmod module