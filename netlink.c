#include <net/netlink.h>
#include <net/genetlink.h>

#include "netlink.h"
#include "tls.h"

int nl_fail(struct sk_buff* skb, struct genl_info* info);
int daemon_cb(struct sk_buff* skb, struct genl_info* info);
int daemon_data_cb(struct sk_buff* skb, struct genl_info* info);

static const struct nla_policy ssa_nl_policy[SSA_NL_A_MAX + 1] = {
        [SSA_NL_A_UNSPEC] = { .type = NLA_UNSPEC },
	[SSA_NL_A_ID] = { .type = NLA_UNSPEC },
        [SSA_NL_A_SOCKADDR_INTERNAL] = { .type = NLA_UNSPEC },
        [SSA_NL_A_SOCKADDR_EXTERNAL] = { .type = NLA_UNSPEC },
	[SSA_NL_A_SOCKADDR_REMOTE] = { .type = NLA_UNSPEC },
	[SSA_NL_A_OPTLEVEL] = { .type = NLA_UNSPEC },
	[SSA_NL_A_OPTNAME] = { .type = NLA_UNSPEC },
	[SSA_NL_A_OPTVAL] = { .type = NLA_UNSPEC },
	[SSA_NL_A_RETURN] = { .type = NLA_UNSPEC },
};

static struct genl_ops ssa_nl_ops[] = {
        {
                .cmd = SSA_NL_C_SOCKET_NOTIFY,
                .flags = GENL_ADMIN_PERM,
                .policy = ssa_nl_policy,
                .doit = nl_fail,
                .dumpit = NULL,
        },
        {
                .cmd = SSA_NL_C_SETSOCKOPT_NOTIFY,
                .flags = GENL_ADMIN_PERM,
                .policy = ssa_nl_policy,
                .doit = nl_fail,
                .dumpit = NULL,
        },
        {
                .cmd = SSA_NL_C_GETSOCKOPT_NOTIFY,
                .flags = GENL_ADMIN_PERM,
                .policy = ssa_nl_policy,
                .doit = nl_fail,
                .dumpit = NULL,
        },
        {
                .cmd = SSA_NL_C_BIND_NOTIFY,
                .flags = GENL_ADMIN_PERM,
                .policy = ssa_nl_policy,
                .doit = nl_fail,
                .dumpit = NULL,
        },
        {
                .cmd = SSA_NL_C_CONNECT_NOTIFY,
                .flags = GENL_ADMIN_PERM,
                .policy = ssa_nl_policy,
                .doit = nl_fail,
                .dumpit = NULL,
        },
        {
                .cmd = SSA_NL_C_LISTEN_NOTIFY,
                .flags = GENL_ADMIN_PERM,
                .policy = ssa_nl_policy,
                .doit = nl_fail,
                .dumpit = NULL,
        },
        {
                .cmd = SSA_NL_C_CLOSE_NOTIFY,
                .flags = GENL_ADMIN_PERM,
                .policy = ssa_nl_policy,
                .doit = nl_fail,
                .dumpit = NULL,
        },
        {
                .cmd = SSA_NL_C_RETURN,
                .flags = GENL_ADMIN_PERM,
                .policy = ssa_nl_policy,
                .doit = daemon_cb,
                .dumpit = NULL,
        },
        {
                .cmd = SSA_NL_C_DATA_RETURN,
                .flags = GENL_ADMIN_PERM,
                .policy = ssa_nl_policy,
                .doit = daemon_data_cb,
                .dumpit = NULL,
        },
        {
                .cmd = SSA_NL_C_UPGRADE_NOTIFY,
                .flags = GENL_ADMIN_PERM,
                .policy = ssa_nl_policy,
                .doit = nl_fail,
                .dumpit = NULL,
        },
};

static const struct genl_multicast_group ssa_nl_grps[] = {
        [SSA_NL_NOTIFY] = { .name = "notify", },
};

static struct genl_family ssa_nl_family = {
        .module = THIS_MODULE,
        .ops = ssa_nl_ops,
        .n_ops = ARRAY_SIZE(ssa_nl_ops),
        .mcgrps = ssa_nl_grps,
        .n_mcgrps = ARRAY_SIZE(ssa_nl_grps),
        .hdrsize = 0,
        .name = "SSA",
        .version = 1,
        .maxattr = SSA_NL_A_MAX,
};

int nl_fail(struct sk_buff* skb, struct genl_info* info) {
        printk(KERN_ALERT "Kernel receieved an SSA netlink notification. This should never happen.\n");
        return -1;
}
 
int daemon_cb(struct sk_buff* skb, struct genl_info* info) {
	struct nlattr* na;
	unsigned long key;
	int response;
	if (info == NULL) {
		printk(KERN_ALERT "Netlink: Message info is null\n");
		return -1;
	}
	if ((na = info->attrs[SSA_NL_A_ID]) == NULL) {
		printk(KERN_ALERT "Netlink: Unable to retrieve socket ID\n");
		return -1;
	}
	key = nla_get_u64(na);
	if ((na = info->attrs[SSA_NL_A_RETURN]) == NULL) {
		printk(KERN_ALERT "Netlink: Unable to get return value\n");
	}
	response = nla_get_u32(na);
	report_return(key, response);
        return 0;
}

int daemon_data_cb(struct sk_buff* skb, struct genl_info* info) {
	struct nlattr* na;
	unsigned long key;
	unsigned int len;
	char* data;
	if (info == NULL) {
		printk(KERN_ALERT "Netlink: Message info is null\n");
		return -1;
	}
	if ((na = info->attrs[SSA_NL_A_ID]) == NULL) {
		printk(KERN_ALERT "Netlink: Unable to retrieve socket ID\n");
		return -1;
	}
	key = nla_get_u64(na);
	if ((na = info->attrs[SSA_NL_A_OPTVAL]) == NULL) {
		printk(KERN_ALERT "Netlink: Unable to get optval from data message\n");
		return -1;
	}
	data = nla_data(na);
	len = nla_len(na);
	report_data_return(key, data, len);
        return 0;
}

int register_netlink() {
	return genl_register_family(&ssa_nl_family);
}

void unregister_netlink() {
	genl_unregister_family(&ssa_nl_family);
	return;
}

int send_socket_notification(unsigned long id) {
	struct sk_buff* skb;
	int ret;
	void* msg_head;

	skb = genlmsg_new(32, GFP_KERNEL);
	if (skb == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_new [socket notify]\n");
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_SOCKET_NOTIFY);
	if (msg_head == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_put [socket notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (id) [socket notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	ret = genlmsg_multicast(&ssa_nl_family, skb, 0, SSA_NL_NOTIFY, GFP_KERNEL);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in gemlmsg_multicast [socket notify] (%d)\n", ret);
	}
	return 0;
}

int send_setsockopt_notification(unsigned long id, int level, int optname, void* optval, int optlen) {
	struct sk_buff* skb;
	int ret;
	void* msg_head;

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_new [setsockopt notify]\n");
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_SETSOCKOPT_NOTIFY);
	if (msg_head == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_put [setsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (id) [setsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_OPTLEVEL, sizeof(int), &level);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (level) [setsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_OPTNAME, sizeof(int), &optname);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (optname) [setsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_OPTVAL, optlen, optval);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (optval) [setsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	ret = genlmsg_multicast(&ssa_nl_family, skb, 0, SSA_NL_NOTIFY, GFP_KERNEL);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in gemlmsg_multicast [setsockopt notify] (%d)\n", ret);
	}
	return 0;
}

int send_getsockopt_notification(unsigned long id, int level, int optname) {
	struct sk_buff* skb;
	int ret;
	void* msg_head;

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_new [getsockopt notify]\n");
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_GETSOCKOPT_NOTIFY);
	if (msg_head == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_put [getsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (id) [getsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_OPTLEVEL, sizeof(int), &level);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (level) [getsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_OPTNAME, sizeof(int), &optname);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (optname) [getsockopt notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	ret = genlmsg_multicast(&ssa_nl_family, skb, 0, SSA_NL_NOTIFY, GFP_KERNEL);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in gemlmsg_multicast [getsockopt notify] (%d)\n", ret);
	}
	return 0;
}

int send_bind_notification(unsigned long id, struct sockaddr* int_addr, struct sockaddr* ext_addr) {
	struct sk_buff* skb;
	int ret;
	void* msg_head;

	skb = genlmsg_new(64, GFP_KERNEL);
	if (skb == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_new [bind notify]\n");
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_BIND_NOTIFY);
	if (msg_head == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_put [bind notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (id) [bind notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_SOCKADDR_INTERNAL, sizeof(struct sockaddr), int_addr);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (internal) [bind notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_SOCKADDR_EXTERNAL, sizeof(struct sockaddr), ext_addr);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (external) [bind notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	ret = genlmsg_multicast(&ssa_nl_family, skb, 0, SSA_NL_NOTIFY, GFP_KERNEL);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in gemlmsg_multicast [bind notify] (%d)\n", ret);
	}
	return 0;
}

int send_connect_notification(unsigned long id, struct sockaddr* int_addr, struct sockaddr* rem_addr) {
	struct sk_buff* skb;
	int ret;
	void* msg_head;

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_new [connect notify]\n");
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_CONNECT_NOTIFY);
	if (msg_head == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_put [connect notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (id) [connect notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_SOCKADDR_INTERNAL, sizeof(struct sockaddr), int_addr);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (internal) [connect notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_SOCKADDR_REMOTE, sizeof(struct sockaddr), rem_addr);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (remote) [connect notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	ret = genlmsg_multicast(&ssa_nl_family, skb, 0, SSA_NL_NOTIFY, GFP_KERNEL);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in gemlmsg_multicast [connect notify]\n (%d)", ret);
	}
	return 0;
}

int send_listen_notification(unsigned long id, struct sockaddr* int_addr, struct sockaddr* ext_addr) {
	struct sk_buff* skb;
	int ret;
	void* msg_head;

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_new [listen notify]\n");
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_LISTEN_NOTIFY);
	if (msg_head == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_put [listen notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (id) [listen notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_SOCKADDR_INTERNAL, sizeof(struct sockaddr), int_addr);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (internal) [listen notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_SOCKADDR_EXTERNAL, sizeof(struct sockaddr), ext_addr);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (external) [listen notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	ret = genlmsg_multicast(&ssa_nl_family, skb, 0, SSA_NL_NOTIFY, GFP_KERNEL);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in gemlmsg_multicast [listen notify] (%d)\n", ret);
	}
	return 0;
}

int send_close_notification(unsigned long id) {
	struct sk_buff* skb;
	int ret;
	void* msg_head;

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (skb == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_new [close notify]\n");
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_CLOSE_NOTIFY);
	if (msg_head == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_put [close notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (id) [close notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	ret = genlmsg_multicast(&ssa_nl_family, skb, 0, SSA_NL_NOTIFY, GFP_ATOMIC);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in gemlmsg_multicast [close notify] (%d)\n", ret);
		
	}
	return 0;
}

int send_upgrade_notification(unsigned long id, struct sockaddr* src_addr) {
	struct sk_buff* skb;
	int ret;
	void* msg_head;

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_new [upgrade notify]\n");
		return -1;
	}
	msg_head = genlmsg_put(skb, 0, 0, &ssa_nl_family, 0, SSA_NL_C_UPGRADE_NOTIFY);
	if (msg_head == NULL) {
		printk(KERN_ALERT "Failed in genlmsg_put [upgrade notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_ID, sizeof(id), &id);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (id) [upgrade notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	ret = nla_put(skb, SSA_NL_A_SOCKADDR_INTERNAL, sizeof(struct sockaddr), src_addr);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in nla_put (internal) [upgrade notify]\n");
		nlmsg_free(skb);
		return -1;
	}
	genlmsg_end(skb, msg_head);
	ret = genlmsg_multicast(&ssa_nl_family, skb, 0, SSA_NL_NOTIFY, GFP_KERNEL);
	if (ret != 0) {
		printk(KERN_ALERT "Failed in gemlmsg_multicast [upgrade notify]\n (%d)", ret);
	}
	return 0;
}

