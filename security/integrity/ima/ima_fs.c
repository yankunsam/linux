/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 *
 * Authors:
 * Kylene Hall <kjhall@us.ibm.com>
 * Reiner Sailer <sailer@us.ibm.com>
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_fs.c
 *	implemenents security file system for reporting
 *	current measurement list and IMA statistics
 */
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/parser.h>
#include <linux/vmalloc.h>
#include <linux/proc_ns.h>
#include <linux/radix-tree.h>

#include "ima.h"

static DEFINE_MUTEX(ima_write_mutex);

bool ima_canonical_fmt;
static int __init default_canonical_fmt_setup(char *str)
{
#ifdef __BIG_ENDIAN
	ima_canonical_fmt = 1;
#endif
	return 1;
}
__setup("ima_canonical_fmt", default_canonical_fmt_setup);

static int valid_policy = 1;
#define TMPBUFLEN 12
static ssize_t ima_show_htable_value(char __user *buf, size_t count,
				     loff_t *ppos, atomic_long_t *val)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t len;

	len = scnprintf(tmpbuf, TMPBUFLEN, "%li\n", atomic_long_read(val));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, len);
}

static ssize_t ima_show_htable_violations(struct file *filp,
					  char __user *buf,
					  size_t count, loff_t *ppos)
{
	return ima_show_htable_value(buf, count, ppos, &ima_htable.violations);
}

static const struct file_operations ima_htable_violations_ops = {
	.read = ima_show_htable_violations,
	.llseek = generic_file_llseek,
};

static ssize_t ima_show_measurements_count(struct file *filp,
					   char __user *buf,
					   size_t count, loff_t *ppos)
{
	return ima_show_htable_value(buf, count, ppos, &ima_htable.len);

}

static const struct file_operations ima_measurements_count_ops = {
	.read = ima_show_measurements_count,
	.llseek = generic_file_llseek,
};

/* returns pointer to hlist_node */
static void *ima_measurements_start(struct seq_file *m, loff_t *pos)
{
	loff_t l = *pos;
	struct ima_queue_entry *qe;

	/* we need a lock since pos could point beyond last element */
	rcu_read_lock();
	list_for_each_entry_rcu(qe, &ima_measurements, later) {
		if (!l--) {
			rcu_read_unlock();
			return qe;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static void *ima_measurements_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct ima_queue_entry *qe = v;

	/* lock protects when reading beyond last element
	 * against concurrent list-extension
	 */
	rcu_read_lock();
	qe = list_entry_rcu(qe->later.next, struct ima_queue_entry, later);
	rcu_read_unlock();
	(*pos)++;

	return (&qe->later == &ima_measurements) ? NULL : qe;
}

static void ima_measurements_stop(struct seq_file *m, void *v)
{
}

void ima_putc(struct seq_file *m, void *data, int datalen)
{
	while (datalen--)
		seq_putc(m, *(char *)data++);
}

/* print format:
 *       32bit-le=pcr#
 *       char[20]=template digest
 *       32bit-le=template name size
 *       char[n]=template name
 *       [eventdata length]
 *       eventdata[n]=template specific data
 */
int ima_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct ima_queue_entry *qe = v;
	struct ima_template_entry *e;
	char *template_name;
	u32 pcr, namelen, template_data_len; /* temporary fields */
	bool is_ima_template = false;
	int i;

	/* get entry */
	e = qe->entry;
	if (e == NULL)
		return -1;

	template_name = (e->template_desc->name[0] != '\0') ?
	    e->template_desc->name : e->template_desc->fmt;

	/*
	 * 1st: PCRIndex
	 * PCR used defaults to the same (config option) in
	 * little-endian format, unless set in policy
	 */
	pcr = !ima_canonical_fmt ? e->pcr : cpu_to_le32(e->pcr);
	ima_putc(m, &pcr, sizeof(e->pcr));

	/* 2nd: template digest */
	ima_putc(m, e->digest, TPM_DIGEST_SIZE);

	/* 3rd: template name size */
	namelen = !ima_canonical_fmt ? strlen(template_name) :
		cpu_to_le32(strlen(template_name));
	ima_putc(m, &namelen, sizeof(namelen));

	/* 4th:  template name */
	ima_putc(m, template_name, strlen(template_name));

	/* 5th:  template length (except for 'ima' template) */
	if (strcmp(template_name, IMA_TEMPLATE_IMA_NAME) == 0)
		is_ima_template = true;

	if (!is_ima_template) {
		template_data_len = !ima_canonical_fmt ? e->template_data_len :
			cpu_to_le32(e->template_data_len);
		ima_putc(m, &template_data_len, sizeof(e->template_data_len));
	}

	/* 6th:  template specific data */
	for (i = 0; i < e->template_desc->num_fields; i++) {
		enum ima_show_type show = IMA_SHOW_BINARY;
		struct ima_template_field *field = e->template_desc->fields[i];

		if (is_ima_template && strcmp(field->field_id, "d") == 0)
			show = IMA_SHOW_BINARY_NO_FIELD_LEN;
		if (is_ima_template && strcmp(field->field_id, "n") == 0)
			show = IMA_SHOW_BINARY_OLD_STRING_FMT;
		field->field_show(m, show, &e->template_data[i]);
	}
	return 0;
}

static const struct seq_operations ima_measurments_seqops = {
	.start = ima_measurements_start,
	.next = ima_measurements_next,
	.stop = ima_measurements_stop,
	.show = ima_measurements_show
};

static int ima_measurements_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ima_measurments_seqops);
}

static const struct file_operations ima_measurements_ops = {
	.open = ima_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

void ima_print_digest(struct seq_file *m, u8 *digest, u32 size)
{
	u32 i;

	for (i = 0; i < size; i++)
		seq_printf(m, "%02x", *(digest + i));
}

/* print in ascii */
static int ima_ascii_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct ima_queue_entry *qe = v;
	struct ima_template_entry *e;
	char *template_name;
	int i;

	/* get entry */
	e = qe->entry;
	if (e == NULL)
		return -1;

	template_name = (e->template_desc->name[0] != '\0') ?
	    e->template_desc->name : e->template_desc->fmt;

	/* 1st: PCR used (config option) */
	seq_printf(m, "%2d ", e->pcr);

	/* 2nd: SHA1 template hash */
	ima_print_digest(m, e->digest, TPM_DIGEST_SIZE);

	/* 3th:  template name */
	seq_printf(m, " %s", template_name);

	/* 4th:  template specific data */
	for (i = 0; i < e->template_desc->num_fields; i++) {
		seq_puts(m, " ");
		if (e->template_data[i].len == 0)
			continue;

		e->template_desc->fields[i]->field_show(m, IMA_SHOW_ASCII,
							&e->template_data[i]);
	}
	seq_puts(m, "\n");
	return 0;
}

static const struct seq_operations ima_ascii_measurements_seqops = {
	.start = ima_measurements_start,
	.next = ima_measurements_next,
	.stop = ima_measurements_stop,
	.show = ima_ascii_measurements_show
};

static int ima_ascii_measurements_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ima_ascii_measurements_seqops);
}

static const struct file_operations ima_ascii_measurements_ops = {
	.open = ima_ascii_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static struct dentry *ima_dir;
static struct dentry *binary_runtime_measurements;
static struct dentry *ascii_runtime_measurements;
static struct dentry *runtime_measurements_count;
static struct dentry *violations;
static struct dentry *ima_policy_initial_ns;
#ifdef CONFIG_IMA_PER_NAMESPACE
static struct dentry *ima_namespaces;
#endif

enum ima_fs_flags {
	IMA_FS_BUSY,
};

static unsigned long ima_fs_flags;

#ifdef CONFIG_IMA_PER_NAMESPACE
/* used for namespace policy rules initialization */
static LIST_HEAD(empty_policy);

static int allocate_namespace_policy(struct ima_ns_policy **ins,
		struct dentry *policy_dentry, struct dentry *ns_dentry)
{
	int result;
	struct ima_ns_policy *p;

	p = kmalloc(sizeof(struct ima_ns_policy), GFP_KERNEL);
	if (!p) {
		result = -ENOMEM;
		goto out;
	}

	p->policy_dentry = policy_dentry;
	p->ns_dentry = ns_dentry;
	p->ima_appraise = ima_appraise;
	p->ima_policy_flag = 0;
	INIT_LIST_HEAD(&p->ima_policy_rules);
	/* namespace starts with empty rules and not pointing to
	 * ima_policy_rules */
	p->ima_rules = &empty_policy;

	result = 0;
	*ins = p;

out:
	return result;
}

static void free_namespace_policy(struct ima_ns_policy *ins)
{
	if (ins->policy_dentry)
		securityfs_remove(ins->policy_dentry);
	securityfs_remove(ins->ns_dentry);

	ima_free_policy_rules(&ins->ima_policy_rules);

	kfree(ins);
}

/*
 * check_mntns: check a mount namespace is valid
 *
 * @ns_id: namespace id to be checked
 * Returns 0 if the namespace is valid.
 *
 * Note: a better way to implement this check is needed. There are
 * cases where the namespace id is valid but not in use by any process
 * and then this implementation misses this case. Could we use an
 * interface similar to what setns implements?
 */
static int check_mntns(unsigned int ns_id)
{
	struct task_struct *p;
	int result = 1;
	struct ns_common *ns;

	rcu_read_lock();
	for_each_process(p) {
		ns = mntns_operations.get(p);
		if (ns->inum == ns_id) {
			result = 0;
			mntns_operations.put(ns);
			break;
		}
		mntns_operations.put(ns);
	}
	rcu_read_unlock();

	return result;
}

static unsigned int initial_mntns_id;
static void get_initial_mntns_id(void)
{
	struct ns_common *ns;

	ns = mntns_operations.get(&init_task);
	initial_mntns_id = ns->inum;
	mntns_operations.put(ns);
}

/*
 * ima_find_namespace_id_from_inode
 * @policy_inode: the inode of the securityfs policy file for a given
 * namespace
 *
 * Return 0 if the namespace id is not found in ima_ns_policy_mapping
 */
static unsigned int find_namespace_id_from_inode(struct inode *policy_inode)
{
	unsigned int ns_id = 0;
#ifdef CONFIG_IMA_PER_NAMESPACE
	struct ima_ns_policy *ins;
	void **slot;
	struct radix_tree_iter iter;

	rcu_read_lock();
	radix_tree_for_each_slot(slot, &ima_ns_policy_mapping, &iter, 0) {
		ins = radix_tree_deref_slot(slot);
		if (unlikely(!ins))
			continue;
		if (radix_tree_deref_retry(ins)) {
			slot = radix_tree_iter_retry(&iter);
			continue;
		}

		if (ins->policy_dentry && ins->policy_dentry->d_inode == policy_inode) {
			ns_id = iter.index;
			break;
		}
	}
	rcu_read_unlock();
#endif

	return ns_id;
}

/*
 * get_namespace_policy_from_inode - Finds namespace mapping from
 * securityfs policy file
 * It is called to get the namespace policy reference when a seurityfs
 * file such as the namespace or policy files are read or written.
 * @inode: inode of the securityfs policy file under a namespace
 * folder
 * Expects the ima_ns_policy_lock already held
 *
 * Returns NULL if the namespace policy reference is not reliable once it
 * probably was already released after a concurrent namespace release.
 * Otherwise, the namespace policy reference is returned.
 */
struct ima_ns_policy *ima_get_namespace_policy_from_inode(struct inode *inode)
{
	unsigned int ns_id;
	struct ima_ns_policy *ins;

	ns_id = find_namespace_id_from_inode(inode);
#ifdef CONFIG_IMA_PER_NAMESPACE
	if (ns_id == 0 &&
		(!ima_policy_initial_ns || inode != ima_policy_initial_ns->d_inode)) {
		/* ns_id == 0 refers to initial namespace, but inode refers to a
		 * namespaced policy file. It might be a race condition with
		 * namespace release, return invalid reference. */
		return NULL;
	}
#endif

	ins = ima_get_policy_from_namespace(ns_id);

	return ins;
}
#endif

static ssize_t ima_read_policy(char *path)
{
	void *data;
	char *datap;
	loff_t size;
	int rc, pathlen = strlen(path);

	char *p;

	/* remove \n */
	datap = path;
	strsep(&datap, "\n");

	rc = kernel_read_file_from_path(path, &data, &size, 0, READING_POLICY);
	if (rc < 0) {
		pr_err("Unable to open file: %s (%d)", path, rc);
		return rc;
	}

	datap = data;
	while (size > 0 && (p = strsep(&datap, "\n"))) {
		pr_debug("rule: %s\n", p);
		rc = ima_parse_add_rule(p);
		if (rc < 0)
			break;
		size -= rc;
	}

	vfree(data);
	if (rc < 0)
		return rc;
	else if (size)
		return -EINVAL;
	else
		return pathlen;
}

static ssize_t ima_write_policy(struct file *file, const char __user *buf,
				size_t datalen, loff_t *ppos)
{
	char *data;
	ssize_t result;
	struct ima_ns_policy *ins;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	result = -EINVAL;
	if (*ppos != 0)
		goto out;

	result = -ENOMEM;
	data = kmalloc(datalen + 1, GFP_KERNEL);
	if (!data)
		goto out;

	*(data + datalen) = '\0';

	result = -EFAULT;
	if (copy_from_user(data, buf, datalen))
		goto out_free;

	result = mutex_lock_interruptible(&ima_write_mutex);
	if (result < 0)
		goto out_free;

	ima_namespace_lock();
	ins = ima_get_namespace_policy_from_inode(file->f_inode);
	if (!ins) {
		/* the namespace is not valid anymore, indicate the error
		 * and exit */
		result = -EINVAL;
		goto out_unlock;
	}

	if (data[0] == '/') {
		result = ima_read_policy(data);
	} else if (ins->ima_appraise & IMA_APPRAISE_POLICY) {
		pr_err("IMA: signed policy file (specified as an absolute pathname) required\n");
		integrity_audit_msg(AUDIT_INTEGRITY_STATUS, NULL, NULL,
				    "policy_update", "signed policy required",
				    1, 0);

		if (ins->ima_appraise & IMA_APPRAISE_ENFORCE)
			result = -EACCES;
	} else {
		result = ima_parse_add_rule(data);
	}
out_unlock:
	ima_namespace_unlock();
	mutex_unlock(&ima_write_mutex);
out_free:
	kfree(data);
out:
	if (result < 0)
		valid_policy = 0;

	return result;
}

#ifdef	CONFIG_IMA_READ_POLICY
static const struct seq_operations ima_policy_seqops = {
		.start = ima_policy_start,
		.next = ima_policy_next,
		.stop = ima_policy_stop,
		.show = ima_policy_show,
};
#endif

/*
 * ima_open_policy: sequentialize access to the policy file
 */
static int ima_open_policy(struct inode *inode, struct file *filp)
{
	if (!(filp->f_flags & O_WRONLY)) {
#ifndef	CONFIG_IMA_READ_POLICY
		return -EACCES;
#else
		if ((filp->f_flags & O_ACCMODE) != O_RDONLY)
			return -EACCES;
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		return seq_open(filp, &ima_policy_seqops);
#endif
	}
	if (test_and_set_bit(IMA_FS_BUSY, &ima_fs_flags))
		return -EBUSY;
	return 0;
}

/*
 * ima_release_policy - start using the new measure policy rules.
 *
 * Initially, ima_measure points to the default policy rules, now
 * point to the new policy rules, and remove the securityfs policy file,
 * assuming a valid policy.
 */
static int ima_release_policy(struct inode *inode, struct file *file)
{
	const char *cause = valid_policy ? "completed" : "failed";
	struct ima_ns_policy *ins;

	if ((file->f_flags & O_ACCMODE) == O_RDONLY)
		return seq_release(inode, file);

	if (valid_policy && ima_check_policy() < 0) {
		cause = "failed";
		valid_policy = 0;
	}

	pr_info("IMA: policy update %s\n", cause);
	integrity_audit_msg(AUDIT_INTEGRITY_STATUS, NULL, NULL,
			    "policy_update", cause, !valid_policy, 0);

	if (!valid_policy) {
		ima_delete_rules();
		valid_policy = 1;
		clear_bit(IMA_FS_BUSY, &ima_fs_flags);
		return 0;
	}

	/* get the namespace id from file->inode (policy file inode).
	 * We also need to synchronize this operation with concurrent namespace
	 * releasing. */
	ima_namespace_lock();
	ins = ima_get_namespace_policy_from_inode(inode);
	if (!ins) {
		/* the namespace is not valid anymore, discard new policy
		 * rules and exit */
		ima_delete_rules();
		valid_policy = 1;
		clear_bit(IMA_FS_BUSY, &ima_fs_flags);
		ima_namespace_unlock();
		return 0;
	}

	ima_update_policy(ins);
#ifndef	CONFIG_IMA_WRITE_POLICY
	if (ins == &ima_initial_namespace_policy) {
		securityfs_remove(ima_policy_initial_ns);
		ima_policy_initial_ns = NULL;
	} else {
		securityfs_remove(ins->policy_dentry);
		ins->policy_dentry = NULL;
	}
#endif

	/* always clear the busy flag so other namespaces can use it */
	clear_bit(IMA_FS_BUSY, &ima_fs_flags);

	ima_namespace_unlock();

	return 0;
}

static const struct file_operations ima_measure_policy_ops = {
	.open = ima_open_policy,
	.write = ima_write_policy,
	.read = seq_read,
	.release = ima_release_policy,
	.llseek = generic_file_llseek,
};

#ifdef CONFIG_IMA_PER_NAMESPACE
/*
 * Assumes namespace id is in use by some process and this mapping
 * does not exist in the map table.
 * @ns_id namespace id
 * Expects ima_ns_policy_lock already held
 */
static int create_mnt_ns_directory(unsigned int ns_id)
{
	int result;
	struct dentry *ns_dir, *ns_policy;
	char dir_name[64];
	struct ima_ns_policy *ins;

	snprintf(dir_name, sizeof(dir_name), "%u", ns_id);

	ns_dir = securityfs_create_dir(dir_name, ima_dir);
	if (IS_ERR(ns_dir)) {
		/* TODO: handle EEXIST error, remove the folder and
		continue the procedure */
		result = PTR_ERR(ns_dir);
		goto out;
	}

	ns_policy = securityfs_create_file("policy", POLICY_FILE_FLAGS,
		                                ns_dir, NULL,
		                                &ima_measure_policy_ops);
	if (IS_ERR(ns_policy)) {
		result = PTR_ERR(ns_policy);
		securityfs_remove(ns_dir);
		goto out;
	}

	result = allocate_namespace_policy(&ins, ns_policy, ns_dir);
	if (!result) {
		result = radix_tree_insert(&ima_ns_policy_mapping, ns_id, ins);
		if (result)
			free_namespace_policy(ins);
	} else {
		securityfs_remove(ns_policy);
		securityfs_remove(ns_dir);
	}

out:
	return result;
}

/*
 * ima_mnt_namespace_dying - releases all namespace policy resources
 * It is called automatically when the namespace is released.
 * @ns_id namespace id to be released
 *
 * Note: This function is called by put_mnt_ns() in the context
 * of a namespace release. We need to make sure that a lock on
 * this path is allowed.
 */
void ima_mnt_namespace_dying(unsigned int ns_id)
{
	struct ima_ns_policy *p;

	ima_namespace_lock();
	p = radix_tree_delete(&ima_ns_policy_mapping, ns_id);

	if (!p) {
		ima_namespace_unlock();
		return;
	}

	free_namespace_policy(p);
	ima_namespace_unlock();
}

static ssize_t handle_new_namespace_policy(const char *data, size_t datalen)
{
	unsigned int ns_id;
	ssize_t result;
	struct ima_ns_policy *ins;

	result = -EINVAL;

	if (sscanf(data, "%u", &ns_id) != 1) {
		pr_err("IMA: invalid namespace id: %s\n", data);
		goto out;
	}

	rcu_read_lock();
	ins = radix_tree_lookup(&ima_ns_policy_mapping, ns_id);
	rcu_read_unlock();
	if (ins) {
		pr_info("IMA: directory for namespace id %u already created\n", ns_id);
		result = datalen;
		goto out;
	}

	if (ns_id == initial_mntns_id) {
		pr_err("IMA: invalid use of the initial mount namespace\n");
		result = -EINVAL;
		goto out;
	}

	ima_namespace_lock();
	if (check_mntns(ns_id)) {
		result = -ENOENT;
		pr_err("IMA: unused namespace id %u\n", ns_id);
		goto out_unlock;
	}

	result = create_mnt_ns_directory(ns_id);
	if (result != 0) {
		pr_err("IMA: namespace id %u directory creation failed\n", ns_id);
		goto out_unlock;
	}

	result = datalen;
	pr_info("IMA: directory created for namespace id %u\n", ns_id);

out_unlock:
	ima_namespace_unlock();

out:
	return result;
}

static ssize_t ima_write_namespaces(struct file *file, const char __user *buf,
		                            size_t datalen, loff_t *ppos)
{
	char *data;
	ssize_t result;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	result = -EINVAL;
	if (*ppos != 0)
		goto out;

	result = -ENOMEM;
	data = kmalloc(datalen + 1, GFP_KERNEL);
	if (!data)
		goto out;

	*(data + datalen) = '\0';

	result = -EFAULT;
	if (copy_from_user(data, buf, datalen))
		goto out_free;

	result = mutex_lock_interruptible(&ima_write_mutex);
	if (result < 0)
		goto out_free;

	result = handle_new_namespace_policy(data, datalen);

	mutex_unlock(&ima_write_mutex);

out_free:
	kfree(data);
out:
	return result;
}

static int ima_open_namespaces(struct inode *inode, struct file *filp)
{
	if (!(filp->f_flags & O_WRONLY))
		return -EACCES;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (test_and_set_bit(IMA_FS_BUSY, &ima_fs_flags))
		return -EBUSY;
	return 0;
}

static int ima_release_namespaces(struct inode *inode, struct file *file)
{
	clear_bit(IMA_FS_BUSY, &ima_fs_flags);

	return 0;
}

static const struct file_operations ima_namespaces_ops = {
		.open = ima_open_namespaces,
		.write = ima_write_namespaces,
		.read = seq_read,
		.release = ima_release_namespaces,
		.llseek = generic_file_llseek,
};
#endif

int __init ima_fs_init(void)
{
	ima_dir = securityfs_create_dir("ima", NULL);
	if (IS_ERR(ima_dir))
		return -1;

	binary_runtime_measurements =
	    securityfs_create_file("binary_runtime_measurements",
				   S_IRUSR | S_IRGRP, ima_dir, NULL,
				   &ima_measurements_ops);
	if (IS_ERR(binary_runtime_measurements))
		goto out;

	ascii_runtime_measurements =
	    securityfs_create_file("ascii_runtime_measurements",
				   S_IRUSR | S_IRGRP, ima_dir, NULL,
				   &ima_ascii_measurements_ops);
	if (IS_ERR(ascii_runtime_measurements))
		goto out;

	runtime_measurements_count =
	    securityfs_create_file("runtime_measurements_count",
				   S_IRUSR | S_IRGRP, ima_dir, NULL,
				   &ima_measurements_count_ops);
	if (IS_ERR(runtime_measurements_count))
		goto out;

	violations =
	    securityfs_create_file("violations", S_IRUSR | S_IRGRP,
				   ima_dir, NULL, &ima_htable_violations_ops);
	if (IS_ERR(violations))
		goto out;

	ima_policy_initial_ns = securityfs_create_file("policy", POLICY_FILE_FLAGS,
					    ima_dir, NULL,
					    &ima_measure_policy_ops);
	if (IS_ERR(ima_policy_initial_ns))
		goto out;

#ifdef CONFIG_IMA_PER_NAMESPACE
	ima_namespaces = securityfs_create_file("namespaces", NAMESPACES_FILE_FLAGS,
						ima_dir, NULL,
						&ima_namespaces_ops);
	if (IS_ERR(ima_namespaces))
		goto out;

	get_initial_mntns_id();
#endif

	return 0;
out:
	securityfs_remove(violations);
	securityfs_remove(runtime_measurements_count);
	securityfs_remove(ascii_runtime_measurements);
	securityfs_remove(binary_runtime_measurements);
	securityfs_remove(ima_dir);
	securityfs_remove(ima_policy_initial_ns);
#ifdef CONFIG_IMA_PER_NAMESPACE
	securityfs_remove(ima_namespaces);
#endif
	return -1;
}
