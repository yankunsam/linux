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
#include <linux/mnt_namespace.h>
#include <linux/radix-tree.h>

#include "ima.h"

static DEFINE_MUTEX(ima_write_mutex);

static RADIX_TREE(ns_alias_mapping, GFP_ATOMIC);

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
static int ima_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct ima_queue_entry *qe = v;
	struct ima_template_entry *e;
	char *template_name;
	int namelen;
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
	ima_putc(m, &e->pcr, sizeof(e->pcr));

	/* 2nd: template digest */
	ima_putc(m, e->digest, TPM_DIGEST_SIZE);

	/* 3rd: template name size */
	namelen = strlen(template_name);
	ima_putc(m, &namelen, sizeof(namelen));

	/* 4th:  template name */
	ima_putc(m, template_name, namelen);

	/* 5th:  template length (except for 'ima' template) */
	if (strcmp(template_name, IMA_TEMPLATE_IMA_NAME) == 0)
		is_ima_template = true;

	if (!is_ima_template)
		ima_putc(m, &e->template_data_len,
			 sizeof(e->template_data_len));

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

	if (data[0] == '/') {
		result = ima_read_policy(data);
	} else if (ima_appraise & IMA_APPRAISE_POLICY) {
		pr_err("IMA: signed policy file (specified as an absolute pathname) required\n");
		integrity_audit_msg(AUDIT_INTEGRITY_STATUS, NULL, NULL,
				    "policy_update", "signed policy required",
				    1, 0);
		if (ima_appraise & IMA_APPRAISE_ENFORCE)
			result = -EACCES;
	} else {
		result = ima_parse_add_rule(data);
	}
	mutex_unlock(&ima_write_mutex);
out_free:
	kfree(data);
out:
	if (result < 0)
		valid_policy = 0;

	return result;
}

static void free_alias_map_entry(struct alias_map *map)
{
//	if (!map) {
//		pr_err("IMA: not expected alias map entry as NULL\n");
//		return;
//	}
//	if (!map->alias_name) {
//		pr_err("IMA: not expected alias 'name' map entry as NULL\n");
//		return;
//	}
	kfree(map->alias_name);
	kfree(map);
}

static int allocate_alias_map_entry(struct alias_map **map, u64 seq,
		char *alias_name, ssize_t namelen)
{
	struct alias_map *new_map;
	int result;

	new_map = kmalloc(sizeof(struct alias_map), GFP_KERNEL);
	if (!new_map) {
		result = ENOMEM;
		goto out;
	}

	new_map->alias_name = kmalloc(namelen, GFP_KERNEL);
	if (!new_map->alias_name) {
		result = ENOMEM;
		kfree(new_map);
		goto out;
	}

	new_map->incarnation = seq;
	strcpy(new_map->alias_name, alias_name);

	*map = new_map;
	result = 0;

out:
	return result;
}

/*
 * if ns_id already exists, check incarnation. If incarnation is incorrect this is an outdated alias.
 * return the alias name if the the alias map exists with the current incarnation number
 *
 */
const char *get_mnt_ns_alias(unsigned int ns_id, u64 seq)
{
	struct alias_map *map;
	char *alias_name = NULL;

	map = radix_tree_lookup(&ns_alias_mapping, ns_id);
	if (map) {
		if (map->incarnation == seq) {
			alias_name = map->alias_name;
		}
	}

	return alias_name;
}

/*
 * if there is a namespace alias for mnt_ns_id with incorrect incarnation, delete the alias
 * return zero if the alias was already set with the correct ns_id and incarnation number
 */
int check_and_fix_ns_alias(unsigned int ns_id, u64 seq)
{
	int result;
	struct alias_map *map;

	result = 1;
	map = radix_tree_lookup(&ns_alias_mapping, ns_id);
	if (map) {
		if (map->incarnation == seq) {
//			pr_info("IMA: alias mapping found for nsid=%u seq=%llu alias='%s'\n", ns_id, seq, map->alias_name);
			result = 0;
		} else {
			pr_err("IMA: alias mapping found with incorrect seq: nsid=%u seq=%llu expected seq=%llu\n", ns_id, map->incarnation, seq);
			map = radix_tree_delete(&ns_alias_mapping, ns_id);
			free_alias_map_entry(map);
		}
	}

	return result;
}

static bool is_ns_alias_already_set(unsigned int ns_id, u64 seq)
{
	bool result = false;

	if (get_mnt_ns_alias(ns_id, seq)) {
		result = true;
	}

	return result;
}

static int check_ns_exists(unsigned int ns_id, u64 *seq)
{
	struct task_struct *p;
	int result = 1;
	//struct ns_common *ns;

	for_each_process(p) {
		//ns = p->nsproxy->mnt_ns->ns.ops->get(p);
		if (get_mnt_ns_inum(p->nsproxy->mnt_ns) == ns_id) {
			*seq = get_mnt_ns_seq(p->nsproxy->mnt_ns);
			result = 0;
			break;
		}
		//p->nsproxy->mnt_ns->ns.ops->put(ns);
	}

	return result;
}

/*
 * if ns_id already exists, check incarnation. If incarnation is incorrect this is an outdated
 * alias and it can be updated.
 * create a new alias if alias is not already set with correct incarnation or update alias if
 * it is set to an old incarnation.
 * Assumes namespace id is in use by some process and this alias does not exist in the map table.
 * Should we block the creation if the same alias already exists on another namespace?
*/
int set_mnt_ns_alias_once(unsigned int ns_id, u64 seq, char *alias_name, ssize_t namelen)
{
	int result;
	struct alias_map *map = 0;

	// delete outdated alias mapping to make sure the tree is ready for the update
	if (check_and_fix_ns_alias(ns_id, seq) == 0) {
		// the alias mapping is not outdated, updating an existing mapping is not allowed
		result = -EPERM;
		goto out;
	}

	result = allocate_alias_map_entry(&map, seq, alias_name, namelen);

	pr_info("IMA: Adding alias='%s' with seq=%llu to nsid=%u\n", map->alias_name, map->incarnation, ns_id);

	if (!result)
		result = radix_tree_insert(&ns_alias_mapping, ns_id, map);

	if (result)
		free_alias_map_entry(map);

out:
	return result;
}

static ssize_t parse_namespace_alias_update(const char *data, size_t datalen) {
	char *alias_name;
	unsigned int ns_id;
	u64 seq;
	ssize_t result;

	result = -EINVAL;
	// TODO: not required the 'A:' head
	// TODO: consider adding alias without mnt id. The mnt id is assumed to be the namespace
	//       of the caller ('current')
	if (data[0] == 'A') {
		alias_name = kmalloc(datalen, GFP_KERNEL);
		if (!alias_name) {
			result = -ENOMEM;
			goto out;
		}

		if (sscanf(data, "A:%u:%s", &ns_id, alias_name) != 2) {
			pr_err("IMA: invalid namespace alias add request\n");
			goto out_free;
		}

		if (check_ns_exists(ns_id, &seq)) {
			result = -EPERM;
			pr_err("IMA: alias set failed for unused namespace id %u\n", ns_id);
			goto out_free;
		}

		if (is_ns_alias_already_set(ns_id, seq)) {
			result = -EPERM;
			pr_err("IMA: alias for namespace id %u already set\n", ns_id);
			goto out_free;
		}

		// TODO: check if the alias_name is already in use by other namespace id?

		if (set_mnt_ns_alias_once(ns_id, seq, alias_name, strlen(alias_name) + 1) == 0) {
			result = strlen(data);
			pr_info("IMA: alias '%s' created for namespace id %u\n", alias_name, ns_id);
		}

		if (result < 0)
			pr_err("IMA: alias set for namespace id %u failed: %lu\n", ns_id, result);

		// TODO: clean up the entire alias map table in order to avoid too many not used alias
		//       (for released namespaces)? IMA will delete the old alias only for new
		//       measures in the related mount namespace
	} else {
		pr_err("IMA: invalid namespace alias add request\n");
		goto out;
	}

out_free:
    kfree(alias_name);

out:
	return result;
}

static ssize_t ima_write_namespace(struct file *file, const char __user *buf,
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

	pr_info("IMA: namespace alias update: '%s'\n", data);

	result = mutex_lock_interruptible(&ima_write_mutex);
	if (result < 0)
		goto out_free;

	result = parse_namespace_alias_update(data, datalen);

	mutex_unlock(&ima_write_mutex);

out_free:
	kfree(data);
out:

	return result;
}

static struct dentry *ima_dir;
static struct dentry *binary_runtime_measurements;
static struct dentry *ascii_runtime_measurements;
static struct dentry *runtime_measurements_count;
static struct dentry *violations;
static struct dentry *ima_policy;
static struct dentry *ima_namespace;

enum ima_fs_flags {
	IMA_FS_BUSY,
};

static unsigned long ima_fs_flags;

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

	if ((file->f_flags & O_ACCMODE) == O_RDONLY)
		return 0;

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

	ima_update_policy();
#ifndef	CONFIG_IMA_WRITE_POLICY
	securityfs_remove(ima_policy);
	ima_policy = NULL;
#else
	clear_bit(IMA_FS_BUSY, &ima_fs_flags);
#endif
	return 0;
}

static const struct file_operations ima_measure_policy_ops = {
	.open = ima_open_policy,
	.write = ima_write_policy,
	.read = seq_read,
	.release = ima_release_policy,
	.llseek = generic_file_llseek,
};

/*
 * ima_open_namespace: TODO: should not allow open for reading
 */
static int ima_open_namespace(struct inode *inode, struct file *filp)
{
	if (!(filp->f_flags & O_WRONLY))
		return -EACCES;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	pr_info("IMA: open namespace alias file\n");

	if (test_and_set_bit(IMA_FS_BUSY, &ima_fs_flags))
		return -EBUSY;
	return 0;
}

/*
 * ima_release_namespace - TODO.
 *
 * TODO.
 */
static int ima_release_namespace(struct inode *inode, struct file *file)
{
	if ((file->f_flags & O_ACCMODE) == O_RDONLY)
    	return 0;

	pr_info("IMA: release namespace alias file\n");

	clear_bit(IMA_FS_BUSY, &ima_fs_flags);

	return 0;
}

static const struct file_operations ima_measure_namespace_ops = {
	.open = ima_open_namespace,
	.write = ima_write_namespace,
	.read = seq_read,
	.release = ima_release_namespace,
	.llseek = generic_file_llseek,
};

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

	ima_policy = securityfs_create_file("policy", POLICY_FILE_FLAGS,
					    ima_dir, NULL,
					    &ima_measure_policy_ops);
	if (IS_ERR(ima_policy))
		goto out;

	ima_namespace = securityfs_create_file("namespace_alias", NAMESPACE_FILE_FLAGS,
						ima_dir, NULL,
						&ima_measure_namespace_ops);
	if (IS_ERR(ima_namespace))
		goto out;

	return 0;
out:
	securityfs_remove(violations);
	securityfs_remove(runtime_measurements_count);
	securityfs_remove(ascii_runtime_measurements);
	securityfs_remove(binary_runtime_measurements);
	securityfs_remove(ima_dir);
	securityfs_remove(ima_policy);
	securityfs_remove(ima_namespace);
	return -1;
}
