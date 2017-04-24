#ifndef _NAMESPACE_H_
#define _NAMESPACE_H_
#ifdef __KERNEL__

#include <linux/types.h>

struct mnt_namespace;
struct fs_struct;
struct user_namespace;

extern struct mnt_namespace *copy_mnt_ns(unsigned long, struct mnt_namespace *,
		struct user_namespace *, struct fs_struct *);
extern void put_mnt_ns(struct mnt_namespace *ns);

extern const struct file_operations proc_mounts_operations;
extern const struct file_operations proc_mountinfo_operations;
extern const struct file_operations proc_mountstats_operations;

extern unsigned int get_mnt_ns_inum(struct mnt_namespace *);
extern u64 get_mnt_ns_seq(struct mnt_namespace *);

#endif
#endif
