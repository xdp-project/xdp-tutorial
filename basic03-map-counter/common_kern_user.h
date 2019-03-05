/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

struct datarec {
	__u64 rx_packets;
};

#endif /* __COMMON_KERN_USER_H */
