/////By fanxiushu 2016-07-28

#pragma once

#include <linux/version.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/if.h>
#include <linux/poll.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <asm/uaccess.h>
#include <linux/aio.h>
#include <linux/statfs.h>

///
#define MIN_KVER  KERNEL_VERSION(2,6,36)

////
struct string_t
{
	int    length;
	int    max_length; ///
	char*  buffer;
};


unsigned long hash_string(const char *s);


