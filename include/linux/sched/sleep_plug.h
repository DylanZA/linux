// SPDX-License-Identifier: GPL-2.0
#ifndef _LINUX_SCHED_SLEEP_PLUG_H
#define _LINUX_SCHED_SLEEP_PLUG_H

#include <linux/list.h>

struct sched_sleep_plug {
	struct list_head list;
	void (*cb)(struct sched_sleep_plug*);
};

void __sched_sleep_plug_flush(struct list_head *list);

static inline void sched_sleep_plug_flush(struct list_head *list)
{
	if (!list_empty(list))
		__sched_sleep_plug_flush(list);
}

#endif
