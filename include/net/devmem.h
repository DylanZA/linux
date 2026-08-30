/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _NET_PUBLIC_DEVMEM_H
#define _NET_PUBLIC_DEVMEM_H

#include <linux/err.h>
#include <linux/types.h>

struct dma_buf;
struct sock;

#if IS_ENABLED(CONFIG_NET_DEVMEM)
/**
 * net_devmem_get_rx_dmabuf() - Get the RX dma-buf bound to a socket's device.
 * @id: device-memory binding ID
 * @sk: socket whose connected device must match the binding
 *
 * Returns a referenced dma_buf matched to the socket's destination device, or
 * an ERR_PTR with a negative errno. The caller owns the returned reference.
 */
struct dma_buf *net_devmem_get_rx_dmabuf(u32 id, struct sock *sk);
#else
static inline struct dma_buf *
net_devmem_get_rx_dmabuf(u32 id, struct sock *sk)
{
	return ERR_PTR(-EOPNOTSUPP);
}
#endif

#endif /* _NET_PUBLIC_DEVMEM_H */
