---
title: Zephys OS uIP 协议栈：netcore - 发送数据
date: 2016-10-11 22:39:19
categories: ["Zephyr OS"]
tags: [Zephyr]
---
这一节我们来学习 uIP 协议栈向网络发送数据的流程。

<!--more-->
# net_send
应用程序准备好要发送的 buffer 后，调用 net_send 函数就可以发送数据了，所以我们通过 net_send() 这个函数，追踪一下发送数据的整体流程。

```
int net_send(struct net_buf *buf)
{
	int ret = 0;

  // 先简单地对应用程序传入的 buf 进行有效性检查
	if (!buf || ip_buf_len(buf) == 0) {
		return -ENODATA;
	}
	if (buf->len && !uip_appdatalen(buf)) {
		uip_appdatalen(buf) = ip_buf_appdatalen(buf);
	}

  // (根据当前上下文来决定)释放 CPU，切换到其它线程
  // 有个疑问，为什么要切换？
	switch (sys_execution_context_type_get()) {
	case NANO_CTX_ISR:
		break;
	case NANO_CTX_FIBER:
		fiber_yield();
		break;
	case NANO_CTX_TASK:
#ifdef CONFIG_MICROKERNEL
		task_yield();
#endif
		break;
	}

#ifdef CONFIG_NETWORKING_WITH_TCP
#define MAX_TCP_RETRY_COUNT 3
	if (ip_buf_context(buf) && net_context_get_tuple(ip_buf_context(buf))->ip_proto == IPPROTO_TCP) {
    // 如果应用程序使用的是 TCP 协议，则根据 TCP 协议的相关规范，做一些协议相关的工作
		struct uip_conn *conn;
		int status;
		uint8_t retry_count;

    // tcp 相关的 context 初始化
		net_context_tcp_init(ip_buf_context(buf), NET_TCP_TYPE_CLIENT);

    // 由于 net_context_tcp_init 内部做了很多工作
    // 获取该 buf 的 context 的连接状态
		status = net_context_get_connection_status(ip_buf_context(buf));
    // 根据连接状态，做相应的处理
		switch (status) {
		case EISCONN:
      ......
			break;
		case -EALREADY:
			......
			return 0;
		case -EINPROGRESS:
			......
			break;
		case -ECONNRESET:
      ......
			return status;
		}
		ret = status;
	}
#endif

  // 将该 buffer 放到 netdev 的 tx_queue 中
	nano_fifo_put(&netdev.tx_queue, buf);

	// 唤醒接收线程
	fiber_wakeup(tx_fiber_id);

	return ret;
}
```

# net_tx_fiber
```
static void net_tx_fiber(void)
{
	while (1) {
		struct net_buf *buf;
		int ret;

		// 从 netdev 的 tx_queue 中取 buffer
    // 这里传入的参数为 TICKS_UNLIMITED
    // 表示如果此时 tx_queue 中没有 buffer，该线程将加入阻塞状态，直到 net_send() 向
    // tx_queue 中放了 buffer，然后把该线程唤醒
		buf = net_buf_get_timeout(&netdev.tx_queue, 0, TICKS_UNLIMITED);

    // 代码走到这里，说明已经成功取到 buffer 了。

		/* 根据返回值，判断对 buffer 的操作：
		 *  <0: 发生了错误，我们需要释放 buffer
		 *   0: 消息被 uIP 协议栈丢弃了， 此时 buffer 已被 uIP 释放了
		 *  >0: 消息发送成功，buffer 已被释放
		 */
		ret = check_and_send_packet(buf);
		if (ret < 0) {
			ip_buf_unref(buf);
			goto wait_next;
		} else if (ret > 0) {
			goto wait_next;
		}

		NET_BUF_CHECK_IF_NOT_IN_USE(buf);

		// 处理所有我们需要处理的事件
		do {
			ret = process_run(buf);
		} while (ret > 0);

		// 释放 buffer
		ip_buf_unref(buf);

	wait_next:
	  ...
	}
}
```

# check_and_send_packet
```
static int check_and_send_packet(struct net_buf *buf)
{
	struct net_tuple *tuple;
	struct simple_udp_connection *udp;
	int ret = 0;

	if (!netdev.drv) {
		// 如果 netdev 没有绑定驱动，直接返回错误。
		return -EINVAL;
	}

	tuple = net_context_get_tuple(ip_buf_context(buf));
	if (!tuple) {
		return -EINVAL;
	}

	// 根据 context 中设定的 协议，做相应的处理。
	switch (tuple->ip_proto) {
	case IPPROTO_UDP:
		......
		break;
	case IPPROTO_TCP:
#ifdef CONFIG_NETWORKING_WITH_TCP
		......
		ret = net_context_tcp_send(buf);
		if (ret < 0 && ret != -EAGAIN) {
			NET_DBG("Packet could not be sent properly (err %d)\n", ret);
		} else if (ret == 0) {
			/* For TCP the return status 0 means that the packet
			 * is released already. The caller of this function
			 * expects return value of > 0 in this case.
			 */
			ret = 1;
		} else {
			ip_buf_sent_status(buf) = ret;
			ret = true; /* This will prevent caller to discard
				     * the buffer that needs to be resent
				     * again.
				     */
		}
#else
		NET_DBG("TCP not supported\n");
		ret = -EINVAL;
#endif
		break;
	case IPPROTO_ICMPV6:
		NET_DBG("ICMPv6 not yet supported\n");
		ret = -EINVAL;
		break;
	}

	return ret;
}
```
# net_context_tcp_send
```
int net_context_tcp_send(struct net_buf *buf)
{
	bool connected, reset;
	// 准备需要发送的数据
	// 向该 buf 的 context 绑定的 tcp 线程投递一个 tcpip_event 事件
	process_post_synch(&ip_buf_context(buf)->tcp, tcpip_event, INT_TO_POINTER(TCP_WRITE_EVENT), buf);

	connected = uip_flags(buf) & UIP_CONNECTED;
	reset = uip_flags(buf) & UIP_ABORT;

	/* If the buffer ref is 1, then the buffer was sent and it
	 * is cleared already.
	 */
	if (buf->ref == 1) {
		return 0;
	}

	return ip_buf_sent_status(buf);
}
```

# process_thread_tcp
```
PROCESS_THREAD(tcp, ev, data, buf, user_data)
{
	PROCESS_BEGIN();

	while(1) {
		// 由于投递的事 tcpip_event 事件，所以代码将继续走下去
		PROCESS_YIELD_UNTIL(ev == tcpip_event);

	try_send:
		if (POINTER_TO_INT(data) == TCP_WRITE_EVENT) {
			/* We want to send data to peer. */
			struct net_context *context = user_data;

			if (!context) {
				continue;
			}

			context->connection_status = ip_buf_sent_status(buf);

			do {
				context = user_data;
				if (!context || !buf) {
					break;
				}

				if (!context->ps.net_buf || context->ps.net_buf != buf) {
					NET_DBG("psock init %p buf %p\n",	&context->ps, buf);
					PSOCK_INIT(&context->ps, buf);
				}

				handle_tcp_connection(&context->ps, POINTER_TO_INT(data), buf);

				// 线程退出，直到今后有其它线程再向此线程投递 tcpip_event 事件
				// 然后线程才会被唤醒,并从此处开始执行
				PROCESS_WAIT_EVENT_UNTIL(ev == tcpip_event);
				......
			} while(!(uip_closed(buf) || uip_aborted(buf) || uip_timedout(buf)));
			......
			continue;
		} else {
			......
		}

	read_data:
		......
	}

	PROCESS_END();
}
```

# handle_tcp_connection
```
static int handle_tcp_connection(struct psock *p, enum tcp_event_type type, struct net_buf *buf)
{
	PSOCK_BEGIN(p);

	if (type == TCP_WRITE_EVENT) {
		PSOCK_SEND(p, buf);
	}

	PSOCK_END(p);
}
```
