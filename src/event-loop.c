/*
 * Copyright © 2008 Kristian Høgsberg
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <assert.h>
#include <event2/event.h>
#include <event2/thread.h>
#include "wayland-private.h"
#include "wayland-server.h"
#include "wayland-os.h"

struct wl_event_loop {
	struct event_base *evbase;
//	int epoll_fd;
	struct wl_list check_list;
	struct wl_list idle_list;
	struct wl_list destroy_list;

	struct wl_signal destroy_signal;
};

struct wl_event_source_interface {
//	int (*dispatch)(struct wl_event_source *source,
//			struct epoll_event *ep);
	int (*dispatch)(evutil_socket_t fd, short what,
			void *arg);
};

struct wl_event_source {
	struct wl_event_source_interface *interface;
	struct wl_event_loop *loop;
	struct wl_list link;
	void *data;
	struct event *ev;
	int fd;
};

struct wl_event_source_fd {
	struct wl_event_source base;
	wl_event_loop_fd_func_t func;
	int fd;
};

static void
wl_event_source_libevent_dispatch(evutil_socket_t fd, short what, void *arg)
{
	struct wl_event_source *source = (struct wl_event_source *) arg;

	(void)source->interface->dispatch(fd, what, arg);
}

#if 0
static int
wl_event_source_fd_dispatch(struct wl_event_source *source,
			    struct epoll_event *ep)
{
	struct wl_event_source_fd *fd_source = (struct wl_event_source_fd *) source;
	uint32_t mask;

	mask = 0;
	if (ep->events & EPOLLIN)
		mask |= WL_EVENT_READABLE;
	if (ep->events & EPOLLOUT)
		mask |= WL_EVENT_WRITABLE;
	if (ep->events & EPOLLHUP)
		mask |= WL_EVENT_HANGUP;
	if (ep->events & EPOLLERR)
		mask |= WL_EVENT_ERROR;

	return fd_source->func(fd_source->fd, mask, source->data);
}
#endif

static int
wl_event_source_fd_dispatch(evutil_socket_t fd, short what, void *arg)
{
	struct wl_event_source *source = (struct wl_event_source *) arg;
	struct wl_event_source_fd *fd_source = (struct wl_event_source_fd *) source;
	uint32_t mask;

//	wl_log("fd_dispatch\n");

	mask = 0;
	if (what & EV_READ)
		mask |= WL_EVENT_READABLE;
	if (what & EV_WRITE)
		mask |= WL_EVENT_WRITABLE;
//	wl_log("%s: what=%d, mask=%u\n", __func__, what, mask);
#if 0
	if (what & EPOLLHUP)
		mask |= WL_EVENT_HANGUP;
	if (what & EPOLLERR)
		mask |= WL_EVENT_ERROR;
#endif

	return fd_source->func(fd_source->fd, mask, source->data);
}

struct wl_event_source_interface fd_source_interface = {
	wl_event_source_fd_dispatch,
};

#if 0
static struct wl_event_source *
add_source(struct wl_event_loop *loop,
	   struct wl_event_source *source, uint32_t mask, void *data)
{
	struct epoll_event ep;

	if (source->fd < 0) {
		free(source);
		return NULL;
	}

	source->loop = loop;
	source->data = data;
	wl_list_init(&source->link);

	memset(&ep, 0, sizeof ep);
	if (mask & WL_EVENT_READABLE)
		ep.events |= EPOLLIN;
	if (mask & WL_EVENT_WRITABLE)
		ep.events |= EPOLLOUT;
	ep.data.ptr = source;

	if (epoll_ctl(loop->epoll_fd, EPOLL_CTL_ADD, source->fd, &ep) < 0) {
		close(source->fd);
		free(source);
		return NULL;
	}

	return source;
}
#endif

static struct wl_event_source *
add_source(struct wl_event_loop *loop,
	   struct wl_event_source *source, void *data)
{
	source->loop = loop;
	source->data = data;
	wl_list_init(&source->link);

	return source;
}

WL_EXPORT struct wl_event_source *
wl_event_loop_add_fd(struct wl_event_loop *loop,
		     int fd, uint32_t mask,
		     wl_event_loop_fd_func_t func,
		     void *data)
{
	struct wl_event_source_fd *source;
	short what;

	source = malloc(sizeof *source);
	if (source == NULL)
		return NULL;

//	wl_log("%s called\n", __func__);

	what = EV_PERSIST;
	if (mask & WL_EVENT_READABLE)
		what |= EV_READ;
	if (mask & WL_EVENT_WRITABLE)
		what |= EV_WRITE;

	add_source(loop, &source->base, data);
	source->base.interface = &fd_source_interface;
	source->base.fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	fcntl(source->base.fd, O_NONBLOCK);
	source->func = func;
	source->fd = fd;
	source->base.ev = event_new(loop->evbase, source->base.fd, what,
	    wl_event_source_libevent_dispatch, source);
	event_add(source->base.ev, NULL);

	return &source->base;
}

#if 0
WL_EXPORT int
wl_event_source_fd_update(struct wl_event_source *source, uint32_t mask)
{
	struct wl_event_loop *loop = source->loop;
	struct epoll_event ep;

	memset(&ep, 0, sizeof ep);
	if (mask & WL_EVENT_READABLE)
		ep.events |= EPOLLIN;
	if (mask & WL_EVENT_WRITABLE)
		ep.events |= EPOLLOUT;
	ep.data.ptr = source;

	return epoll_ctl(loop->epoll_fd, EPOLL_CTL_MOD, source->fd, &ep);
}
#endif

WL_EXPORT int
wl_event_source_fd_update(struct wl_event_source *source, uint32_t mask)
{
	struct wl_event_loop *loop = source->loop;
	short what;

//	wl_log("%s called\n", __func__);

	what = EV_PERSIST;
	if (mask & WL_EVENT_READABLE)
		what |= EV_READ;
	if (mask & WL_EVENT_WRITABLE)
		what |= EV_WRITE;

	event_free(source->ev);
	source->ev = event_new(loop->evbase, source->fd, what,
	    wl_event_source_libevent_dispatch, source);
	event_add(source->ev, NULL);

	return 0;
}

struct wl_event_source_timer {
	struct wl_event_source base;
	wl_event_loop_timer_func_t func;
};

#if 0
static int
wl_event_source_timer_dispatch(struct wl_event_source *source,
			       struct epoll_event *ep)
{
	struct wl_event_source_timer *timer_source =
		(struct wl_event_source_timer *) source;
	uint64_t expires;
	int len;

	len = read(source->fd, &expires, sizeof expires);
	if (!(len == -1 && errno == EAGAIN) && len != sizeof expires)
		/* Is there anything we can do here?  Will this ever happen? */
		wl_log("timerfd read error: %m\n");

	return timer_source->func(timer_source->base.data);
}
#endif

static int
wl_event_source_timer_dispatch(evutil_socket_t fd, short what, void *arg)
{
	struct wl_event_source *source = (struct wl_event_source *) arg;
	struct wl_event_source_timer *timer_source =
		(struct wl_event_source_timer *) source;

//	wl_log("timer_dispatch\n");

	return timer_source->func(timer_source->base.data);
}

struct wl_event_source_interface timer_source_interface = {
	wl_event_source_timer_dispatch,
};

WL_EXPORT struct wl_event_source *
wl_event_loop_add_timer(struct wl_event_loop *loop,
			wl_event_loop_timer_func_t func,
			void *data)
{
	struct wl_event_source_timer *source;

	source = malloc(sizeof *source);
	if (source == NULL)
		return NULL;

//	wl_log("%s called\n", __func__);

	add_source(loop, &source->base, data);
	source->base.interface = &timer_source_interface;
	source->base.fd = -1;
	source->func = func;
	source->base.ev = event_new(loop->evbase, -1, 0,
	    wl_event_source_libevent_dispatch, source);

	return &source->base;
}

WL_EXPORT int
wl_event_source_timer_update(struct wl_event_source *source, int ms_delay)
{
	struct timeval tv;

//	wl_log("updating timer to ms_delay=%d\n", ms_delay);

	tv.tv_sec = ms_delay / 1000;
	tv.tv_usec = (ms_delay % 1000) * 1000;
	if (ms_delay == 0)
		event_del(source->ev);
	else
		event_add(source->ev, &tv);

	return 0;
}

struct wl_event_source_signal {
	struct wl_event_source base;
	int signal_number;
	wl_event_loop_signal_func_t func;
};

#if 0
static int
wl_event_source_signal_dispatch(struct wl_event_source *source,
			       struct epoll_event *ep)
{
	struct wl_event_source_signal *signal_source =
		(struct wl_event_source_signal *) source;
	struct signalfd_siginfo signal_info;
	int len;

	len = read(source->fd, &signal_info, sizeof signal_info);
	if (!(len == -1 && errno == EAGAIN) && len != sizeof signal_info)
		/* Is there anything we can do here?  Will this ever happen? */
		wl_log("signalfd read error: %m\n");

	return signal_source->func(signal_source->signal_number,
				   signal_source->base.data);
}
#endif

static int
wl_event_source_signal_dispatch(evutil_socket_t fd, short what, void *arg)
{
	struct wl_event_source *source = (struct wl_event_source *) arg;
	struct wl_event_source_signal *signal_source =
		(struct wl_event_source_signal *) source;

//	wl_log("signal_dispatch\n");

	return signal_source->func(signal_source->signal_number,
				   signal_source->base.data);
}

struct wl_event_source_interface signal_source_interface = {
	wl_event_source_signal_dispatch,
};

WL_EXPORT struct wl_event_source *
wl_event_loop_add_signal(struct wl_event_loop *loop,
			int signal_number,
			wl_event_loop_signal_func_t func,
			void *data)
{
	struct wl_event_source_signal *source;

	source = malloc(sizeof *source);
	if (source == NULL)
		return NULL;

//	wl_log("%s called\n", __func__);

	add_source(loop, &source->base, data);
	source->base.interface = &signal_source_interface;
	source->base.fd = -1;
	source->func = func;
	source->signal_number = signal_number;

	source->base.ev = event_new(loop->evbase, signal_number,
	    EV_SIGNAL|EV_PERSIST, wl_event_source_libevent_dispatch, source);
	event_add(source->base.ev, NULL);

	return &source->base;
}

struct wl_event_source_idle {
	struct wl_event_source base;
	wl_event_loop_idle_func_t func;
};

struct wl_event_source_interface idle_source_interface = {
	NULL,
};

WL_EXPORT struct wl_event_source *
wl_event_loop_add_idle(struct wl_event_loop *loop,
		       wl_event_loop_idle_func_t func,
		       void *data)
{
	struct wl_event_source_idle *source;

	source = malloc(sizeof *source);
	if (source == NULL)
		return NULL;

	source->base.interface = &idle_source_interface;
	source->base.loop = loop;
	source->base.fd = -1;
	source->base.ev = NULL;

	source->func = func;
	source->base.data = data;

	wl_list_insert(loop->idle_list.prev, &source->base.link);

	return &source->base;
}

WL_EXPORT void
wl_event_source_check(struct wl_event_source *source)
{
	wl_list_insert(source->loop->check_list.prev, &source->link);
}

WL_EXPORT void
wl_event_source_activate(struct wl_event_source *source)
{
	if (source->ev != NULL) {
		if (!event_pending(source->ev, EV_TIMEOUT|EV_READ|EV_WRITE|EV_SIGNAL, NULL)) {
			event_add(source->ev, NULL);
		}
		event_active(source->ev, EV_TIMEOUT, 0);
	}
}

WL_EXPORT int
wl_event_source_remove(struct wl_event_source *source)
{
	struct wl_event_loop *loop = source->loop;

//	wl_log("%s called\n", __func__);
	if (source->ev != NULL) {
	event_free(source->ev);
	source->ev = NULL;
	}

	wl_list_remove(&source->link);
	wl_list_insert(&loop->destroy_list, &source->link);

	return 0;
}

static void
wl_event_loop_process_destroy_list(struct wl_event_loop *loop)
{
	struct wl_event_source *source, *next;

	wl_list_for_each_safe(source, next, &loop->destroy_list, link){
//		fprintf(stderr, "%s: processing entry\n", __func__);
		if (source->ev != NULL) {
			event_free(source->ev);
			source->ev = NULL;
		}
//		fprintf(stderr, "%s: freed event\n", __func__);

		/* We need to explicitly remove the fd, since closing the fd
		 * isn't enough in case we've dup'ed the fd. */
		if (source->fd >= 0) {
//			fprintf(stderr, "%s: closing fd\n", __func__);
			close(source->fd);
			source->fd = -1;
		}
//		fprintf(stderr, "%s: freeing\n", __func__);
		free(source);
	}

//	fprintf(stderr, "%s: wl_list_init\n", __func__);
	wl_list_init(&loop->destroy_list);
}

WL_EXPORT struct wl_event_loop *
wl_event_loop_create(void)
{
	struct wl_event_loop *loop;

	loop = malloc(sizeof *loop);
	if (loop == NULL)
		return NULL;

	evthread_use_pthreads();
	loop->evbase = event_base_new();
	if (loop->evbase == NULL) {
		free(loop);
		return NULL;
	}
//	loop->epoll_fd = wl_os_epoll_create_cloexec();
//	if (loop->epoll_fd < 0) {
//		free(loop);
//		return NULL;
//	}
	wl_list_init(&loop->check_list);
	wl_list_init(&loop->idle_list);
	wl_list_init(&loop->destroy_list);

	wl_signal_init(&loop->destroy_signal);

	return loop;
}

WL_EXPORT void
wl_event_loop_destroy(struct wl_event_loop *loop)
{
	wl_signal_emit(&loop->destroy_signal, loop);

	wl_event_loop_process_destroy_list(loop);
	event_base_free(loop->evbase);
//	close(loop->epoll_fd);
	free(loop);
}

static int
post_dispatch_check(struct wl_event_loop *loop)
{
	struct wl_event_source *source, *next;
	int n;

//	wl_log("%s called\n", __func__);

	n = 0;
	wl_list_for_each_safe(source, next, &loop->check_list, link)
		n += source->interface->dispatch(source->fd, 0, source);

	return n;
}

WL_EXPORT void
wl_event_loop_dispatch_idle(struct wl_event_loop *loop)
{
	struct wl_event_source_idle *source;

//	fprintf(stderr, "%s: running\n", __func__);

	while (!wl_list_empty(&loop->idle_list)) {
		source = container_of(loop->idle_list.next,
				      struct wl_event_source_idle, base.link);
		source->func(source->base.data);
		wl_event_source_remove(&source->base);
	}
//	fprintf(stderr, "%s: finished\n", __func__);
}

WL_EXPORT int
wl_event_loop_dispatch(struct wl_event_loop *loop, int timeout)
{
	int val, n;

//	fprintf(stderr, "%s: called\n", __func__);

	wl_event_loop_dispatch_idle(loop);

//	wl_log("%s: called\n", __func__);
//	fprintf(stderr, "%s: calling event_base_loop\n", __func__);

	val = event_base_loop(loop->evbase, EVLOOP_ONCE);
	if (val < 0) {
		fprintf(stderr, "%s: event_base_loop returned %d\n", __func__, val);
		return -1;
	}

//	fprintf(stderr, "%s: calling wl_event_loop_process_destroy_list\n", __func__);
	wl_event_loop_process_destroy_list(loop);
//	fprintf(stderr, "%s: calling post_dispatch_check\n", __func__);

	wl_event_loop_dispatch_idle(loop);

	do {
		n = post_dispatch_check(loop);
//		fprintf(stderr, "%s: post_dispatch_check returned %d\n", __func__, n);
	} while (n > 0);

	return 0;
}

#if 0
WL_EXPORT int
wl_event_loop_get_fd(struct wl_event_loop *loop)
{
	return loop->epoll_fd;
}
#endif

WL_EXPORT void
wl_event_loop_add_destroy_listener(struct wl_event_loop *loop,
				   struct wl_listener *listener)
{
	wl_signal_add(&loop->destroy_signal, listener);
}

WL_EXPORT struct wl_listener *
wl_event_loop_get_destroy_listener(struct wl_event_loop *loop,
				   wl_notify_func_t notify)
{
	return wl_signal_get(&loop->destroy_signal, notify);
}

