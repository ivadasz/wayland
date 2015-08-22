/*
 * Copyright © 2012 Intel Corporation
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting documentation, and
 * that the name of the copyright holders not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  The copyright holders make no representations
 * about the suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>

#include "test-runner.h"

static int num_alloc;
static void* (*sys_malloc)(size_t);
static void (*sys_free)(void*);
static void* (*sys_realloc)(void*, size_t);
static void* (*sys_calloc)(size_t, size_t);

/* when set to 1, check if tests are not leaking memory and opened files.
 * It is turned on by default. It can be turned off by
 * WAYLAND_TEST_NO_LEAK_CHECK environment variable. */
int leak_check_enabled;

/* when this var is set to 0, every call to test_set_timeout() is
 * suppressed - handy when debugging the test. Can be set by
 * WAYLAND_TEST_NO_TIMEOUTS evnironment var */
static int timeouts_enabled = 1;

/* set to one if the output goes to the terminal */
static int is_atty = 0;

extern const struct test __start_test_section, __stop_test_section;

__attribute__ ((visibility("default"))) void *
malloc(size_t size)
{
	num_alloc++;
	return sys_malloc(size);
}

__attribute__ ((visibility("default"))) void
free(void* mem)
{
	if (mem != NULL)
		num_alloc--;
	sys_free(mem);
}

__attribute__ ((visibility("default"))) void *
realloc(void* mem, size_t size)
{
	if (mem == NULL)
		num_alloc++;
	return sys_realloc(mem, size);
}

__attribute__ ((visibility("default"))) void *
calloc(size_t nmemb, size_t size)
{
	if (sys_calloc == NULL)
		return NULL;

	num_alloc++;

	return sys_calloc(nmemb, size);
}

static const struct test *
find_test(const char *name)
{
	const struct test *t;

	for (t = &__start_test_section; t < &__stop_test_section; t++)
		if (strcmp(t->name, name) == 0)
			return t;

	return NULL;
}

static void
usage(const char *name, int status)
{
	const struct test *t;

	fprintf(stderr, "Usage: %s [TEST]\n\n"
		"With no arguments, run all test.  Specify test case to run\n"
		"only that test without forking.  Available tests:\n\n",
		name);

	for (t = &__start_test_section; t < &__stop_test_section; t++)
		fprintf(stderr, "  %s\n", t->name);

	fprintf(stderr, "\n");

	exit(status);
}

void
test_set_timeout(unsigned int to)
{
	int re;

	if (!timeouts_enabled) {
		fprintf(stderr, "Timeouts suppressed.\n");
		return;
	}

	re = alarm(to);
	fprintf(stderr, "Timeout was %sset", re ? "re-" : "");

	if (to != 0)
		fprintf(stderr, " to %d second%s from now.\n",
			to, to > 1 ? "s" : "");
	else
		fprintf(stderr, " off.\n");
}

static void
sigalrm_handler(int signum)
{
	fprintf(stderr, "Test timed out.\n");
	abort();
}

static void
run_test(const struct test *t)
{
	int cur_alloc = num_alloc;
	int cur_fds, num_fds;
	struct sigaction sa;

	cur_fds = count_open_fds();

	if (timeouts_enabled) {
		sa.sa_handler = sigalrm_handler;
		sa.sa_flags = 0;
		sigemptyset(&sa.sa_mask);
		assert(sigaction(SIGALRM, &sa, NULL) == 0);
	}

	t->run();

	/* turn off timeout (if any) after test completition */
	if (timeouts_enabled)
		alarm(0);

	if (leak_check_enabled) {
		if (cur_alloc != num_alloc) {
			fprintf(stderr, "Memory leak detected in test. "
				"Allocated %d blocks, unfreed %d\n", num_alloc,
				num_alloc - cur_alloc);
			abort();
		}
		num_fds = count_open_fds();
		if (cur_fds != num_fds) {
			fprintf(stderr, "fd leak detected in test. "
				"Opened %d files, unclosed %d\n", num_fds,
				num_fds - cur_fds);
			abort();
		}
	}
	exit(EXIT_SUCCESS);
}

#ifndef PATH_MAX
#define PATH_MAX 256
#endif

static void
set_xdg_runtime_dir(void)
{
	char xdg_runtime_dir[PATH_MAX];
	const char *xrd_env;

	xrd_env = getenv("XDG_RUNTIME_DIR");
	/* if XDG_RUNTIME_DIR is not set in environ, fallback to /tmp */
	assert((snprintf(xdg_runtime_dir, PATH_MAX, "%s/wayland-tests",
			 xrd_env ? xrd_env : "/tmp") < PATH_MAX)
		&& "test error: XDG_RUNTIME_DIR too long");

	if (mkdir(xdg_runtime_dir, 0700) == -1)
		if (errno != EEXIST) {
			perror("Creating XDG_RUNTIME_DIR");
			abort();
		}

	if (setenv("XDG_RUNTIME_DIR", xdg_runtime_dir, 1) == -1) {
		perror("Setting XDG_RUNTIME_DIR");
		abort();
	}
}

static void
rmdir_xdg_runtime_dir(void)
{
	const char *xrd_env = getenv("XDG_RUNTIME_DIR");
	assert(xrd_env && "No XDG_RUNTIME_DIR set");

	/* rmdir may fail if some test didn't do clean up */
	if (rmdir(xrd_env) == -1)
		perror("Cleaning XDG_RUNTIME_DIR");
}

#define RED	"\033[31m"
#define GREEN	"\033[32m"

static void
stderr_set_color(const char *color)
{
	/* use colors only when the output is connected to
	 * the terminal */
	if (is_atty)
		fprintf(stderr, "%s", color);
}

static void
stderr_reset_color(void)
{
	if (is_atty)
		fprintf(stderr, "\033[0m");
}

int main(int argc, char *argv[])
{
	const struct test *t;
	pid_t pid;
	int total, pass;
#ifdef __DragonFly__
	int status;
#else
	siginfo_t info;
#endif

	/* Load system malloc, free, and realloc */
	sys_calloc = dlsym(RTLD_NEXT, "calloc");
	sys_realloc = dlsym(RTLD_NEXT, "realloc");
	sys_malloc = dlsym(RTLD_NEXT, "malloc");
	sys_free = dlsym(RTLD_NEXT, "free");

	leak_check_enabled = !getenv("WAYLAND_TEST_NO_LEAK_CHECK");
	timeouts_enabled = !getenv("WAYLAND_TEST_NO_TIMEOUTS");

	if (isatty(fileno(stderr)))
		is_atty = 1;

	if (argc == 2 && strcmp(argv[1], "--help") == 0)
		usage(argv[0], EXIT_SUCCESS);

	if (argc == 2) {
		t = find_test(argv[1]);
		if (t == NULL) {
			fprintf(stderr, "unknown test: \"%s\"\n", argv[1]);
			usage(argv[0], EXIT_FAILURE);
		}

		set_xdg_runtime_dir();
		/* run_test calls exit() */
		assert(atexit(rmdir_xdg_runtime_dir) == 0);

		run_test(t);
	}

	/* set our own XDG_RUNTIME_DIR */
	set_xdg_runtime_dir();

	pass = 0;
	for (t = &__start_test_section; t < &__stop_test_section; t++) {
		int success = 0;

		pid = fork();
		assert(pid >= 0);

		if (pid == 0)
			run_test(t); /* never returns */

#ifdef __DragonFly__
		if (wait(&status)) {
			fprintf(stderr, "waitid failed: %m\n");
			abort();
		}
#else
		if (waitid(P_ALL, 0, &info, WEXITED)) {
			stderr_set_color(RED);
			fprintf(stderr, "waitid failed: %m\n");
			stderr_reset_color();

			abort();
		}
#endif

		fprintf(stderr, "test \"%s\":\t", t->name);
#ifdef __DragonFly__
		if (WIFEXITED(status)) {
			fprintf(stderr, "exit status %d", WEXITSTATUS(status));
			if (WEXITSTATUS(status) == EXIT_SUCCESS)
				success = 1;
			break;
		} else if (WIFSIGNALED(status) || WCOREDUMP(status)) {
			fprintf(stderr, "signal %d", WTERMSIG(status));
			break;
		}
#else
		switch (info.si_code) {
		case CLD_EXITED:
			if (info.si_status == EXIT_SUCCESS)
				success = !t->must_fail;
			else
				success = t->must_fail;

			stderr_set_color(success ? GREEN : RED);
			fprintf(stderr, "test \"%s\":\texit status %d",
				t->name, info.si_status);

			break;
		case CLD_KILLED:
		case CLD_DUMPED:
			if (t->must_fail)
				success = 1;

			stderr_set_color(success ? GREEN : RED);
			fprintf(stderr, "test \"%s\":\tsignal %d",
				t->name, info.si_status);

			break;
		}
#endif

		if (success) {
			pass++;
			fprintf(stderr, ", pass.\n");
		} else
			fprintf(stderr, ", fail.\n");

		stderr_reset_color();

		/* print separator line */
		fprintf(stderr, "----------------------------------------\n");
	}

	total = &__stop_test_section - &__start_test_section;
	fprintf(stderr, "%d tests, %d pass, %d fail\n",
		total, pass, total - pass);

	/* cleaning */
	rmdir_xdg_runtime_dir();

	return pass == total ? EXIT_SUCCESS : EXIT_FAILURE;
}
