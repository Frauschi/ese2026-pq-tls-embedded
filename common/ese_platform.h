/* Platform hooks implemented once per OS (dut/linux, dut/zephyr, host). */
#ifndef ESE_PLATFORM_H
#define ESE_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#define ESE_CTRL_PORT 11111
#define ESE_TLS_PORT  4433

uint64_t ese_now_ns(void);
void ese_sleep_ms(int ms);

int ese_sock_connect(const char *ip, uint16_t port);
int ese_sock_listen(uint16_t port);
/* Returns the accepted fd, or <0 on error or after timeout_ms (0 = forever). */
int ese_sock_accept(int lfd, int timeout_ms);
int ese_sock_send(int fd, const void *buf, size_t len);
/* Returns bytes read, 0 on orderly close, <0 on error. */
int ese_sock_recv(int fd, void *buf, size_t len);
void ese_sock_close(int fd);

/* Runs fn(arg) on a fresh thread with a painted stack; reports the high-water mark. */
int ese_run_measured(void (*fn)(void *), void *arg, size_t *stack_used);

const char *ese_platform_name(void);
uint32_t ese_cpu_hz(void);
void ese_log(const char *fmt, ...);

#endif /* ESE_PLATFORM_H */
