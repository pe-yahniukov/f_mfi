#include <poll.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#define IOCTL_GADGET_GET_MFI_IN_BUF_CNT _IOW('a', 0x10, int32_t)
#define IOCTL_GADGET_GET_MFI_MAX_PACKET_SIZE _IOW('a', 0x11, int32_t)

static uint8_t *recv_buf = NULL;
static uint8_t *send_buf = NULL;

static int exit_signal = 0;
static void signal_handler(int signal)
{
    exit_signal = signal;
}

int main(int argc, const char * argv[])
{
    int err, fd, max_packet_size, recv_buf_cnt, send_buf_cnt;

    signal(SIGINT, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGSEGV, signal_handler);
    signal(SIGTERM, signal_handler);

    err = open("/dev/mfi0", O_RDWR);
    if (err < 0) {
        printf("ERROR: /dev/mfi0 open() err = %d\n", err);
        return err;
    }
    fd = err;

    err = ioctl(fd, IOCTL_GADGET_GET_MFI_MAX_PACKET_SIZE, NULL);
    if (err < 0) {
        printf("ERROR: /dev/mfi0 ioctl() err = %d\n", err);
        goto exit;
    }
    max_packet_size = err;
    if (!max_packet_size) {
        printf("ERROR: some UDC driver issue?\n");
        err = -1;
        goto exit;
    }

    recv_buf = (uint8_t *)calloc(max_packet_size, sizeof(uint8_t));
    send_buf = (uint8_t *)calloc(max_packet_size, sizeof(uint8_t));
    if (!recv_buf || !send_buf) {
        printf("ERROR: calloc()\n");
        err = -1;
        goto exit;
    }

    printf("Polling...\n");

    send_buf[0]  = 0xFF;
    send_buf[1]  = 0x55;
    send_buf[2]  = 0x02;
    send_buf[3]  = 0x00;
    send_buf[4]  = 0xEE;
    send_buf[5]  = 0x10;
    send_buf_cnt = 6;

    err = write(fd, send_buf, send_buf_cnt);
    if (err < 0) {
        printf("ERROR: /dev/mfi0 write() err = %d\n", err);
        goto exit;
    }

    while (!exit_signal)
    {
        struct pollfd fds[] = { { fd, POLLIN | POLLERR } };
        err = poll(fds, 1, 1000); // wait for 1 second for event
        if (err > 0)
        {
            if (err & POLLERR)
            {
                printf("ERROR: probably permission denied error\n");
                err = -1;
                goto exit;
            }
            if (err & POLLIN)
            {
                printf("Got polling event. Reading...\n");
                break;
            }
        }
    }
    if (exit_signal) {
        err = 0;
        goto exit;
    }

    err = ioctl(fd, IOCTL_GADGET_GET_MFI_IN_BUF_CNT, NULL);
    if (err < 0) {
        printf("ERROR: /dev/mfi0 ioctl() err = %d\n", err);
        goto exit;
    }
    recv_buf_cnt = err;

    if (recv_buf_cnt)
    {
        err = read(fd, recv_buf, recv_buf_cnt);
        if (err < 0) {
            printf("ERROR: /dev/mfi0 read() err = %d\n", err);
            goto exit;
        }

        if (recv_buf_cnt == send_buf_cnt)
        {
            for (int i = 0; i < recv_buf_cnt; ++i)
            {
                if (recv_buf[i] != send_buf[i])
                {
                    printf("ERROR: Wrong link initialization sequence received\n");
                    err = -1;
                    goto exit;
                }
            }
            printf("SUCCESS. We're ready to start iAP2 session\n");
        }
        else
        {
            printf("ERROR: Wrong link initialization sequence received\n");
            err = -1;
            goto exit;
        }
    }
    else
    {
        printf("ERROR: Something is very wrong with driver\n");
        err = -1;
    }

exit:
    printf("Exit\n");
    if (recv_buf)
        free(recv_buf);
    if (send_buf)
        free(send_buf);
    close(fd);

    return err;
}
