#ifndef _COMMON_H_
#define _COMMON_H_

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <shadow.h>
#include <crypt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/types.h>
#include <sys/sendfile.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <pwd.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/time.h>
#include <signal.h>
#include <linux/capability.h>
#include <syscall.h>
#include <sys/wait.h>

#define ERR_EXIT(m) \
        do \
        {  \
                perror(m); \
                exit(EXIT_FAILURE); \
        }  \
        while(0)


#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND 32
#define MAX_ARG 1024
#define MINIFTP_CONF "miniftpd.conf"


#endif

