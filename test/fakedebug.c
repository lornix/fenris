// This is a simple "fake server" code for testing Aegir

#include <unistd.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>

#include "../fdebug.h"

#include "../common.h"

static unsigned int sd;

static void flisten(char* where) {
    struct sockaddr_un sun;

    STDERRMSG("[+] Setting up a socket...\n");

    if ((sd = socket (AF_LOCAL, SOCK_STREAM, 0))<0) {
        perror("cannot create a socket");
        exit(1);
    }

    sun.sun_family = AF_LOCAL;
    strncpy (sun.sun_path, where, UNIX_PATH_MAX);

    if (bind (sd, (struct sockaddr*)&sun,sizeof (sun))) {
        perror("cannot bind");
        exit(1);
    }

    listen(sd,10);

    STDERRMSG("[+] Listening...\n");

    sd=accept(sd,0,0);

    STDERRMSG("[+] Connection accepted!\n");

}

char* send_message(int mtype,char* data,int dlen) {
    struct dmsg_header x;

    x.magic1=DMSG_MAGIC1;
    x.magic2=DMSG_MAGIC2;
    x.type=mtype;
    x.code_running=1;
    write(sd,&x,sizeof(x));
    if (dlen) write(sd,data,dlen);

    STDERRMSG("[+] Sent message %d with %d bytes of payload.\n",mtype,dlen);

}

void check_messages(void) {
    char buf[100000];
    struct dmsg_header x;
    int dlen;
    int miaumiau;

    fcntl(sd,F_SETFL,O_NONBLOCK);

    if ((miaumiau=read(sd,&x,sizeof(x)))<=0) {
        fcntl(sd,F_SETFL,O_SYNC);
        if (!miaumiau) FATALEXIT("disconnect");
        return;
    }

    fcntl(sd,F_SETFL,O_SYNC);

    switch (x.type) {
        case DMSG_GETREGS: case DMSG_GETMAP:    case DMSG_FDMAP:
        case DMSG_SIGNALS: case DMSG_TOLIBCALL: case DMSG_TOSYSCALL:
        case DMSG_TOLOCALCALL: case DMSG_TOLOWERNEST: case DMSG_GETBACK:
        case DMSG_RUN: case DMSG_TONEXT: case DMSG_STOP:
        case DMSG_LISTBREAK: case DMSG_KILL:
        case DMSG_FOO: dlen=0; break;
        default:
                       dlen=read(sd,buf,sizeof(buf));
    }
    STDERRMSG("[+] Received message %d with %d bytes of payload.\n",x.type,dlen);

    if (x.type == 5) {
        struct user_regs_struct x;
        x.eip=0x12345678;
        send_message(DMSG_REPLY,(char*)&x,sizeof(x));
    } else if (x.type == 2) {
        char buf[1000];
        int* q;

        memcpy(buf+4,check_messages,sizeof(buf)-4);
        q=(int*)buf;
        *q=900;
        send_message(DMSG_REPLY,buf,904);
#define XXX "So, trying memory reads?\n"
        send_message(DMSG_ASYNC,XXX,strlen(XXX)+1);


    } else if (x.type == 3) {
        char bufx[1000];
        sprintf(bufx,"foobar+%d",*(int*)buf);
        send_message(DMSG_REPLY,bufx,strlen(bufx)+1);
    }


}

main() {
    char* f;
    unlink("/tmp/ftest");
    flisten("/tmp/ftest");
    f="Hello, mere mortals.\n";
    send_message(DMSG_ASYNC,f,strlen(f)+1);
    send_message(DMSG_REPLY,0,0);
    f="This is your commander speaking.\n\n";
    send_message(DMSG_ASYNC,f,strlen(f)+1);

    while (1) {
        check_messages();
        //    usleep(1000000);
        //  f="\nHow do you do?\n";
        //  send_message(DMSG_ASYNC,f,strlen(f)+1);

    }
}
