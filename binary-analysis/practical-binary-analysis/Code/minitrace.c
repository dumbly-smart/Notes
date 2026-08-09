#define _GNU_SOURCE
#include <capstone/capstone.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static size_t read_code(pid_t pid,uint64_t pc,uint8_t out[15]){
    size_t n=0;while(n<15){errno=0;long w=ptrace(PTRACE_PEEKTEXT,pid,(void*)(pc+n),0);if(errno)break;
        size_t take=sizeof(w);if(take>15-n)take=15-n;memcpy(out+n,&w,take);n+=take;}return n;
}
static bool wait_stop(pid_t pid,int *status){
    for(;;){pid_t r=waitpid(pid,status,0);if(r==pid)return true;if(r<0&&errno==EINTR)continue;return false;}
}
int main(int argc,char **argv){
    if(argc<3){fprintf(stderr,"usage: %s STEP_BUDGET PROGRAM [ARGS...]\n",argv[0]);return 2;}
    char *end=NULL;unsigned long long budget=strtoull(argv[1],&end,10);if(!*argv[1]||*end||!budget){fprintf(stderr,"bad budget\n");return 2;}
    pid_t child=fork();if(child<0){perror("fork");return 1;}
    if(child==0){if(ptrace(PTRACE_TRACEME,0,0,0)<0){perror("TRACEME");_exit(127);}raise(SIGSTOP);execv(argv[2],&argv[2]);perror("execv");_exit(127);}
    int st;if(!wait_stop(child,&st)||!WIFSTOPPED(st)){fprintf(stderr,"child did not stop\n");return 1;}
    if(ptrace(PTRACE_SETOPTIONS,child,0,PTRACE_O_EXITKILL|PTRACE_O_TRACEEXEC)<0){perror("SETOPTIONS");return 1;}
    if(ptrace(PTRACE_CONT,child,0,0)<0||!wait_stop(child,&st)){perror("exec wait");return 1;}
    if(!WIFSTOPPED(st)){fprintf(stderr,"child exited during exec\n");return 1;}
    csh h;if(cs_open(CS_ARCH_X86,CS_MODE_64,&h)!=CS_ERR_OK)return 1;
    uint64_t previous=0;for(unsigned long long seq=0;seq<budget;seq++){
        struct user_regs_struct r;if(ptrace(PTRACE_GETREGS,child,0,&r)<0){perror("GETREGS");break;}
        uint8_t bytes[15];size_t got=read_code(child,r.rip,bytes);cs_insn *ins=NULL;size_t n=got?cs_disasm(h,bytes,got,r.rip,1,&ins):0;
        if(n)printf("%06llu tid=%d pc=0x%"PRIx64" from=0x%"PRIx64" %-8s %s\n",seq,child,(uint64_t)r.rip,previous,ins[0].mnemonic,ins[0].op_str);
        else printf("%06llu tid=%d pc=0x%"PRIx64" from=0x%"PRIx64" <decode-failed>\n",seq,child,(uint64_t)r.rip,previous);
        previous=r.rip;if(n)cs_free(ins,n);
        if(ptrace(PTRACE_SINGLESTEP,child,0,0)<0){perror("SINGLESTEP");break;}if(!wait_stop(child,&st)){perror("waitpid");break;}
        if(WIFEXITED(st)){printf("exit=%d\n",WEXITSTATUS(st));break;}if(WIFSIGNALED(st)){printf("signal-exit=%d\n",WTERMSIG(st));break;}
        if(!WIFSTOPPED(st)) break;
        int sig=WSTOPSIG(st);
        if(sig!=SIGTRAP){
            fprintf(stderr,"forwarding signal %d\n",sig);if(ptrace(PTRACE_CONT,child,0,sig)<0||!wait_stop(child,&st))break;
            if(!WIFSTOPPED(st))break;
        }
    }
    ptrace(PTRACE_DETACH,child,0,0);cs_close(&h);return 0;
}
