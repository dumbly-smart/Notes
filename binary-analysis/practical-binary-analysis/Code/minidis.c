#define _GNU_SOURCE
#include <capstone/capstone.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct { uint64_t va, off, size; } Exec;
typedef struct { uint64_t *v; size_t n, cap; } Work;

static bool span(size_t file_size, uint64_t off, uint64_t len) {
    return off <= file_size && len <= (uint64_t)file_size - off;
}
static void push(Work *w, uint64_t x) {
    if (w->n == w->cap) {
        size_t nc = w->cap ? w->cap * 2 : 64;
        void *p = realloc(w->v, nc * sizeof(*w->v));
        if (!p) { perror("realloc"); exit(1); }
        w->v = p; w->cap = nc;
    }
    w->v[w->n++] = x;
}
static bool in_exec(const Exec *x, uint64_t va, uint64_t len) {
    return va >= x->va && va - x->va <= x->size && len <= x->size - (va - x->va);
}
static bool has_group(const cs_insn *i, uint8_t group) {
    for (uint8_t n=0; n<i->detail->groups_count; n++) if (i->detail->groups[n] == group) return true;
    return false;
}
static bool immediate_target(const cs_insn *i, uint64_t *out) {
    cs_x86 *x = &i->detail->x86;
    if (!x->op_count || x->operands[0].type != X86_OP_IMM) return false;
    *out = (uint64_t)x->operands[0].imm; return true;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s ELF64 [SEED_VA ...]\n", argv[0]); return 2; }
    int fd=open(argv[1],O_RDONLY); if(fd<0){perror("open");return 1;}
    struct stat st; if(fstat(fd,&st)<0||st.st_size<0){perror("fstat");return 1;}
    size_t sz=(size_t)st.st_size; uint8_t *m=mmap(NULL,sz,PROT_READ,MAP_PRIVATE,fd,0);
    if(m==MAP_FAILED){perror("mmap");return 1;} close(fd);
    if(!span(sz,0,sizeof(Elf64_Ehdr))){fprintf(stderr,"truncated ELF header\n");return 1;}
    Elf64_Ehdr *e=(Elf64_Ehdr*)m;
    if(memcmp(e->e_ident,ELFMAG,SELFMAG)||e->e_ident[EI_CLASS]!=ELFCLASS64||
       e->e_ident[EI_DATA]!=ELFDATA2LSB||e->e_machine!=EM_X86_64){fprintf(stderr,"need little-endian x86-64 ELF\n");return 1;}
    if(e->e_phentsize!=sizeof(Elf64_Phdr)||!span(sz,e->e_phoff,(uint64_t)e->e_phnum*sizeof(Elf64_Phdr))){fprintf(stderr,"bad program headers\n");return 1;}
    Elf64_Phdr *ph=(Elf64_Phdr*)(m+e->e_phoff); Exec xs[64]; size_t nx=0;
    for(uint16_t i=0;i<e->e_phnum;i++) if(ph[i].p_type==PT_LOAD&&(ph[i].p_flags&PF_X)&&ph[i].p_filesz){
        if(nx==64||!span(sz,ph[i].p_offset,ph[i].p_filesz)){fprintf(stderr,"bad executable segment\n");return 1;}
        xs[nx++]=(Exec){ph[i].p_vaddr,ph[i].p_offset,ph[i].p_filesz};
    }
    if(!nx){fprintf(stderr,"no executable file-backed segment\n");return 1;}
    csh h; if(cs_open(CS_ARCH_X86,CS_MODE_64,&h)!=CS_ERR_OK)return 1; cs_option(h,CS_OPT_DETAIL,CS_OPT_ON);
    Work q={0}; push(&q,e->e_entry);
    for(int i=2;i<argc;i++){
        char *end=NULL;errno=0;uint64_t seed=strtoull(argv[i],&end,0);
        if(errno||!argv[i][0]||*end){fprintf(stderr,"bad seed: %s\n",argv[i]);return 2;}
        push(&q,seed);
    }
    size_t seen_size=sz?sz:1; uint8_t *seen=calloc(seen_size,1); if(!seen)return 1;
    printf("entry=0x%"PRIx64" executable_segments=%zu\n",e->e_entry,nx);
    while(q.n){uint64_t pc=q.v[--q.n];
        for(;;){Exec *x=NULL;for(size_t k=0;k<nx;k++)if(in_exec(&xs[k],pc,1)){x=&xs[k];break;}if(!x){printf("unmapped-target 0x%"PRIx64"\n",pc);break;}
            uint64_t fo=x->off+(pc-x->va);if(fo>=sz||seen[fo])break;cs_insn *ins=NULL;
            size_t avail=(size_t)(x->size-(pc-x->va));if(avail>15)avail=15;size_t n=cs_disasm(h,m+fo,avail,pc,1,&ins);
            if(!n||!ins[0].size||!in_exec(x,pc,ins[0].size)){printf("0x%"PRIx64": .byte 0x%02x ; undecodable\n",pc,m[fo]);break;}
            for(size_t b=0;b<ins[0].size;b++)seen[fo+b]=1;
            printf("0x%"PRIx64": %-8s %s\n",pc,ins[0].mnemonic,ins[0].op_str);
            uint64_t next=pc+ins[0].size,target=0;bool imm=immediate_target(&ins[0],&target);
            bool ret=has_group(&ins[0],CS_GRP_RET), call=has_group(&ins[0],CS_GRP_CALL), jump=has_group(&ins[0],CS_GRP_JUMP);
            unsigned id=ins[0].id;bool unconditional=id==X86_INS_JMP;
            cs_free(ins,n);
            if(call){if(imm)push(&q,target);pc=next;continue;}
            if(jump){if(imm)push(&q,target);else printf("unresolved-indirect at 0x%"PRIx64"\n",pc);if(!unconditional){pc=next;continue;}break;}
            if(ret||id==X86_INS_HLT||id==X86_INS_UD2) break;
            pc=next;
        }
    }
    free(seen);free(q.v);cs_close(&h);munmap(m,sz);return 0;
}
