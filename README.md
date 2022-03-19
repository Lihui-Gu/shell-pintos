# ZJUT操作系统课程设计

## 项目介绍
本人2021年秋操作系统课程设计，完成了shell实现、Pintos的线程和用户程序部分更多详细介绍可见本人知乎平台。
### shell实现
设计并实现一个模拟Bash 的shell实现，要求支持cd和pwd命令，支持程序执行、路径解析、输入/输出的重定向。

经验分享：[模拟的简易Shell实现](https://zhuanlan.zhihu.com/p/433873968)
### Pintos线程管理
经验分享：
1. [Pintos通关记录](https://zhuanlan.zhihu.com/p/434924931?)

2. [Pintos抢占式优先级](https://zhuanlan.zhihu.com/p/436842526)

3. [Pintos捐赠优先级分析](https://zhuanlan.zhihu.com/p/437286183)

4. [Pintos捐赠优先级实现](https://zhuanlan.zhihu.com/p/437286183)

5. [Pintos多级反馈队列（MLFQ）](https://zhuanlan.zhihu.com/p/436674359)

### Pintos用户程序
[Pintos用户程序](https://zhuanlan.zhihu.com/p/441433700)
- 实现参数传递
- 实现系统调用的具体处理程序
- 用户的内存访问，系统调用需要读取用户内存
- 从用户对战中读取系统调用号，调度处理程序

## shell
1. 在原有基础上增加了终端提示符
2. 利用tokenize实现了接收用户输入指令的参数分割
3. 实现路径解析
- 优先在本目录下进行搜索，判断是否为本目录下的可执行文件；
- 未找到，到PATH目录下找
4. fork创建子进程进行execv执行
5. 输入输出重定向功能
   
*信号量机制没有实现，欢迎在本项目上帮助完成信号量机制*

## Pintos线程管理
### 时钟唤醒
1. 修改timer_sleep函数
```C
void timer_sleep(int64_t ticks)
{
    struct thread *cur = thread_current();
    enum intr_level old_level = intr_disable();
    cur->wake_up_time = timer_ticks() + ticks;
    heap_push(&sleep_q, cur);
    thread_block();
    intr_set_level(old_level);
}
```
2. sleep_check函数
```C
static void sleep_check(int64_t now)
{
    while (!heap_empty(&sleep_q) && ((struct thread *)heap_top(&sleep_q))->wake_up_time <= now)
    {
        thread_unblock((struct thread *)heap_pop(&sleep_q));
    }
}
```
3. timer_interrupt函数修改
```C
static void timer_interrupt (struct intr_frame *args UNUSED)
{
  ticks++;
  thread_tick ();
  sleep_check(ticks);
}
```
4. 比较两个进程的唤醒时间，若A的唤醒时间小于B，则返回true。
```C
static bool thread_wake_up_time_cmp(void *a, void *b)
{
    return ((struct thread *)a)->wake_up_time < ((struct thread *)b)->wake_up_time;
}
```
### 抢占式优先级
1. thread_yield函数分析
   1. 将当前正在运行的进程放入就绪队列
   2. 从就绪队列中调度出一个进程执行
2. thread_set_priority函数修改
```C
void thread_set_priority (int new_priority) 
{
    ASSERT(PRI_MIN <= new_priority && new_priority <= PRI_MAX);  //保证优先级的有效性
    thread_current ()->priority = new_priority;    //更新当前进程优先级
    thread_yield();     //将当前进程放入就绪队列后重新调度进程执行
}
```
3. thread_priority_cmp函数
```C
static bool thread_priority_cmp(void *a, void *b)
{
    struct thread *ta = (struct thread *)a;
    struct thread *tb = (struct thread *)b;
    ASSERT(ta->fifo != tb->fifo);
    if (ta->priority == tb->priority)
        return ta->fifo > tb->fifo;
    return ta->priority < tb->priority;
}
```
4. thread_unblock函数修改
```C
void thread_unblock (struct thread *t) 
{
  enum intr_level old_level;
  ASSERT (is_thread (t));
  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  t->fifo = fifo++;
  heap_push(&ready_q, t);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}
```
### 优先级捐赠
#### 实现功能
1. 单一捐赠，一个进程捐赠给另一个进程
2. 多重捐赠，即多个进程给一个进程捐赠
3. 嵌套捐赠，例如A捐赠给B，B捐赠给C
4. 原始优先级保存
5. condvar和lock
#### 实现方法
主要有两个文件的修改，一个是synch，一个是thread。
#### 数据结构
- thread
```C
int base_priority;             /*初始优先级*/
struct list locks;             /*进程占用的锁*/
struct lock *lock_waiting;    /* 进程正在等待的锁 */
```
- lock
```C
struct thread *holder;      /* 该锁的拥有者 */
int max_priority;           /* 等待该锁的进程中的最高优先级 */
```
- cond
```C
struct condition
{
    struct semaphore semaphore; 
};
```
#### lock_acquire函数修改
```C
void lock_acquire(struct lock *lock)
{
    ASSERT (lock != NULL);
    ASSERT (!intr_context ());
    ASSERT (!lock_held_by_current_thread (lock));
struct thread *cur = thread_current();  
/*获取当前正在运行的进程，也就是请求获取该锁的进程*/
    bool success = lock_try_acquire(lock);           /*返回获取的结果*/
    if (!success)                                    /*获取失败*/
    {
        cur->lock_waiting = lock;
        if(lock->max_priority<cur->priority)    
/*锁的最大优先级小于当前进程的优先级*/
        { 
            lock->max_priority=cur->priority;        /*更新锁的优先级*/
            thread_update_priority(lock->holder);    /*开始进行优先级捐赠*/
        }
        sema_down(&lock->semaphore);                 /*执行P操作 阻塞该进程*/
        lock_acquire_success(lock);                  /*执行到这一步获取锁成功，需要进行一些处理*/
    }
   else                                              /*获取成功*/
   {
        cur->lock_waiting = NULL;
        lock->holder = cur;                           /*将锁的拥有者改为当前进程*/
        list_push_back(&cur->locks, &lock->elem);     /*将该锁放入进程拥有的锁的队列中*/
   }
}
```
#### thread_update_priority函数
```C
void thread_update_priority(struct thread *t)
{
    if (thread_mlfqs)
        return;
    ASSERT(is_thread(t));
    int old_priority = t->priority;
    t->priority = thread_get_donor_priority(t);
    if (t->priority < t->base_priority)
        t->priority = t->base_priority;
if (t->priority != old_priority && t->lock_waiting!= NULL)  
/*说明所有捐赠的优先级不如初始优先级，有可能重新设置了进程的优先级，设置的高了*/
        lock_update_priority(t->lock_waiting);       
/*那么就要重新更新自己在等待的锁的优先级*/
}
static int thread_get_donor_priority(struct thread *t)   /*得到该进程占用的所有锁中的最大的优先级*/
{
    if (list_empty(&t->locks))
        return PRI_MIN;
    return list_entry(list_max(&t->locks, lock_elem_priority_cmp, NULL), struct lock, elem)->max_priority;
}
```
#### lock_update_priority函数
```C
void lock_update_priority(struct lock *lock)
{
    if (thread_mlfqs)
        return;
    ASSERT(is_lock(lock));
    int old_priority = lock->max_priority;
lock->max_priority = lock_get_donor_priority(lock); 
/*锁从等待队列中取出优先级最高的进程的优先级*/
    if (lock->max_priority != old_priority)      /*更新锁的拥有者的优先级*/
        thread_update_priority(lock->holder);         
}
/*从锁的等待队列中取出优先级最高的进程的优先级*/
static int lock_get_donor_priority(struct lock *lock)  
{
    if (list_empty(&lock->semaphore.waiters))
        return PRI_MIN;
    return list_entry(list_max(&lock->semaphore.waiters, thread_elem_priority_cmp, NULL), struct thread, elem)->priority;
}
```
*说明：thread_update_priority和lock_update_priority互相调用，会不会出现死循环呢？可以分析一下，为什么需要两个函数互相调用，是为了解决一种特殊情况，某一进正在等待一个锁，也有比它优先级高的进程在等待这个锁，这时将这个进程的优先级设置为了最高的，那么对应的锁的max_priority也应该提高，因此调用lock_update_priority；然后lock_update_priority又调用thread_update_priority，由于这时不会再继续执行lock_update_priority了。*
#### lock_realse函数修改
```C
void lock_release(struct lock *lock)
{
    ASSERT (lock != NULL);
    ASSERT (lock_held_by_current_thread (lock));
    struct thread *cur = thread_current();
    lock->holder = NULL;           /*清空锁的占用者*/
    list_remove(&lock->elem);      /*将该锁从list中移除*/
    thread_update_priority(cur);   /*更新当前进程的优先级*/  
    sema_up(&lock->semaphore);     /*不要忘记执行V操作*/
}
```
#### cond相关
```C
void cond_wait(struct condition *cond, struct lock *lock)
{
    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));
    lock_release(lock);
    sema_down(&cond->semaphore);
    lock_acquire(lock);
}

void cond_signal(struct condition *cond, struct lock *lock UNUSED)
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));
  if (!list_empty(&cond->semaphore.waiters))
    sema_up(&cond->semaphore);
}
```
#### semaphore相关
```C
//V操作
void sema_up(struct semaphore *sema)
{
    enum intr_level old_level;
    ASSERT (sema != NULL);
    old_level = intr_disable();
    if (!list_empty(&sema->waiters))
        thread_unblock(thread_pop_highest_priority(&sema->waiters));   
//唤醒等待队列中优先级最高的进程
    sema->value++;
    intr_set_level(old_level);
    if (!intr_context())
        thread_yield();              //切换进程
}
//P操作
void sema_down(struct semaphore *sema)
{
    enum intr_level old_level;
    ASSERT (sema != NULL);
    ASSERT (!intr_context ());
    old_level = intr_disable();
    while (sema->value == 0)
    {
        list_push_back(&sema->waiters, &thread_current()->elem);
        thread_block();
    }
    sema->value--;
    intr_set_level(old_level);
}
struct thread *thread_pop_highest_priority(struct list *list)
{
    struct list_elem *tmp = list_max(list, thread_elem_priority_cmp, NULL);
    list_remove(tmp);
    return list_entry(tmp, struct thread, elem);
}
```
### 多级反馈队列
#### 实现功能
MLFQ调度的关键在于调度程序如何设置优先级。MLFQ并没有将每个工作的固定优先级放在首位，而是根据其观察到的行为来改变工作的优先级。例如，如果一个作业在等待键盘输入时重复地放弃了CPU，那么MLFQ将保持它的优先级高，因为这是一个交互过程的行为方式。相反，如果一份工作长期频繁地使用CPU，MLFQ将会降低它的优先级。这样，MLFQ将尝试在运行过程中了解进程，从而使用任务的历史来预测其未来的行为。
#### 实现原理
公式说明见[Pintos多级反馈队列（MLFQ）](https://zhuanlan.zhihu.com/p/436674359)
#### 数据结构
在thread结构体中增加如下
```C
int nice;                  /* How nice the thread should be to other threads. */
fp_t recent_cpu;
```
#### 浮点数运算
注意在Pintos操作系统中没有浮点型，我们要使用整型完成以上公式的计算。使用一个巧妙的方法，将32位的整型，分为两部分，1~16位代表小数部分，17~32位代表整数部分，明确了这一点，我们将自己定义的数据类型称为fp，我们重新定义fp数据类型的加减乘除。详见/pintos/src/threads/fixed_point.h文件。

#### 修改timer_intterrupt
每执行一次timer_interrupt，tick+1，而每隔4个tick，更新当前运行的线程的priority。
```C
/* Timer interrupt handler. */
static void timer_interrupt(struct intr_frame *args UNUSED)
{
    ticks++;
    thread_tick();     
    sleep_check(ticks);
    if (thread_mlfqs)
    {
        if(ticks % TIMER_FREQ == 0)  mlfqs_check();    /*每秒重新计算load_avg和每一个线程的recent_cpu*/
	else if(ticks % 4 == 0)    thread_mlfqs_update_priority(thread_current ());  /*每4个时钟进行一次priority更新*/
    }
}
/* 更新一下recent_cpu和load_avg，理论上不能被中断，需要作为原子操作执行*/
static void mlfqs_check(void)
{
    ASSERT(thread_mlfqs);
    enum intr_level old_level = intr_disable();
    thread_calc_recent_cpu();
    intr_set_level(old_level);
}
```
#### thread_mlfqs_update_priority函数
每秒重新计算线程的优先级
```C
/* priority = PRI_MAX - (recent_cpu / 4) - (nice * 2) */
static void thread_mlfqs_update_priority(struct thread *t)   
/*重新计算当前进程的优先级*/
{
    ASSERT(thread_mlfqs);
    ASSERT(is_thread(t));
    if (t == idle_thread)
        return;
    t->priority = PRI_MAX - fp_to_i(fp_div_i(t->recent_cpu, 4)) - t->nice * 2;
    if (t->priority > PRI_MAX)
        t->priority = PRI_MAX;
    if (t->priority < PRI_MIN)
        t->priority = PRI_MIN;
}
```
#### thread_calc_priority函数
用于计算函数优先级
```C
static void thread_calc_load_avg(void)
{
    int ready_threads = ready_q.size + (thread_current() != idle_thread);
    fp_t k1 = fp_div_fp(i_to_fp(59), i_to_fp(60));
    fp_t k2 = fp_div_fp(i_to_fp(1), i_to_fp(60));
    load_avg = fp_add_fp(fp_mul_fp(k1, load_avg), fp_mul_i(k2, ready_threads));
}
```

#### 函数补充
以下函数需要补充完整。
```C
void thread_set_nice(int nice)
{
    ASSERT(NICE_MIN <= nice && nice <= NICE_MAX);
    struct thread *cur = thread_current();
    cur->nice = nice;
    thread_mlfqs_update_priority(cur);   /*每次设置nice，相应的线程的priority也要更新*/
    thread_yield();
}

/* Returns the current thread's nice value. */
int thread_get_nice(void)
{
    return thread_current()->nice;
}

/* Returns 100 times the current system load average, rounded to the nearest integer. */
int thread_get_load_avg(void)
{
    return fp_to_i(fp_mul_i(load_avg, 100));
}
```

## Pintos用户程序
在开始之前首先要处理好process与thread的关系。从字面上讲，process是进程，thread是线程，一个进程应该可以拥有很多线程，但是在pintos中其实两者是同等的（如果想要自己搞PCB当然也可以，但只是为了通过测试点没有必要），process用于执行用户程序，同样需要thread的操作，因此可以将两者进行绑定。两者一一对应，可以通过threads找到对应的process，也能返回相应的process信息。

### 数据结构
- **process**
```C
struct process
{
    struct thread *thread;      /* 指向结构线程的指针*/
    pid_t pid;                  /* 进程标识符 */
    enum process_status status; /* 进程状态 */
    int exit_code;              /* 退出码 */
    struct list_elem allelem;   /* 用于存放所有进程 */
    struct list_elem elem;      /* 用于存放子进程 */
    struct list children;       /* 用于存放子进程 */
    struct process *parent;     /* 父进程 */
    struct semaphore sema_load; /* load时阻塞父进程 */
    struct semaphore sema_wait; /* wait阻塞父进程 */
    struct list files;          /* 打开的文件（链表） */
    struct file *file;          /* 存放load的文件 */
};
```
- **thread**
  
  可以通过threads找到对应的process，因此也能返回相应的process信息。
```C
#ifdef USERPROG
    struct process *process; /*thread和process的映射*/
    uint32_t *pagedir;       /* Page directory. */
#endif
```
- **open_file**
使用list维护某一process打开的文件。
```C
static struct open_file
{
    int fd;
    struct file *file;
    struct list_elem elem;
};
```
### 参数传递
目前，process_execute()不支持将参数传递给新进程。通过扩展 process_execute()来实现此功能，这样它就不会简单地将程序文件名作为其参数，而是将其划分为空格处的单词。第一个单词是程序名称，第二个单词是第一个参数，依此类推。也就是说，process_  execute("grepfoobar")应该运行 grep 传递两个参数 foo 和 bar。
在命令行中，多个空格等效于单个空格，因此 process_execute("grep foo bar") 等效于我们的原始示例。对命令行参数的长度施加合理的限制，项目限制为4KB。
#### 目标
- 分离从命令行中传入的文件名和各个参数
- 按照C函数调用的约定，将参数放入栈中
#### 1. 入栈
1. 将命令按空格拆开，分成一个个以“\0”结尾的字符串；
2. 从后往前循环，将esp往下压一个argv[i]的长度，然后把argv[i]给copy到那个地方；
3. 将esp接着往下压，压到是4的倍数（word align），为了让速度更快；
4. 把从argv[argc+1]一直到argv[0]的地址逐个写进去；
5. 再把中放argv[0]的地址的那个地址放进去；
6. 压进去一个argc，表示参数个数；
7. 最后压进去一个0，作为return address
```C
typedef union
{
    void *vp;
    char *cp;
    unsigned u;
    char **cpp;
    char ***cppp;
    int *ip;
    ret_addr_t *rap;
} esp_t;

static void *push_argument(esp_t esp, char *cmd, char *save_ptr)
{
    /* Push arguments. */
    char *arg_ptrs[1024];
    size_t i = 0;
    for (char *arg = cmd; arg != NULL; arg = strtok_r(NULL, " ", &save_ptr))
    {
        size_t size = strlen(arg) + 1;
        esp.cp -= size;
        strlcpy(esp.cp, arg, size);
        arg_ptrs[i++] = esp.cp;
    }
    int argc = i;
    arg_ptrs[i++] = NULL;
    /* Push word-align. 就是压到4的倍数*/
    esp.u -= esp.u % 4;
    /* Push argv[i]. */
    esp.cpp -= i;
    memcpy(esp.cpp, arg_ptrs, i * sizeof(char *));
    char **argv = esp.cpp;
    /* Push argv. */
    *(--esp.cppp) = argv;
    /* Push argc. */
    *(--esp.ip) = argc;
    /* Push fake return address. */
    *(--esp.rap) = 0;
    return esp.vp;
}
```
#### 2. 改写process_execute函数
- 需要对原来的文件名做一个备份
- 创建子进程启动用户程序
- 父进程需要等待子进程结束才能退出
```C
/*
创建一个新的线程运行用户程序
input: filename
output: tid
*/
tid_t process_execute(const char *file_name)
{
    /*如果进程不能被创建就返回TID_ERROR*/
    if (process_num == PROCESS_NUM_LIMIT)
        return TID_ERROR;
    /*进程数量增加*/
    ++process_num;
    char *fn_copy0, *fn_copy1;   /*由于strtok_r会改变原来的值，要做一个备份*/
    tid_t tid;
    /* Make a copy of FILE_NAME.Otherwise there's a race between the caller and load(). */
    fn_copy0 = palloc_get_page(0);/*palloc_get_page(0)动态分配了一个内存页*/
    if (fn_copy0 == NULL)         /*分配失败*/
        return TID_ERROR;
    /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
    fn_copy1 = palloc_get_page (0);
    if (fn_copy1 == NULL)
    {
        palloc_free_page(fn_copy0);
        return TID_ERROR;
    }
    /*
    把file_name 复制2份，PGSIZE为页大小
    */
    strlcpy (fn_copy0, file_name, PGSIZE);
    strlcpy (fn_copy1, file_name, PGSIZE);
    /* 创建一个新线程去执行 */
    char *save_ptr;
    char *cmd = strtok_r(fn_copy0, " ", &save_ptr);
    /*
    创建一个子进程 启动用户程序
    父进程要等待子进程结束才能继续向下执行
    因此在start_process中需要同步
    */
    tid = thread_create(cmd, PRI_DEFAULT, start_process, fn_copy1);
    if (tid == TID_ERROR)
        palloc_free_page(fn_copy1);
    palloc_free_page(fn_copy0);
    if (thread_current()->tid != 1 && tid != TID_ERROR)
    {
        struct process *self = thread_current()->process;
        struct process *child = get_process(tid);
        child->parent = self;
        list_push_back(&self->children, &child->elem);
    }
    return tid;
}
```
### 系统调用
系统调用的运行原理一定要看官方文档说明[Pintos Userprog](https://www.cs.jhu.edu/~huang/cs318/fall18/project/project2.html#SEC44)，系统调用如何访问用户地址，判断地址是否有效，关于其中包含用户地址，内核虚拟地址，实地址与虚拟地址的映射。

**syscall_handler**使用断言，地址必须是有效的，判断方式使用文档中第二种方法，使用is_user_vaddr和pagedir_get_page。
```C
USER_ASSERT(is_user_mem(f->esp, sizeof(void *)));
```
#### 1. void halt (void)
```C
static void halt(void)
{
    shutdown_power_off();
}
```
#### 2. void exit (int status)
终止当前用户程序，返回状态到内核，状态为0表示成功，非零值表示错误。
```C
static void exit(int status)
{
    struct process *self = thread_current()->process;
    while (!list_empty(&self->files))
    {
        struct open_file *f = list_entry(list_back(&self->files),
                                         struct open_file, elem);
        close(f->fd);
    }
    self->exit_code = status;
    thread_exit();
}
```
#### 3. pid_t exec (const char *cmd_line)
运行名称以cmd  行为单位的可执行文件，传递任何给定的参数，并返回新进程的程序 ID （pid）。 必须返回 pid -1，否则，如果程序由于任何原因无法加载或运行，则该 pid 不应是有效的 pid。 因此，在知道子进程是否成功加载其可执行文件之前，父进程无法从可执行文件返回。 您必须使用适当的同步来确保这一点。
```C
static pid_t exec(const char *cmd_line)
{
    USER_ASSERT(is_valid_str(cmd_line));
    lock_acquire(&file_lock);
    pid_t pid = process_execute(cmd_line);
    lock_release(&file_lock);
    if (pid == TID_ERROR)
        return -1;
    struct process *child = get_child(pid);
    sema_down(&child->sema_load);
    if (child->status == PROCESS_FAILED)
    {
        sema_down(&child->sema_wait);
        palloc_free_page(child);
        return -1;
    }
    else
    {
        ASSERT(child->status == PROCESS_NORMAL);
        return pid;
    }
}
```
#### 4. int wait (pid_t pid)
wait是本部分中的重点，也是难点，可以说是牵一发而动全身，需要完成父子进程之间的同步操作。但是父进程只能wait自己exce出去的子进程，这就需要知道父进程究竟有哪些子进程，我们使用一个list进行维护。这个调试起来也是最困难的。
1. 在 process_execute中，应将创建的子进程加入list children中。
每创建一个线程thread，创建一个process（就是thread的成员变量），就将process放入一个保存所有process的list中。然后通过tid号找到process，加入父进程的list children中。
2. 在process_wait中，通过子线程号，找到对应的子线程，如果没找到就直接返回；如果找到了，就使用sema_down阻塞，继续向下执行从所有process和child process中移除，返回退出码。
```C
static int wait(pid_t pid)
{
    return process_wait(pid);
}
int process_wait (tid_t child_tid UNUSED) 
{
    bool cur_init = thread_current()->tid == 1;
    struct process *child = cur_init ? get_process(child_tid) : get_child(child_tid);
    if (child == NULL)
        return -1;
    sema_down(&child->sema_wait);
    if (!cur_init)
        list_remove(&child->elem);
    list_remove(&child->allelem);
    int exit_code = child->exit_code;
    palloc_free_page(child);
    return exit_code;
}
```
#### 5. bool create (const char *file, unsigned initial_size)
创建一个名为file的新文件，该文件的初始大小字节大小为字节。如果成功，则返回 true，否则返回 false，注意创建新文件不会打开它。
```C
static bool create(const char *file, unsigned initial_size)
{
    USER_ASSERT(is_valid_str(file));
    lock_acquire(&file_lock);
    bool ret = filesys_create(file, initial_size);
    lock_release(&file_lock);
    return ret;
}
```

#### 6. bool remove (const char *file)
删除名为 file的文件。如果成功，则返回 true，否则返回 false。无论文件是打开的还是关闭的，都可能被删除，删除打开的文件不会关闭它。
```C
static bool remove(const char *file)
{
    USER_ASSERT(is_valid_str(file));

    lock_acquire(&file_lock);
    bool ret = filesys_remove(file);
    lock_release(&file_lock);

    return ret;
}
```
#### 7. int open (const char *file)
打开名为file的文件。返回一个称为"文件描述符"（fd）的非负整数句柄，如果无法打开文件，则返回 -1。 

编号为 0 和 1 的文件描述符是为控制台保留的：fd0（STDIN_FILENO）是标准输入，fd 1（STDOUT_FILENO）是标准输出。 打开的系统调用将永远不会返回这些文件描述符中的任何一个，这些文件描述符仅作为系统调用参数有效，如下所示。 
每个进程都有一组独立的文件描述符。 子进程不会继承文件描述符。 
当单个文件被打开多次时，无论是通过单个进程还是不同的进程，每个打开都会返回一个新的文件描述符。 单个文件的不同文件描述符在单独的关闭调用中独立关闭，并且它们不共享文件位置。 
```C
static int open(const char *file)
{
    USER_ASSERT(is_valid_str(file));
    lock_acquire(&file_lock);
    struct file *f = filesys_open(file);
    lock_release(&file_lock);
    if (f == NULL)
        return -1;
    struct process *self = thread_current()->process;
    struct open_file *open_file = malloc(sizeof(struct open_file));
    open_file->fd = self->fd++;
    open_file->file = f;
    list_push_back(&self->files, &open_file->elem);
    return open_file->fd;
}
```
#### 8. int filesize (int fd)
返回以fd形式打开的文件的大小（以字节为单位）。 
```C
static int filesize(int fd)
{
    struct open_file *f = get_file_by_fd(fd);

    lock_acquire(&file_lock);
    int ret = file_length(f->file);
    lock_release(&file_lock);

    return ret;
}
```

#### 9. int read (int fd, void *buffer, unsigned size)
将大小字节从以 fd形式打开的文件读入缓冲区。 返回实际读取的字节数（文件末尾为 0），如果无法读取文件（由于文件末尾以外的情况），则返回 -1。 Fd 0 使用 input_getc（）从键盘读取。 
```C
static int read(int fd, void *buffer, unsigned size)
{
    USER_ASSERT(is_user_mem(buffer, size));
    USER_ASSERT(fd != STDOUT_FILENO);
    if (fd == STDIN_FILENO)
    {
        uint8_t *c = buffer;
        for (unsigned i = 0; i != size; ++i)
            *c++ = input_getc();
        return size;
    }
    struct open_file *f = get_file_by_fd(fd);
    lock_acquire(&file_lock);
    int ret = file_read(f->file, buffer, size);
    lock_release(&file_lock);

    return ret;
}
```
#### 10. int write (int fd, const void *buffer, unsigned size)
判断内存是否能够写入
写入控制台
调用函数file_write

```C
static int write(int fd, const void *buffer, unsigned size)
{
    USER_ASSERT(is_user_mem(buffer, size));
    USER_ASSERT(fd != STDIN_FILENO);
    if (fd == STDOUT_FILENO)
    {
        putbuf((const char *)buffer, size);
        return size;
    }
    struct open_file *f = get_file_by_fd(fd);
    lock_acquire(&file_lock);
    int ret = file_write(f->file, buffer, size);
    lock_release(&file_lock);
    return ret;
}
```
#### 11. void seek (int fd, unsigned position)
将要在打开的文件fd中读取或写入的下一个字节更改为位置，以字节表示，从文件的开头开始。（因此，一个位置 0 是文件的开始位置。 
查找超过文件当前末尾不是错误。稍后读取获取 0 字节，指示文件结束。稍后的写入操作会扩展文件，用零填充任何未写入的间隙，文件的长度是固定的，因此在文件末尾写入后将返回错误。
```C
static void seek(int fd, unsigned position)
{
    struct open_file *f = get_file_by_fd(fd);
    lock_acquire(&file_lock);
    file_seek(f->file, position);
    lock_release(&file_lock);
}
```
#### 12. unsigned tell (int fd)	
返回要在打开的文件fd中读取或写入的下一个字节的位置，以字节表示自文件开头开始。
```C
static unsigned tell(int fd)
{
    struct open_file *f = get_file_by_fd(fd);

    lock_acquire(&file_lock);
    int ret = file_tell(f->file);
    lock_release(&file_lock);
    return ret;
}
```
#### 13. void close (int fd)
关闭文件描述符fd，退出或终止进程会隐式关闭其所有打开的文件描述符.
```C
static void close(int fd)
{
    struct open_file *f = get_file_by_fd(fd);
    lock_acquire(&file_lock);
    file_close(f->file);
    lock_release(&file_lock);
    list_remove(&f->elem);
    free(f);
}
```
### 拒绝执行可执行文件
添加代码以拒绝写入作为可执行文件使用的文件。之所以这样做，是因为如果进程尝试运行磁盘上正在更改的代码，则会出现不可预知的结果。

当一个进程试图运行正在磁盘中被修改的文件。Pintos提供了file_deny_write()函数用来禁止对打开的文件进行写操作，file_allow_write()函数用来对文件允许写入。同时，当一个文件被关闭后也可以写入。 file_deny_write断言判断文件是否为空，其次将文件置为不可被写入状态并且修改该文件的索引节点内容。最后将进程当下打开的文件指针指向file。

在process中增加file list管理process打开的文件。
1. 在成功start_process后，禁止文件被写入：
```C
static void process_load_success(const char *cmd)
{
    struct process *self = thread_current()->process;
    self->status = PROCESS_NORMAL;
    self->file = filesys_open(cmd);
    file_deny_write(self->file);
    sema_up(&self->sema_load);
}
```
2. process_exit末尾增加以下内容：
```C
if (self->file != NULL)
{
    file_allow_write(self->file);
    file_close(self->file);
}
```

