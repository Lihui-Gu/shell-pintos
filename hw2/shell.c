#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <pwd.h>
#include "tokenizer.h"
#include <sys/wait.h>
#include <sys/stat.h> 
#include <signal.h>   
#define MAX_PROMPT 1024
#define MAXLINE 4096 //the length of all args is ARG_MAX
#define MAXARG 20
char *buffer;
const int max_name_len = 256;
const int max_path_len = 1024;
#define MAXLINE 4096 
#define MAXARG 20
#define BUFFSIZE 512
#define MAXPIDTABLE 1024
/*pw_dir   当前路径*/
/*pw_name  用户名  */
struct passwd *pwd;
/* Convenience macro to silence compiler warnings about unused function parameters. */
#define unused __attribute__((unused))

/* Whether the shell is connected to an actual terminal or not. */
bool shell_is_interactive;

/* File descriptor for the shell input */
int shell_terminal;

/* Terminal mode settings for the shell */
struct termios shell_tmodes;

/* Process group id for the shell */
pid_t shell_pgid;

void type_prompt(char *prompt);  //打印终端提示符
char *get_fullpath(char *name);
int cmd_exit(struct tokens* tokens);
int cmd_help(struct tokens* tokens);
int cmd_cd(unused struct tokens *tokens);
int cmd_pwd(unused struct tokens *tokens);
void sig_handler(int sig);

bool flag=false;   //是否包含&  
/* Built-in command functions take token array (see parse.h) and return int */
typedef int cmd_fun_t(struct tokens* tokens);

/* Built-in command struct and lookup table */
typedef struct fun_desc {
  cmd_fun_t* fun;
  char* cmd;
  char* doc;
} fun_desc_t;

/*创建一个结构体用于解析参数*/
struct ch_process {
	int tokens_len;
	int next_token;
	char **args;
    /*用于重定向*/
    int in_fd;                
	int out_fd;
	int out_attr;
};


pid_t BPTable[MAXPIDTABLE];   //进程号
pid_t FPTable[MAXPIDTABLE];   //进程号

void sig_handler(int sig)
{
    pid_t pid;
    int i;
    for(i=0;i<MAXPIDTABLE;i++)
        if(BPTable[i] != 0)            //only handler the background processes
        {
            pid = waitpid(BPTable[i],NULL,WNOHANG);
            if(pid > 0)
            {
                printf("process %d exited.\n",pid);
                BPTable[i] = 0;                  //clear
            }
            else if(pid < 0)
            {
	            if(errno != ECHILD)
                    perror("waitpid error");
            }
            //else:do nothing.  pid=0
         }
    return;
}

/*打印终端提示符*/
void type_prompt(char *prompt)
{
    char hostname[max_name_len];
    char pathname[max_path_len];
    int length;
    pwd = getpwuid(getuid());             //getpwuid获取用户的数据结构
    getcwd(pathname,max_path_len);        //将当前工作目录的绝对路径复制到参数buffer所指的内存空间中
    
    if(gethostname(hostname,max_name_len)==0)         //返回本地主机的标准主机名
        sprintf(prompt,"[glhshell]%s@%s:",pwd->pw_name,hostname);
    else
        sprintf(prompt,"[glhshell]%s@unknown:",pwd->pw_name);  //无法获取主机名
    length = strlen(prompt);

    if(strlen(pathname) < strlen(pwd->pw_dir) ||                    //  长度小说明不在用户文件下
            strncmp(pathname,pwd->pw_dir,strlen(pwd->pw_dir))!=0)   //  前缀不一样，不在该用户目录下，在另一个用户目录下
        sprintf(prompt+length,"%s",pathname);
    else
        sprintf(prompt+length,"~%s",pathname+strlen(pwd->pw_dir));
    length = strlen(prompt);
    if(geteuid()==0)                           //是否为有效用户的ID，root身份返回0
        sprintf(prompt+length,"#");            //root身份以'#'号结尾
    else
        sprintf(prompt+length,"$");            //一般用户身份以'$'号结尾
    return;
}

/*用于解析参数的函数*/
void parse_args(struct ch_process *ch, struct tokens *tokens)
{
	char *token;
	int finish = 0;
	while (ch->next_token < ch->tokens_len && !finish) {
		token = tokens_get_token(tokens, ch->next_token);
		/* if first char of token is < or >, break */
		finish = (token[0] == '<' || token[0] == '>');
		/* if not finish, !finish 1, 
		then args[next_token] = token, then next_token inccrease
		else if finish, args[next_token] = NULL, 
		and next_token refer to the first < or > or >> */
		/* This line may be hard to understand, but it can avoid IF branch */
		ch->args[ch->next_token] = (char *)((!finish) * (int64_t)(void*)(token));
		ch->next_token += !finish;
	}
	
	ch->args[ch->next_token] = NULL;
}


void parse_redirection(struct ch_process *ch, struct tokens *tokens)
{
	/* next_tocken start from the first < or > or >>
	for example, if `program > foo`, then arrow = >, path = foo */
	char * arrow;
	int attr;
	arrow = tokens_get_token(tokens, ch->next_token++);
	if (ch->next_token >= ch->tokens_len) {
		/* next_token is out of range, no filename next to < or > or >> */
		return;
    }
    char* path = tokens_get_token(tokens, ch->next_token++);
	switch(arrow[0]) {
		case '<':
			/* redirect standard input.
			If there are multiple '<' in command line, such as `prog < foo1 < foo2`,
			the last one would be active */
			if (access(path, R_OK) == 0) {
				ch->in_fd = open(path,O_CREAT|O_RDONLY, 0666);
				dup2(ch->in_fd, 0);
				close(ch->in_fd);
			} else {
				printf("%s is not exsist or readable\n", path);
				return;
			}
			break;
		case '>':
			attr=O_RDWR|O_CREAT|O_TRUNC;
			ch->out_attr = attr;
			ch->out_fd = open(path, attr, 0664);	/* -rw-rw-r-- */
			dup2(ch->out_fd, 1);
			close(ch->out_fd);
		}
	return;
}


/* 创建一个子进程进行执行 */
int run_program(struct tokens *tokens)
{
	int tokens_len = tokens_get_length(tokens);
	if (tokens_len == 0)	/* no input */
		exit(0);


	char *args[tokens_len + 1];
	struct ch_process child = { 0 };
	child.tokens_len = tokens_len;
	child.next_token = 0;
	child.args = args;

    parse_args(&child, tokens);
	if(strcmp(child.args[tokens_len-1],"&") ==0)
    {
        flag=true;
        child.args[tokens_len-1] = NULL;
        tokens_len--;
    }
	
    char* path=get_fullpath(child.args[0]);      //获取完整的目录文件
	pid_t chpid;
    switch(chpid = fork()) {
        // 如果 fork 出错，可以提示维护信息
        case -1:
            printf("fork : %s\n", strerror(errno));
		    return -1;
        // 处理子进程
        case 0:
			if(!flag)              //flag=false说明 子进程为前台程序
			{
				int i;
                for(i=0;i<MAXPIDTABLE;i++)
				{
					if(FPTable[i]==0)
                        FPTable[i] = chpid;    //register a background process
						break;
				}
                if(i==MAXPIDTABLE)
                    perror("Too much background processes\nThere will be zombine process");
			}
		    parse_redirection(&child, tokens);
			execv(path, args);
        default:{    //父进程
		    if(flag)
			{
				printf("Child pid:%u\n",chpid);
                int i;
                for(i=0;i<MAXPIDTABLE;i++)
				{
					if(BPTable[i]==0)
                        BPTable[i] = chpid;            //register a background process
						break;
				}
                if(i==MAXPIDTABLE)
                    perror("Too much background processes\nThere will be zombine process");  
			}
			else
			{
				int status;
			    waitpid(chpid, &status, 0); //等待子进程返回
			    // 处理子进程的返回码
			}
        }
        break;
    }
	return 0;
}

fun_desc_t cmd_table[] = {
    { cmd_help, "?", "show this help menu" },
	{ cmd_exit, "exit", "exit the command shell" },
	{ cmd_cd, "cd", "change the working directory" },
	{ cmd_pwd, "pwd", "print name of current/working directory" }
};

/* change working directory */
int cmd_cd(unused struct tokens *tokens)
{
	char *dst = NULL;
	int res = -1;

	switch (tokens_get_length(tokens)) {
	case 1:	          /* 当没有路径作为参数传入, if HOME is given, cd $HOME */
		dst = getenv("HOME");
		break;
	case 2:          /*使用库函数chdir()来更改当前程序的工作目录*/
		dst = tokens_get_token(tokens, 1);
		break;
	default:         /*cd 命令 只能由一个参数*/
		printf("too many argument\n");
	}
	if (dst == NULL)
		return -1;
	if(chdir(dst)!= 0)
	{
		printf("No such file or directory\n");
	}
	return res;
}



/* get current full path 直接使用getcwd库函数即可*/
int cmd_pwd(unused struct tokens *tokens)
{
	char *path = getcwd(NULL, 0);
	if (path == NULL) {
		printf("%s\n", strerror(errno));     //输出error对应的错误信息
		return -1;
	}
	printf("%s\n", path);
	free(path);
	return 0;
}



/* Prints a helpful description for the given command */
int cmd_help(unused struct tokens* tokens) {
  for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++)
    printf("%s - %s\n", cmd_table[i].cmd, cmd_table[i].doc);
  return 1;
}

/* Exits this shell */
int cmd_exit(unused struct tokens* tokens) { exit(0); }

/* Looks up the built-in command, if it exists. */
int lookup(char cmd[]) {
  for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++)
    if (cmd && (strcmp(cmd_table[i].cmd, cmd) == 0))
      return i;
  return -1;
}

/* Intialization procedures for this shell */
void init_shell() {
  /* Our shell is connected to standard input. */
  shell_terminal = STDIN_FILENO;

  /* Check if we are running interactively */
  shell_is_interactive = isatty(shell_terminal);

  if (shell_is_interactive) {
    /* If the shell is not currently in the foreground, we must pause the shell until it becomes a
     * foreground process. We use SIGTTIN to pause the shell. When the shell gets moved to the
     * foreground, we'll receive a SIGCONT. */
    while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp()))
      kill(-shell_pgid, SIGTTIN);

    /* Saves the shell's process id */
    shell_pgid = getpid();

    /* Take control of the terminal */
    tcsetpgrp(shell_terminal, shell_pgid);

    /* Save the current termios to a variable, so it can be restored later. */
    tcgetattr(shell_terminal, &shell_tmodes);
  }
}

/*根据用户输入的路径返回一个完整的路径*/
char *get_fullpath(char *name)
{
	char *val = getenv("PATH");         //获取path变量下
	int i, j, len;
	char *path = (char *)malloc(BUFSIZ);
	/* if name is already full path */
	strcpy(path, name);
	/*access系统调用用来判断某个文件或者目录是否具有某种属性*/
	if (access(path, X_OK) == 0)         //X_OK就是判断其是否可执行
		return path;
	/* 列出 $PATH and search reachable path */
	len = strlen(val);
	i = 0;
	while (i < len) {
		j = i;
		while (j < len && val[j] != ':')
			j++;
		int k = j - i;
		memset(path, 0, BUFSIZ);
		strncpy(path, val + i, k);
		path[k] = '/';
		strcpy(path + k + 1, name);
		if (access(path, X_OK) == 0)
			return path;
		i = j + 1;
	}
	free(path);
	return NULL;
}


int main(unused int argc, unused char* argv[]) {
    init_shell();
    char prompt[1024];        //终端提示符
    static char line[4096];

	/*初始化BP*/
    for(int i=0;i<MAXPIDTABLE;i++)
        BPTable[i] = 0;
    /*初始化FP*/
    for(int i=0;i<MAXPIDTABLE;i++)
        BPTable[i] = 0;
    /* Please only print shell prompts when standard input is not a tty */
    if (shell_is_interactive)
    {
	  type_prompt(prompt);
      printf("%s",prompt);               //打印终端提示符

    }

    if(signal(SIGCHLD,sig_handler) == SIG_ERR)
        perror("signal() error");
    signal(SIGINT, SIG_IGN);
    while (fgets(line, 4096, stdin)) {
		/* Split our line into words. */
		struct tokens* tokens = tokenize(line);

		/* Find which built-in function to run. */
		int fundex = lookup(tokens_get_token(tokens, 0));
		/*先从内建命令中找*/
		if (fundex >= 0) {
		cmd_table[fundex].fun(tokens);
		} 
		else if(run_program(tokens)<0){
			fprintf(stdout, "This shell doesn't know how to run programs.\n");
		}

		if (shell_is_interactive)
		/* Please only print shell prompts when standard input is not a tty */
		{
		type_prompt(prompt);
		printf("%s",prompt);               //打印终端提示符
		}

		/* Clean up memory */
		tokens_destroy(tokens);
  }

  return 0;
}
