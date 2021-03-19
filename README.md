## STPortScanner

![STPortScanner](https://github.com/DebugST/STPortScanner/blob/main/Images/Screen%20Shot%202021-03-18%20at%2016.27.01.png)

![STPortScanner](https://github.com/DebugST/STPortScanner/blob/main/Images/Screen%20Shot%202021-03-18%20at%2017.30.50.png)

## 关于作者
* Blog: [Crystal_lz](http://st233.com)
* Mail: (2212233137@qq.com)

## 可执行程序参数

```cs
 --------------------------------[STPScan  4.0]--------------------------------
-h     Host ......................................... [默认:未指定]
       -h target.com,192.168.0.1,192.168.0.2-192.168.1.254,192.168.0.0/24
-hf    Host from file 从文件加载'\n'分割 ............ [默认:未指定]
       -hf ./iplist.txt
-p     Port ......................................... [默认:Top 300]
       -p 21,22,80,443,8000-8080
-pf    Port from file 从文件加载'\n'分割 ............ [默认:未指定]
       -pf ./portlist.txt       
-np    Null Probe 空探测包 .......................... [默认:未指定]
-pr    The count of probes 进行多少次协议探测........ [默认:2]
       -pr 3
-i     ICMP only 仅扫描存活主机 ..................... [默认:未指定]
       该操作需要管理员权限和server系统
-is    ICMP + Scan 先扫描存活主机再扫描 ............. [默认:未指定]
-t     Timeout 超时时间 ............................. [默认:5]
       -t 3
-tt    TotalTimeout 一个任务总超时时间 .............. [默认:60]
       -tt 50
-r     Retry 重试次数 ............................... [默认:2]
       -r 5
-st    Tcp Scan 使用TCP方式扫描 ..................... [默认:已指定]
-su    Udp Scan 使用UDP方式扫描 ..................... [默认:未指定]
-ss    Syn Scan 使用SYN方式扫描 ..................... [默认:未指定]
       该操作需要管理员权限和server系统
-smb   Only scan 445 通过smb探测系统版本(仅扫描445) . [默认:未指定]
-con   Concurrent of Scanner 并发数 ................. [默认:6000]
       -con 20000
-stop  Stop 当扫描到指定协议时 停止该主机扫描 ....... [默认:未指定]
       -stop http,https
-order The priority of scanning 优先扫描顺序 ........ [默认:rnd]
       -order (host or port or rnd)
-delay The delay 控制台进度刷新时间 ................. [默认:2]
       -delay 5
-cd    Console Display 控制台显示方式 ............... [默认:2]
       -cd (0 or 1 or 2)
           0  Not display
           1  xxx.xxx.xxx.xxx:xxx [Protocol]
           2  xxx.xxx.xxx.xxx:xxx [Protocol][RegexLine][Banner]
-o     Out to file 输出结果到文件 ................... [默认:未指定]
       -o ./result.txt
-f     Format for output 输出文件格式................ [默认:json:h,pr,b]
       -f (json or csv):(fields)
           h  Host                    [127.0.0.1:8080]
           a  Address                 [127.0.0.1]
           p  Port                    [8080]
           pt Protocol Type           [TCP]
           pf Protocol Flag           [http]
           pr Protocol                [(TCP)http]
           l  Line for regexpression  [123]
           b  Banner                  [SSH-2.0-Ubuntu-Server]
           d  Hex data for recv       [485454502F312E312032...]
-cn    Convert Nmap config file  转换nmap配置文件为当前扫描器适配文件
       parameters [Nmap config file] [Save file for STPscan]
       -cn [./nmap-service-probes] [./config_nmap.st]

 -2021-03-19----------------Powered by -> Crystal_lz-----------------ST233.COM-
注:
    icmp 与 syn 不能同时使用 并不推荐使用这两个选项 测试阶段
    Null Probe -> 是否使用空探测包 
    若使用
        连通后先等待对方返回banner(如:mysql,ftp主动返回banner协议等) 直到超时才进行下一次探测
    否则
        连通后立即发送探测包
    区别
        不使用 将影响收到banner是进行规制匹配的顺序 将优先使用发送的探测包的规则匹配
        再进行空探测包的规则进行匹配(mysql,ftp等协议无需探测包的规则)
        不使用速度快精度低 使用速度慢进度高
    
eg:
    STPScan -h 192.168.1.1/24
    STPScan -h 192.168.1.1/24 -pr 3
    STPScan -h 192.168.1.1/24 -smb
    STPScan -h 192.168.1.1/24 -p 80,443,8000-8080 -pr 3
    STPScan -h 192.168.1.1/24 -o result.json
    STPScan -h 192.168.1.1/24 -o result.csv -f csv:h,pr,d
```
## 调用库接口
```cs
[Interface]
    IPortScanner : IDispose
    
[Configer Class]
    ProbeConfiger
    
[Scanner Class]
    PortScanner : IPortScanner
    TCPScanner  : PortScanner
    UDPScanner  : PortScanner
    SYNScanner  : PortScanner
    SmbScanner  : PortScanner
    IcmpScanner : IDispose
    
[Other Class]
    IcmpEventArgs : EventArgs
    ScanEventArgs : EventArgs
    RawSocket
    
[RawSocket]
    static RawSocket.Dispose();
    static RawSocket.InitRawSocket(EndPoint bindEndPoint);
    static RawSocket.SendData(byte[] byBuffer);
    static RawSocket.RecvCompleted -> EventHandler<SocketAsyncEventArgs>;
    
[IPortScanner]
    event ScanEventHandler Completed;
    uint Scan(uint uIP, int nPort);
    uint Scan(uint uIP, int nPort, int nProbes);
    uint Scan(uint uIP, int nPort, int nProbes, int nTimeout);
    uint Scan(uint uIP, int nPort, int nProbes, int nTimeout, int nRetry);
    uint Scan(uint uIP, int nPort, int nProbes, int nTimeout, int nRegry, int nTotalTimeout);
    uint Scan(uint uIP, int nPort, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbes);
    uint Scan(string strIP, int nPort);
    uint Scan(string strIP, int nPort, int nProbes);
    uint Scan(string strIP, int nPort, int nProbes, int nTimeout);
    uint Scan(string strIP, int nPort, int nProbes, int nTimeout, int nRetry);
    uint Scan(string strIP, int nPort, int nProbes, int nTimeout, int nRetry, int nTotalTimeout);
    uint Scan(string strIP, int nPort, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbes);
    uint Scan(int nPort, EndPoint endPoint, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbes);
        return         -> TaskID
        nProbes        -> 最多进行多少次探测
        nRetry         -> 重试次数
        bUseNullProbes -> 是否使用空探测包 
                
[EventArgs]
    IcmpEventArgs : EventArgs
        .Address
        .TTL
        .CanAccess
        .Times
        
    ScanEventArgs : EventArgs
        .TaskID 
        .CanConnect
        .EndPoint
        .Protocol
        .RegexLine
        .Banner
        .Data
        .Length
        .ErrorMessage
        
[EG]
    ProbeConfiger pc = new ProbeConfiger(
                File.ReadAllText("./config_probes.st"),
                File.ReadAllText("./config_defports.st")
                );
    IPortScanner ps = new TCPScanner(3000, pc);
    or
    PortScanner ps = new UDPScanner(3000, pc);
    //PortScanner ps = new SYNScanner(3000, pc);
    //PortScanner ps = new SmbScanner(3000);
    ps.Completed += m_scanner_Completed;
    
    void m_scanner_Completed(object sender, ScanEventArgs e) {
        if(e.CanConnect) Console.Write(e.EndPoint + "\t" + e.Protocol);
    }
    
    ps.Scan("127.0.0.1",80);
```
