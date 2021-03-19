using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.IO;

namespace STPortScanner
{
    public class ScannerConfiger
    {
        public static bool IsSMB;
        public static bool IsIcmp;
        public static bool IsIcmpScan;
        public static bool IsUserNullProbe;
        //public static StreamWriter Writer;
        public static int Retry = 1;
        //public static int MaxTask = 6000;
        public static int Timeout = 5000;
        public static int TotalTimeout = 60000;
        public static int Delay = 2000;
        public static int ConsoleDisplay = 2;
        public static int ProbesCount = 2;
        public static int Concurrent = 6000;
        public static string ScanningOrder = "rnd";
        public static string ProtocolType = "TCP";
        public static string OutputType = "JSON";
        public static string[] OutputFields = new string[] { "h", "pr", "b" };
        public static Dictionary<string, HashSet<string>> DomainDic = new Dictionary<string, HashSet<string>>();
        public static HashSet<string> StopProto = new HashSet<string>();
        public static List<Range> IPRange = new List<Range>();

        public static int[] PortList = new int[]{
            80, 443, 8080, 161, 7547, 5060, 22, 1720, 53, 21, 
            123, 3389, 110, 995, 25, 8000, 8081, 23, 554, 3306, 
            49154, 8443, 49152, 8088, 5432, 49153, 8888, 9092, 6379, 4433, 
            5000, 81, 9200, 9000, 47001, 43, 8008, 49156, 1080, 5353, 
            8090, 8181, 5985, 888, 8899, 88, 8087, 9090, 7777, 9001, 
            8282, 5580, 7000, 139, 50000, 8989, 7001, 6588, 6666, 2000, 
            999, 12345, 7100, 1433, 1212, 1010, 1521, 27017, 666, 1527, 
            11211, 137, 1434, 63, 50, 49, 115, 162, 20, 555, 
            66, 51, 65, 138, 47, 111, 993, 1688, 8010, 9100, 
            587, 27036, 10001, 9010, 8082, 5001, 6000, 2323, 7002, 2105, 
            8001, 3128, 5555, 10000, 2869, 5999, 9999, 6010, 7008, 5002, 
            7007, 10443, 548, 5632, 6667, 9987, 9390, 7887, 8770, 6163, 
            64738, 5683, 5008, 8009, 5232, 8089, 8099, 10080, 500, 8889, 
            8083, 9991, 4899, 800, 6699, 7070, 7788, 8002, 9080, 631, 
            465, 2049, 15000, 8222, 31337, 27910, 808, 25565, 26000, 143, 
            8789, 8880, 13720, 13783, 13722, 8767, 19150, 17555, 11371, 5701, 
            4369, 60087, 8091, 9930, 8003, 623, 10002, 50505, 51234, 9869, 
            7878, 8881, 8084, 20000, 515, 3050, 6543, 3784, 3632, 3483, 
            8004, 8085, 3000, 8006, 992, 8686, 8005, 5009, 60000, 11210, 
            3130, 6789, 1194, 7, 8999, 9002, 7443, 9443, 69, 27950, 
            4443, 2809, 11001, 5061, 9003, 2481, 8883, 2638, 55555, 2600, 
            8007, 636, 13246, 901, 10003, 98, 5986, 5900, 33015, 6060, 
            19800, 994, 20547, 2401, 2303, 9005, 37718, 6443, 2375, 79, 
            3689, 9101, 8728, 37435, 8050, 15001, 8887, 11099, 10005, 6050, 
            2302, 14000, 10162, 6005, 9102, 18264, 70, 5222, 12346, 7200, 
            6003, 60443, 9099, 706, 10161, 7776, 6969, 7272, 9004, 8884, 
            9030, 8051, 7144, 7800, 6600, 8885, 16000, 8890, 9088, 12546, 
            6009, 12446, 50020, 32770, 41523, 7171, 6007, 9050, 30722, 30724, 
            50015, 30710, 9500, 9103, 27964, 27960, 30444, 33000, 9096, 30720, 
            31099, 4000, 8882, 27962, 626, 27000, 28138, 9098, 31416, 27914
        };
    }
}
