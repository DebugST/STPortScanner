using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.IO;
using System.Net;
using System.Text.RegularExpressions;

using ST.Library.Network;

namespace STPortScanner
{
    public class ScannerStatic
    {
        private static StreamWriter m_writer;
        private static char[] m_split = new char[] { '-', '/' };
        private static StringBuilder m_sb_buffer = new StringBuilder();
        private static Dictionary<string, byte> m_dic_ip = new Dictionary<string, byte>();
        private static object m_obj_sync = new object();

        static ScannerStatic() {
            m_dic_ip = new Dictionary<string, byte>();
            for (int i = 0; i < 256; i++) m_dic_ip.Add(i.ToString(), (byte)i);
        }
        //字节反转
        public static ushort Reverse(ushort num) {
            return (ushort)((num << 8) | (num >> 8));
        }
        //反转字节
        public static uint Reverse(uint num) {
            uint temp = (num << 24);
            temp |= (num << 8) & 0x00FF0000;
            temp |= (num >> 8) & 0x0000FF00;
            temp |= (num >> 24) & 0x000000FF;
            return temp;
        }

        public static uint IPToINT(string strIP) {
            return ScannerStatic.IPToINT(strIP, false);
        }

        public static uint IPToINT(string strIP, bool bBig) {
            uint num = 0;
            string[] strs = strIP.Split('.');
            if (!bBig) {
                num = m_dic_ip[strs[3]];
                num <<= 8;
                num |= m_dic_ip[strs[2]];
                num <<= 8;
                num |= m_dic_ip[strs[1]];
                num <<= 8;
                num |= m_dic_ip[strs[0]];
            } else {
                num = m_dic_ip[strs[0]];
                num <<= 8;
                num |= m_dic_ip[strs[1]];
                num <<= 8;
                num |= m_dic_ip[strs[2]];
                num <<= 8;
                num |= m_dic_ip[strs[3]];
            }
            return num;
        }

        //=======================================================

        public static void ShowInfo() {
            string strText = "-h     Host ......................................... [default:not specified]\r\n"
                            + "       -h target.com,192.168.0.1,192.168.0.2-192.168.1.254,192.168.0.0/24\r\n"
                            + "-hf    Host from file split with '\\n' ............... [default:not specified]\r\n"
                            + "       -hf ./iplist.txt\r\n"
                            + "-p     Port ......................................... [default:Top 300]\r\n"
                            + "       -p 21,22,80,443,8000-8080\r\n"
                            + "-pf    Port from file split with '\\n' ............... [default:not specified]\r\n"
                            + "       -pf ./portlist.txt\r\n"
                            + "-np    Null Probe ................................... [default:not specified]\r\n"
                            + "-pr    The count of probes .......................... [default:1]\r\n"
                            + "       -pr 3\r\n"
                            + "-i     ICMP only .................................... [default:not specified]\r\n"
                            + "       This operation requires an administrator and Windows Server\r\n"
                            + "-is    ICMP + Scan .................................. [default:not specified]\r\n"
                            + "-t     Timeout ...................................... [default:5]\r\n"
                            + "       -t 3\r\n"
                            + "-tt    TotalTimeout ................................. [default:60]\r\n"
                            + "       -tt 30\r\n"
                            + "-r     Retries ...................................... [default:3]\r\n"
                            + "       -r 5\r\n"
                            + "-st    Tcp Scan ..................................... [default:specified]\r\n"
                            + "-su    Udp Scan ..................................... [default:not specified]\r\n"
                            + "-ss    Syn Scan ..................................... [default:not specified]\r\n"
                            + "       This operation requires an administrator and Windows Server\r\n"
                            + "-smb   Only scan 445 ................................ [default:not specified]\r\n"
                            + "-con   Concurrent of Scanner ........................ [default:6000]\r\n"
                            + "       -con 20000\r\n"
                            + "-stop  Stop current host when some protocol was found [default:not specified]\r\n"
                            + "       -stop http,https\r\n"
                            + "-order The priority of scanning ..................... [default:rnd]\r\n"
                            + "       -order (host or port or rnd)\r\n"
                            + "-delay The delay of show progress ................... [default:2]\r\n"
                            + "       -delay 5\r\n"
                            + "-cd    Console Display .............................. [default:2]\r\n"
                            + "       -cd (0 or 1 or 2)\r\n"
                            + "           0  Not display\r\n"
                            + "           1  xxx.xxx.xxx.xxx:xxx [Protocol]\r\n"
                            + "           2  xxx.xxx.xxx.xxx:xxx [Protocol][RegexLine][Banner]\r\n"
                            + "-o     Out to file .................................. [default:not specified]\r\n"
                            + "       -o ./result.txt\r\n"
                            + "-f     Format for output ............................ [default:json:h,pr,b]\r\n"
                            + "       -f (json or csv):(fields)\r\n"
                            + "           h  Host                    [127.0.0.1:8080]\r\n"
                            + "           a  Address                 [127.0.0.1]\r\n"
                            + "           p  Port                    [8080]\r\n"
                            + "           pt Protocol Type           [TCP]\r\n"
                            + "           pf Protocol Flag           [http]\r\n"
                            + "           pr Protocol                [(TCP)http]\r\n"
                            + "           l  Line for regexpression  [123]\r\n"
                            + "           b  Banner                  [SSH-2.0-Ubuntu-Server]\r\n"
                            + "           d  Hex data for recv       [485454502F312E312032...]\r\n"
                            + "-cn    Convert Nmap config file\r\n"
                            + "       parameters [Nmap config file] [Save file for STPscan]\r\n"
                            + "       -cn [./nmap-service-probes] [./config_nmap.st]";
            var clr = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(" --------------------------------[STPScan  4.0]--------------------------------");
            foreach (var strLine in strText.Split('\n')) {
                string str = strLine.TrimEnd();
                if (str[0] == '-') {
                    string[] strInfo = str.Split('[');
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    if (strInfo[0].IndexOf('.') != -1) {
                        Console.Write(strInfo[0].Substring(0, strInfo[0].IndexOf('.')));
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.Write(strInfo[0].Substring(strInfo[0].IndexOf('.')));
                    } else
                        Console.Write(strInfo[0]);
                    Console.ForegroundColor = str.IndexOf("not") != -1 ? ConsoleColor.DarkCyan : ConsoleColor.Yellow;
                    if (strInfo.Length == 2)
                        Console.WriteLine("[" + strInfo[1]);
                    else Console.WriteLine();
                } else {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine(str);
                }
            }
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(" -2020-03-19----------------Powered by -> Crystal_lz-----------------ST233.COM-");
            Console.ForegroundColor = clr;
        }

        public static void GetIpRange(string[] strIps) {
            List<Range> lst = new List<Range>();
            Regex reg = new Regex(@"^(\d{1,3}\.){3}\d{1,3}");
            foreach (var v in strIps) {
                string strIP = string.Empty;
                string[] strLine = v.Trim().Trim(',').Trim().Split(m_split);
                if (strLine.Length == 0) continue;
                Range rg = new Range();
                try {
                    if (!reg.IsMatch(v.Trim())) {
                        foreach (var ip in Dns.GetHostEntry(v.Trim()).AddressList) {
                            if (!ip.IsIPv6LinkLocal) {
                                strIP = ip.ToString();
                                if (!ScannerConfiger.DomainDic.ContainsKey(strIP)) {
                                    rg.Start = rg.End = ScannerStatic.IPToINT(strIP, true);
                                    ScannerConfiger.DomainDic.Add(strIP, new HashSet<string>());
                                }
                                ScannerConfiger.DomainDic[strIP].Add(v.Trim());
                                break;
                            }
                        }
                        if (rg.Start == 0) throw new Exception("Can not get IPV4");
                    } else if (strLine.Length == 1) {
                        rg.Start = rg.End = ScannerStatic.IPToINT(strLine[0].Trim(), true);
                    } else if (strLine.Length == 2) {
                        rg.Start = ScannerStatic.IPToINT(strLine[0].Trim(), true);
                        if (v.Contains("-"))
                            rg.End = ScannerStatic.IPToINT(strLine[1].Trim(), true);
                        else {
                            int nBit = (32 - int.Parse(strLine[1]));
                            if (nBit < 0) throw new Exception();
                            if (nBit == 0) rg.End = rg.Start;
                            else {
                                uint nMask = 0xFFFFFFFF << nBit;
                                rg.Start = (rg.Start & nMask) + 1;
                                rg.End = (rg.Start | (~nMask) - 1);
                            }
                        }
                        if (rg.End < rg.Start) throw new ArgumentException("Invalid IP range");
                    } else throw new FormatException("Format error");
                    lst.Add(rg);
                } catch (Exception ex) {
                    throw new Exception("Error:" + v + "\r\n" + ex.Message, ex);
                }
            }
            ScannerConfiger.IPRange = lst;
        }

        public static void GetPortList(string[] strPorts) {
            List<int> lst = new List<int>();
            foreach (var v in strPorts) {
                string[] strLine = v.Trim().Trim(',').Trim().Split('-');
                if (strLine.Length == 0) continue;
                Range rg = new Range();
                try {
                    if (strLine.Length == 1) {
                        rg.Start = rg.End = uint.Parse(strLine[0].Trim());
                    } else if (strLine.Length == 2) {
                        rg.Start = uint.Parse(strLine[0].Trim());
                        rg.End = uint.Parse(strLine[1].Trim());
                        if (rg.End < rg.Start) throw new ArgumentException("Invalid Port range");
                    } else throw new FormatException("Format error");
                    if (rg.End > 65535 || rg.Start < 0) throw new ArgumentOutOfRangeException("Invalid port range");
                    for (uint i = rg.Start; i <= rg.End; i++) lst.Add((int)i);
                } catch (Exception ex) {
                    throw new Exception("Error:" + v + "\r\n" + ex.Message, ex);
                }
            }
            ScannerConfiger.PortList = lst.ToArray();
        }

        public static PortScanner InitScanner(string[] args, ProbeConfiger pc) {
            PortScanner ps = null;
            int nIndex = 0;
            string strScanner = "tcp";
            string strCurrentArg = string.Empty;
            try {
                while (nIndex < args.Length) {
                    strCurrentArg = args[nIndex];
                    switch (args[nIndex].ToLower()) {
                        case "-h":
                            ScannerStatic.GetIpRange(args[++nIndex].Split(','));
                            break;
                        case "-hf":
                            ScannerStatic.GetIpRange(File.ReadAllLines(args[++nIndex]));
                            break;
                        case "-p":
                            ScannerStatic.GetPortList(args[++nIndex].Split(','));
                            break;
                        case "-pf":
                            ScannerStatic.GetPortList(File.ReadAllLines(args[++nIndex]));
                            break;
                        case "-pr":
                            ScannerConfiger.ProbesCount = (int)uint.Parse(args[++nIndex]);
                            break;
                        case "-np":
                            ScannerConfiger.IsUserNullProbe = true;
                            break;
                        case "-i":
                            ScannerConfiger.IsIcmp = true;
                            break;
                        case "-is":
                            ScannerConfiger.IsIcmp = ScannerConfiger.IsIcmpScan = true;
                            break;
                        case "-t":
                            ScannerConfiger.Timeout = (int)uint.Parse(args[++nIndex]) * 1000;
                            break;
                        case "-tt":
                            ScannerConfiger.TotalTimeout = (int)uint.Parse(args[++nIndex]) * 1000;
                            break;
                        case "-r":
                            ScannerConfiger.Retry = (int)uint.Parse(args[++nIndex]);
                            break;
                        case "-con":
                            ScannerConfiger.Concurrent = (int)uint.Parse(args[++nIndex]);
                            break;
                        case "-f":
                            string[] strsF = args[++nIndex].ToLower().Split(':');
                            ScannerConfiger.OutputType = strsF[0].ToLower() == "json" ? "JSON" : "CSV";
                            ScannerConfiger.OutputFields = strsF[1].Split(',');
                            break;
                        case "-ss":
                            strScanner = "syn";
                            break;
                        case "-su":
                            strScanner = "udp";
                            break;
                        case "-smb":
                            ScannerConfiger.IsSMB = true;
                            strScanner = "smb";
                            break;
                        case "-o":
                            m_writer = new StreamWriter(args[++nIndex], true, Encoding.UTF8);
                            break;
                        case "-stop":
                            foreach (var v in args[++nIndex].Split(',')) ScannerConfiger.StopProto.Add(v.Trim());
                            break;
                        case "-order":
                            ScannerConfiger.ScanningOrder = args[++nIndex];
                            break;
                        case "-cd":
                            ScannerConfiger.ConsoleDisplay = (int.Parse(args[++nIndex]));
                            break;
                        case "-delay":
                            ScannerConfiger.Delay = (int)(uint.Parse(args[++nIndex])) * 1000;
                            break;
                        case "-cn":
                            using (StreamWriter writer = new StreamWriter(args[2 + nIndex], false, Encoding.UTF8)) {
                                writer.Write(ProbeConfiger.ConvertNmapProbe(File.ReadAllText(args[++nIndex])));
                            }
                            nIndex++;
                            break;
                        case "-st": break;
                        default:
                            throw new ArgumentException("Invalid argument [" + strCurrentArg + "]");
                    }
                    nIndex++;
                }
            } catch (Exception ex) {
                throw new Exception("[" + strCurrentArg + "]", ex);
            }
            if (ScannerConfiger.IPRange.Count == 0) throw new ArgumentException("Can not found the target to scan. Please use [-h] or [-hf] to specify the value");
            switch (strScanner) {
                case "tcp":
                    ps = new TCPScanner(ScannerConfiger.Concurrent, pc);
                    break;
                case "udp":
                    ScannerConfiger.ProtocolType = "UDP";
                    ps = new UDPScanner(ScannerConfiger.Concurrent, pc);
                    break;
                case "syn":
                    ps = new SYNScanner(ScannerConfiger.Concurrent, pc);
                    break;
                case "smb":
                    ps = new SmbScanner(ScannerConfiger.Concurrent);
                    break;
            }
            if (ScannerConfiger.IsSMB) ScannerConfiger.PortList = new int[] { 445 };
            ScannerStatic.InitWriter();
            return ps;
        }

        public static void OutToFile(string strIP, string strPort, string strType, string strProto, string strBanner, int nLine, byte[] byBuffer, int nLen) {
            if (m_writer == null) return;
            lock (m_writer) {
                m_writer.WriteLine(
                        ScannerConfiger.OutputType == "JSON" ?
                        ScannerStatic.GetJSONString(strIP, strPort, strType, strProto, strBanner, nLine, byBuffer, nLen) :
                        ScannerStatic.GetCSVString(strIP, strPort, strType, strProto, strBanner, nLine, byBuffer, nLen)
                    );
                m_writer.Flush();
            }
        }

        private static void InitWriter() {
            if (m_writer != null && ScannerConfiger.OutputType == "CSV") {
                m_sb_buffer.Remove(0, m_sb_buffer.Length);
                foreach (var v in ScannerConfiger.OutputFields) {
                    switch (v) {
                        case "h":
                            m_sb_buffer.Append("Host");
                            break;
                        case "a":
                            m_sb_buffer.Append("Address");
                            break;
                        case "p":
                            m_sb_buffer.Append("Port");
                            break;
                        case "pt":
                            m_sb_buffer.Append("Protocol_Type");
                            break;
                        case "pf":
                            m_sb_buffer.Append("Protocol_flag");
                            break;
                        case "pr":
                            m_sb_buffer.Append("Protocol");
                            break;
                        case "l":
                            m_sb_buffer.Append("RegexLine");
                            break;
                        case "d":
                            m_sb_buffer.Append("Data");
                            break;
                        case "b":
                            m_sb_buffer.Append("Banner");
                            break;
                    }
                    m_sb_buffer.Append(',');
                }
                if (m_sb_buffer.Length != 0) m_writer.WriteLine(m_sb_buffer.ToString(0, m_sb_buffer.Length - 1));
            }
        }

        private static string GetCSVString(string strIP, string strPort, string strType, string strProto, string strBanner, int nLine, byte[] byBuffer, int nLen) {
            lock (m_obj_sync) {
                m_sb_buffer.Remove(0, m_sb_buffer.Length);
                //string[] strEP = strRemote.Split(':');
                foreach (var v in ScannerConfiger.OutputFields) {
                    switch (v) {
                        case "h":
                            m_sb_buffer.Append(strIP + ":" + strPort);
                            break;
                        case "a":
                            m_sb_buffer.Append(strIP);
                            break;
                        case "p":
                            m_sb_buffer.Append(strPort);
                            break;
                        case "pt":
                            m_sb_buffer.Append(strType);
                            break;
                        case "pf":
                            m_sb_buffer.Append(strProto);
                            break;
                        case "pr":
                            m_sb_buffer.Append("(" + strType + ")" + strProto);
                            break;
                        case "l":
                            m_sb_buffer.Append(nLine.ToString());
                            break;
                        case "d":
                            m_sb_buffer.Append(byBuffer == null ? "" : (BitConverter.ToString(byBuffer, 0, nLen).Replace("-", "")));
                            break;
                        case "b":
                            m_sb_buffer.Append("\"" + (string.IsNullOrEmpty(strBanner) ? "" : strBanner.Replace("\"", "\"\"")) + "\"");
                            break;
                    }
                    m_sb_buffer.Append(',');
                }
                if (m_sb_buffer.Length != 0) return m_sb_buffer.ToString(0, m_sb_buffer.Length - 1);
            }
            return "";
        }

        private static string GetJSONString(string strIP,string strPort, string strType, string strProto, string strBanner, int nLine, byte[] byBuffer, int nLen) {
            lock (m_obj_sync) {
                m_sb_buffer.Remove(0, m_sb_buffer.Length);
                //string[] strEP = strRemote.Split(':');
                foreach (var v in ScannerConfiger.OutputFields) {
                    switch (v) {
                        case "h":
                            m_sb_buffer.Append("\"Host\":\"" + strIP + ":" + strPort + "\"");
                            break;
                        case "a":
                            m_sb_buffer.Append("\"IP\":\"" + strIP + "\"");
                            break;
                        case "p":
                            m_sb_buffer.Append("\"Port\":" + strPort);
                            break;
                        case "pt":
                            m_sb_buffer.Append("\"Type\":\"" + strType + "\"");
                            break;
                        case "pf":
                            m_sb_buffer.Append("\"Protocol_flag\":\"" + strProto + "\"");
                            break;
                        case "pr":
                            m_sb_buffer.Append("\"Protocol\":\"(" + strType + ")" + strProto + "\"");
                            break;
                        case "l":
                            m_sb_buffer.Append("\"RegLine\":" + nLine.ToString());
                            break;
                        case "d":
                            m_sb_buffer.Append("\"Data\":\"" + (byBuffer == null ? "" : (BitConverter.ToString(byBuffer, 0, nLen).Replace("-", ""))) + "\"");
                            break;
                        case "b":
                            m_sb_buffer.Append("\"Banner\":\""
                                + (string.IsNullOrEmpty(strBanner) ? "" : strBanner
                                .Replace("\\", "\\\\")
                                .Replace("\r", "\\r")
                                .Replace("\n", "\\n")
                                .Replace("\t", "\\t")
                                .Replace("\"", "\\\""))
                                + "\"");
                            break;
                    }
                    m_sb_buffer.Append(',');
                }
                if (m_sb_buffer.Length != 0) return "{" + m_sb_buffer.ToString(0, m_sb_buffer.Length - 1) + "}";
            }
            return "{}";
        }
    }

    public struct Range
    {
        public uint Start;
        public uint End;
    }
}
