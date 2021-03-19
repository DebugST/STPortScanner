using System;
using System.Collections.Generic;
using System.Text;

using ST.Library.Network;

using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Diagnostics;

namespace STPortScanner
{
    public class Program
    {
        static ConsoleColor m_clr;
        static int m_nRuned;
        static int m_nJumped;
        static int m_nRunning;
        static int m_nTaskCount;
        static int m_nResult;
        static PortScanner m_scanner;
        static ProbeConfiger m_pc;
        static Semaphore m_se;
        static Random m_rnd = new Random();
        static int m_nCacheCounter = 0;
        static int m_nCacheCount = 100000;
        static ulong[] m_arr_cache = new ulong[m_nCacheCount];
        static Queue<ulong> m_que_task = new Queue<ulong>();
        static HashSet<uint> m_hs_stop_host = new HashSet<uint>();
        static object m_obj_sync = new object();

        static void Main(string[] args) {
            m_clr = Console.ForegroundColor;
            //args = "-h 192.140.145.127 -smb".Split(' ');
            //args = "-h 192.168.10.2 -p 80 -r 10 -tt 10000".Split(' ');
            //args = "-hf ./vultrcidrs.txt -order port -st -cd 0 -con 12000".Split(' ');
            //args = "-h 46.101.181.209/0 -order port -st -cd 0 -con 8000".Split(' ');
            //args = "-h 45.32.249.1/24 -order port -st -cd 1".Split(' ');
            if (args.Length < 2) {
                ScannerStatic.ShowInfo();
                return;
            }
            if (!File.Exists("./config_defports.st")) ConfigerHelper.CreateConfigFile("./config_defports.st", false);
            if (!File.Exists("./config_probes.st")) ConfigerHelper.CreateConfigFile("./config_probes.st", true);
            m_pc = new ProbeConfiger(
                File.ReadAllText("./config_probes.st"),
                File.ReadAllText("./config_defports.st")
                );
            try {
                m_scanner = ScannerStatic.InitScanner(args, m_pc);
                m_scanner.Completed += new ScanEventHandler(m_scanner_Completed);
            } catch (Exception ex) {
                var clr = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message + "\r\n\t" + (ex.InnerException != null ? ex.InnerException.Message : ""));
                Console.ForegroundColor = clr;
                Console.Write("Show help info?(y/n):");
                if (Console.ReadKey().KeyChar == 'y') ScannerStatic.ShowInfo();
                return;
            }
            DateTime dt = DateTime.Now;
            m_se = new Semaphore(ScannerConfiger.Concurrent, ScannerConfiger.Concurrent);
            new Thread(Program.ShowPregress) { IsBackground = true }.Start();
            if (ScannerConfiger.IsIcmp) {
                IcmpScanner icmp = new IcmpScanner(ScannerConfiger.Concurrent);
                icmp.Completed += new IcmpEventHandler(icmp_Completed);
                new Thread(Program.IcmpFlushCallBack) { IsBackground = true }.Start();
                foreach (var v in ScannerConfiger.IPRange) {
                    for (uint i = v.Start; i <= v.End; i++) {
                        m_se.WaitOne();
                        lock (m_obj_sync) {
                            m_nRunning++;
                            m_nTaskCount++;
                        }
                        icmp.Ping(new IPAddress(ScannerStatic.Reverse(i)), ScannerConfiger.Timeout, ScannerConfiger.Retry);
                    }
                }
            } else {
                if (ScannerConfiger.ScanningOrder == "host") {
                    Program.ScanFromHost();
                } else if (ScannerConfiger.ScanningOrder == "port") {
                    Program.ScanFromPort();
                } else {
                    Program.ScanFromRnd();
                }
            }
            while (m_nTaskCount != m_nRuned) Thread.Sleep(500);
            Console.WriteLine("Queue:" + (m_nTaskCount - m_nRuned) + "  Running:" + m_nRunning + "  Runed:" + m_nRuned + "  Result:" + m_nResult + "  Jumped:" + m_nJumped);
            string strTimeSub = DateTime.Now.Subtract(dt).ToString();
            strTimeSub = strTimeSub.Substring(0, strTimeSub.LastIndexOf(':') + 3);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("TIME: [" + dt.ToString("yy-MM-dd_HH:mm:ss")  + "]-[" + DateTime.Now.ToString("yy-MM-dd_HH:mm:ss") + "] [" + strTimeSub + "]");
            Console.ForegroundColor = m_clr;
            //Console.ReadKey();
        }

        static void ShowPregress() {
            while (true) {
                Thread.Sleep(ScannerConfiger.Delay);
                if (m_nTaskCount == m_nRuned) return;
                lock (m_obj_sync) {
                    Console.WriteLine("Queue:" + (m_nTaskCount - m_nRuned)
                        + "  Running:" + m_nRunning
                        + "  Runed:" + m_nRuned
                        + "  Result:" + m_nResult
                        + "  Jumped:" + m_nJumped);
                }
            }
        }

        static void IcmpFlushCallBack() {
            ulong lep = 0;
            while (true) {
                lep = 0;
                lock (m_obj_sync) {
                    if (m_que_task.Count != 0) lep = m_que_task.Dequeue();
                }
                if (lep == 0) {
                    Thread.Sleep(2000);
                    if (!ScannerConfiger.IsIcmp) continue;
                    lock (m_obj_sync) {
                        if (m_nCacheCounter != 0) {
                            Program.FlushCache(true);
                            continue;
                        }
                    }
                    continue;
                }
                Program.Scan((uint)(lep >> 32), (int)lep);
            }
        }

        static void EnCache(uint uIP, int nPort, bool isAsync) {
            ulong lep = (ulong)uIP << 32;
            lep &= 0xFFFFFFFF00000000;
            lep |= (uint)nPort;
            lock (m_obj_sync) {
                m_arr_cache[m_nCacheCounter++] = lep;
                m_nTaskCount++;
                if (m_nCacheCounter == m_nCacheCount) Program.FlushCache(isAsync);
            }
        }

        static void FlushCache(bool isAsync) {
            int nIndex = 0, nLen = 0;
            ulong uTemp = 0;
            nLen = m_nCacheCounter;
            m_nCacheCounter = 0;
            for (int i = 0; i < nLen; i++) {
                nIndex = m_rnd.Next(0, nLen);
                uTemp = m_arr_cache[nIndex];
                m_arr_cache[nIndex] = m_arr_cache[i];
                m_arr_cache[i] = uTemp;
            }
            if (!isAsync) {
                for (int i = 0; i < nLen; i++) {
                    Program.Scan((uint)(m_arr_cache[i] >> 32), (int)m_arr_cache[i]);
                }
                return;
            }
            for (int i = 0; i < nLen; i++) {
                m_que_task.Enqueue(m_arr_cache[i]);
            }
        }

        static void ScanFromRnd() {
            foreach (var r in ScannerConfiger.IPRange) {
                for (uint i = r.Start; i <= r.End; i++) {
                    foreach (var p in ScannerConfiger.PortList) {
                        Program.EnCache(ScannerStatic.Reverse(i), p, false);
                    }
                }
            }
            Program.FlushCache(false);
        }

        static void ScanFromHost() {
            foreach (var r in ScannerConfiger.IPRange) {
                for (uint i = r.Start; i <= r.End; i++) {
                    foreach (var p in ScannerConfiger.PortList) {
                        lock (m_obj_sync) m_nTaskCount++;
                        Program.Scan(ScannerStatic.Reverse(i), p);
                    }
                }
            }
        }

        static void ScanFromPort() {
            foreach (var p in ScannerConfiger.PortList) {
                foreach (var r in ScannerConfiger.IPRange) {
                    for (uint i = r.Start; i <= r.End; i++) {
                        lock (m_obj_sync) m_nTaskCount++;
                        Program.Scan(ScannerStatic.Reverse(i), p);
                    }
                }
            }
        }

        static void Scan(uint uIP, int nPort) {
            m_se.WaitOne();
            lock (m_obj_sync) {
                if (m_hs_stop_host.Contains(uIP)) {
                    m_nRuned++;
                    m_nJumped++;
                    m_se.Release();
                    return;
                }
                m_nRunning++;
            }
            m_scanner.Scan(uIP,
                nPort,
                ScannerConfiger.ProbesCount,
                ScannerConfiger.Timeout,
                ScannerConfiger.Retry,
                ScannerConfiger.TotalTimeout,
                ScannerConfiger.IsUserNullProbe);
        }

        static void icmp_Completed(object sender, IcmpEventArgs e) {
            if (e.CanAccess) {
                lock (m_obj_sync) m_nResult++;
                Program.OutResult(e.IPAddress.ToString(), "0", "ICMP", "Live", null, 0, null, 0);
                if (ScannerConfiger.IsIcmpScan) {
                    uint u = BitConverter.ToUInt32(e.IPAddress.GetAddressBytes(), 0);
                    foreach (var v in ScannerConfiger.PortList) {
                        Program.EnCache(u, v, true);
                    }
                }
            }
            m_se.Release();
            lock (m_obj_sync) {
                m_nRuned++;
                m_nRunning--;
            }
        }

        static void m_scanner_Completed(object sender, ScanEventArgs e) {
            if (e.CanConnect) {
                lock (m_obj_sync) {
                    m_nResult++;
                    if (ScannerConfiger.StopProto.Contains(e.Protocol)) {
                        uint u = BitConverter.ToUInt32(((IPEndPoint)e.EndPoint).Address.GetAddressBytes(), 0);
                        m_hs_stop_host.Add(u);
                    }
                }
                string strProto = e.Protocol;
                string strIP = ((IPEndPoint)e.EndPoint).Address.ToString();
                int nPort = ((IPEndPoint)e.EndPoint).Port;
                if (string.IsNullOrEmpty(strProto)) {
                    if (m_pc.DefaultProtocol.ContainsKey(nPort))
                        strProto = m_pc.DefaultProtocol[nPort] + "?";
                }
                Program.OutResult(strIP, nPort.ToString(), ScannerConfiger.ProtocolType, strProto, e.Banner, e.RegexLine, e.Data, e.Length);
            }
            //if()
            m_se.Release();
            lock (m_obj_sync) {
                m_nRuned++;
                m_nRunning--;
            }
        }

        static void OutResult(string strIP, string strPort, string strProtoType, string strProtoFlag, string strBanner, int nLine, byte[] byBuffer, int nLen) {
            if (ScannerConfiger.ConsoleDisplay > 0) {
                lock (m_obj_sync) {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write((strIP + ":" + strPort).PadRight(22));
                    Console.ForegroundColor = ConsoleColor.Magenta;
                    Console.Write("[(" + strProtoType + ")" + strProtoFlag + "]");
                    if (!string.IsNullOrEmpty(strBanner) && ScannerConfiger.ConsoleDisplay > 1) {
                        Console.WriteLine("[RegLine:" + nLine + "]");
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("[\r\n" + (strBanner.Length > 256 ? (strBanner.Substring(0, 256).TrimEnd('\r') + "...") : strBanner) + "\r\n]");
                    } else Console.WriteLine();
                    Console.ForegroundColor = m_clr;
                }
            }
            ScannerStatic.OutToFile(strIP, strPort, strProtoType, strProtoFlag, strBanner, nLine, byBuffer, nLen);
        }
    }
}
