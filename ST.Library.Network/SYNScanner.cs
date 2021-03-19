using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace ST.Library.Network
{
    public class SYNScanner : PortScanner
    {
        private Random m_rnd;
        private Semaphore m_se;
        private ProbeConfiger m_probes;
        private Queue<SYNScanTaskInfo> m_que_task;
        private Queue<SocketAsyncEventArgs> m_que_sae;
        private TCPScanner m_tcp_scanner;
        private Dictionary<uint, SYNScanTaskInfo> m_dic_task_running;
        //private Dictionary<uint, uint> m_dic_uid;
        private Dictionary<uint, SYNScanTaskInfo> m_dic_uid;
        private Thread m_thread_timeout;
        //private Socket m_sock_raw;
        //private Socket m_sock_bind;
        private uint m_uLocalIP;
        private string m_strLocalIP;
        private ushort m_nLocalPort;

        public SYNScanner(int nMaxTask, ProbeConfiger probes) : this(nMaxTask, probes, null) { }

        public SYNScanner(int nMaxTask, ProbeConfiger probes, EndPoint bindEndPoint) {
            if (nMaxTask > 60000 || nMaxTask < 1) throw new ArgumentOutOfRangeException("the MaxTask must be between 1 and 30000");
            m_probes = probes;
            if (bindEndPoint == null) {
                foreach (var v in Dns.GetHostAddresses(Dns.GetHostName())) {
                    if (v.IsIPv6LinkLocal || v.IsIPv6Multicast || v.IsIPv6SiteLocal) continue;
                    bindEndPoint = new IPEndPoint(v, 0);
                }
            }
            m_rnd = new Random();
            m_dic_uid = new Dictionary<uint, SYNScanTaskInfo>();// new Dictionary<uint, uint>();
            m_dic_task_running = new Dictionary<uint, SYNScanTaskInfo>();
            m_tcp_scanner = new TCPScanner(nMaxTask, probes);
            m_tcp_scanner.Completed += new ScanEventHandler(m_tcp_Completed);
            //m_sock_bind = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            //m_sock_bind.Bind(bindEndPoint);
            //bindEndPoint = m_sock_bind.LocalEndPoint;
            m_strLocalIP = bindEndPoint.ToString().Split(':')[0];
            m_uLocalIP = RAWDefine.IPToINT(m_strLocalIP);
            m_nLocalPort = ushort.Parse(bindEndPoint.ToString().Split(':')[1]);
            m_se = new Semaphore(nMaxTask, nMaxTask);

            //m_sock_raw = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
            //m_sock_raw.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            //m_sock_raw.Bind(bindEndPoint);
            //m_sock_raw.IOControl(IOControlCode.ReceiveAll, new byte[] { 1, 0, 0, 0 }, null);
            RawSocket.InitRawSocket(bindEndPoint);
            RawSocket.RecvCompleted += this.ProcessRecv;

            m_que_task = new Queue<SYNScanTaskInfo>();
            m_que_sae = new Queue<SocketAsyncEventArgs>();
            for (int i = 0; i < nMaxTask; i++) {
                SYNScanTaskInfo ti = new SYNScanTaskInfo();
                ti.TaskID = (uint)((i + 1) << 8);
                ti.SYNPacket = new byte[40];
                m_que_task.Enqueue(ti);
            }

            //SocketAsyncEventArgs sae = new SocketAsyncEventArgs();
            //sae.Completed += new EventHandler<SocketAsyncEventArgs>(IO_Completed);
            //sae.SetBuffer(new byte[65535], 0, 65535);
            //sae.UserToken = m_sock_raw;
            //if (!m_sock_raw.ReceiveAsync(sae)) IOProcessPool.QueueWork(this.ProcessRecv, sae);
            m_thread_timeout = new Thread(this.CheckTimeout);
            m_thread_timeout.IsBackground = true;
            m_thread_timeout.Start();
        }

        void m_tcp_Completed(object sender, ScanEventArgs e) {
            uint uid = e.TaskID;
            SYNScanTaskInfo ti = null;
            lock (m_dic_uid) {
                if (!m_dic_uid.ContainsKey(e.TaskID)) return;
                //e.TaskID = m_dic_uid[e.TaskID];
                ti = m_dic_uid[e.TaskID];
                e.TaskID = ti.TaskID;
                m_dic_uid.Remove(uid);
                if (base._IsDisposed) return;
                m_que_task.Enqueue(ti);
            }
            //lock (m_obj_sync) {
            //}
            base.OnCompleted(e);
            m_se.Release();
        }

        //private SocketAsyncEventArgs PopSAE() {
        //    lock (m_obj_sync) {
        //        if (m_que_sae.Count != 0) return m_que_sae.Dequeue();
        //    }
        //    SocketAsyncEventArgs sae = new SocketAsyncEventArgs();
        //    sae.Completed += new EventHandler<SocketAsyncEventArgs>(IO_Completed);
        //    sae.SetBuffer(new byte[40], 0, 40);
        //    return sae;
        //}

        //private void PushSAE(SocketAsyncEventArgs sae) {
        //    lock (m_obj_sync) {
        //        if (base._IsDisposed) return;
        //        m_que_sae.Enqueue(sae);
        //    }
        //}

        protected override uint OnScan(int nPort, EndPoint endPoint, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbe) {
            lock (m_obj_sync) {
                if (base._IsDisposed) throw new ObjectDisposedException("SYNScanner", "The scanner was disposed");
            }
            m_se.WaitOne();
            SYNScanTaskInfo ti = this.CreateTaskInfo(nPort, endPoint, nProbes, nTimeout, nRetry, nTotalTimeout, bUseNullProbe);
            lock (m_dic_task_running) {
                m_dic_task_running.Add(ti.TaskID, ti);
            }
            //this.SendData(ti);
            RawSocket.SendData(ti.SYNPacket, 0, ti.SYNPacket.Length);
            ti.StartTime = ti.LastTime = DateTime.Now;
            ti.IsStarted = true;
            return ti.TaskID;
        }

        //private void SendData(SYNScanTaskInfo ti) {
        //    SocketAsyncEventArgs sae = this.PopSAE();
        //    Array.Copy(ti.SYNPacket, sae.Buffer, ti.SYNPacket.Length);
        //    ti.LastTime = DateTime.Now;
        //    sae.RemoteEndPoint = ti.EndPoint;
        //    if (!m_sock_raw.SendToAsync(sae)) IOProcessPool.QueueWork(this.ProcessSend, sae);
        //}

        private SYNScanTaskInfo CreateTaskInfo(int nPort, EndPoint endPoint, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbes) {
            SYNScanTaskInfo ti = null;
            lock (m_obj_sync) {
                ti = m_que_task.Dequeue();
            }
            ti.Retry = nRetry;
            ti.RunedRetry = 0;
            ti.Port = nPort;
            ti.EndPoint = endPoint;
            ti.IsStarted = false;
            ti.Probes = nProbes;
            ti.IsUseNullProbe = bUseNullProbes;
            ti.Timeout = nTimeout;
            ti.TotalTimeout = nTotalTimeout;
            ti.UIP = BitConverter.ToUInt32(((IPEndPoint)endPoint).Address.GetAddressBytes(), 0);
            uint uTemp = 0;
            lock (m_rnd) uTemp = (uint)m_rnd.Next();
            uTemp &= 0xFF0000FF;
            ti.TaskID = ti.TaskID & 0x00FFFF00 | uTemp;
            ti.SEQ = RAWDefine.GetSynPacket(ti.SYNPacket, m_uLocalIP, ti.UIP, m_nLocalPort, (ushort)ti.Port, ti.TaskID);
            return ti;
        }

        //void IO_Completed(object sender, SocketAsyncEventArgs e) {
        //    switch (e.LastOperation) {
        //        case SocketAsyncOperation.SendTo:
        //            this.ProcessSend(e);
        //            break;
        //        case SocketAsyncOperation.Receive:
        //            this.ProcessRecv(e);
        //            break;
        //    }
        //}

        //private void ProcessSend(SocketAsyncEventArgs e) {
        //    this.PushSAE(e);
        //}

        private void ProcessRecv(object sender, SocketAsyncEventArgs e) {
            lock (m_obj_sync) {
                if (base._IsDisposed) return;
            }
            Socket sock = e.UserToken as Socket;
            if (e.SocketError == SocketError.Success && e.BytesTransferred > 0) {
                bool b = true;
                uint uSIP = BitConverter.ToUInt32(e.Buffer, 16);
                int nOffset = (e.Buffer[0] & 0x0F) * 4;
                uint uSEQ = RAWDefine.GetACKNumber(e.Buffer, nOffset) - 1;
                if (e.BytesTransferred < 40) b = false;
                else if (nOffset < 20 || e.BytesTransferred - 20 < nOffset) b = false;
                else if (e.Buffer[9] != RAWDefine.PROTO_TCP) b = false;
                else if ((ushort)((e.Buffer[nOffset + 2] << 8) | e.Buffer[nOffset + 3]) != m_nLocalPort) b = false;
                else if (e.Buffer[nOffset + 13] != 0x12) b = false;//syn + ack
                else if (uSIP != m_uLocalIP) b = false;
                SYNScanTaskInfo ti = null;
                if (b) {
                    lock (m_dic_task_running) {
                        if (m_dic_task_running.ContainsKey(uSEQ)) {
                            ti = m_dic_task_running[uSEQ];
                            m_dic_task_running.Remove(uSEQ);
                        }
                    }
                }
                if (ti != null) {
                    uint id = m_tcp_scanner.Scan(ti.UIP, ti.Port, ti.Probes, ti.Timeout, ti.Retry, ti.TotalTimeout, ti.IsUseNullProbe);
                    lock (m_dic_uid) m_dic_uid.Add(id, ti);
                }
            }
            //if (!sock.ReceiveAsync(e)) IOProcessPool.QueueWork(this.ProcessRecv, e);
        }

        private void EndTask(SYNScanTaskInfo ti) {
            ti.IsStarted = false;
            lock (m_dic_task_running) {
                if (!m_dic_task_running.ContainsKey(ti.TaskID)) return;
                m_dic_task_running.Remove(ti.TaskID);
            }
            lock (m_obj_sync) {
                if (base._IsDisposed) return;
                m_que_task.Enqueue(ti);
            }
            base.OnCompleted(new ScanEventArgs(ti.TaskID, ti.EndPoint, "ACK timeout"));
            m_se.Release();
        }

        private void CheckTimeout() {
            DateTime dt = DateTime.Now;
            List<SYNScanTaskInfo> lst_remove = new List<SYNScanTaskInfo>();
            while (true) {
                Thread.Sleep(1000);
                lst_remove.Clear();
                dt = DateTime.Now;
                bool bDisposed = base._IsDisposed;
                lock (m_dic_task_running) {
                    foreach (var v in m_dic_task_running) {
                        if (!v.Value.IsStarted) continue;
                        if (dt.Subtract(v.Value.StartTime).TotalMilliseconds > v.Value.TotalTimeout || bDisposed) {
                            lst_remove.Add(v.Value);
                            continue;
                        }
                        if (dt.Subtract(v.Value.LastTime).TotalMilliseconds > v.Value.Timeout) {
                            if (v.Value.RunedRetry++ < v.Value.Retry) {
                                RawSocket.SendData(v.Value.SYNPacket, 0, v.Value.SYNPacket.Length);// this.SendData(v.Value);
                                v.Value.LastTime = DateTime.Now;
                            } else lst_remove.Add(v.Value);
                        }
                    }
                    foreach (var v in lst_remove) {
                        this.EndTask(v);
                    }
                }
                if (bDisposed) break;
            }
        }

        public override void Dispose() {
            lock (m_obj_sync) {
                if (base.IsDisposed) return;
                base._IsDisposed = true;
            }
            m_tcp_scanner.Dispose();
            //base.CloseSocket(m_sock_bind);
        }
    }
}
