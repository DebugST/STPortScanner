using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace ST.Library.Network
{
    public class TCPScanner : PortScanner
    {
        private Semaphore m_se;
        private ProbeConfiger m_configer;
        private Queue<TCPScanTaskInfo> m_que_task;
        private Queue<SocketAsyncEventArgs> m_que_sae;
        private HashSet<TCPScanTaskInfo> m_hs_task_running;
        private Thread m_thread_timeout;

        public TCPScanner(int nMaxTask, ProbeConfiger probes) {
            if (nMaxTask > 60000 || nMaxTask < 1) throw new ArgumentOutOfRangeException("the MaxTask must be between 1 and 30000");
            m_configer = probes;
            m_que_task = new Queue<TCPScanTaskInfo>();
            m_hs_task_running = new HashSet<TCPScanTaskInfo>();
            m_que_sae = new Queue<SocketAsyncEventArgs>();
            for (int i = 0; i < nMaxTask; i++) {
                TCPScanTaskInfo ti = new TCPScanTaskInfo();
                ti.TaskID = (uint)(i + 1);
                SocketAsyncEventArgs sae = new SocketAsyncEventArgs();
                sae.Completed += new EventHandler<SocketAsyncEventArgs>(IO_Completed);
                sae.SetBuffer(new byte[2048], 0, 2048);
                sae.UserToken = ti;
                ti.RecvSAE = sae;
                m_que_task.Enqueue(ti);
            }
            m_se = new Semaphore(nMaxTask, nMaxTask);
            m_thread_timeout = new Thread(this.CheckTimeout);
            m_thread_timeout.IsBackground = true;
            m_thread_timeout.Start();
        }

        protected override uint OnScan(int nPort, EndPoint endPoint, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbe) {
            lock (m_obj_sync) {
                if (base._IsDisposed) throw new ObjectDisposedException("TCPScanner", "The scanner was disposed");
            }
            m_se.WaitOne();
            TCPScanTaskInfo ti = this.CreateTaskInfo(nPort, endPoint, nProbes, nTimeout, nRetry, nTotalTimeout, bUseNullProbe);
            ti.StartTime = DateTime.Now;
            lock (m_hs_task_running) m_hs_task_running.Add(ti);
            this.StartConnect(ti);
            return ti.TaskID;
        }

        private void StartConnect(TCPScanTaskInfo ti) {
            if (ti.Socket != null) base.CloseSocket(ti.Socket);
            ti.Socket = this.GetNextSocket(ti.Timeout);
            ti.LastTime = DateTime.Now;
            ti.IsStarted = true;
            //lock (m_hs_task_running) m_hs_task_running.Add(ti);//repeat
            SocketAsyncEventArgs sae = this.PopSAE();
            sae.SetBuffer(0, 0);
            sae.RemoteEndPoint = ti.EndPoint;
            sae.UserToken = ti;
            try {
                if (!ti.Socket.ConnectAsync(sae)) IOProcessPool.QueueWork(this.ProcessConnect, sae);
            } catch (Exception ex) {
                this.PushSAE(sae);
                this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, ti.CanConnect, "[SOCKET-CONNECT]-" + ex.Message));
            }
        }

        private Socket GetNextSocket(int nTimeout) {
            Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            sock.SendTimeout = sock.ReceiveTimeout = nTimeout;
            return sock;
        }

        private SocketAsyncEventArgs PopSAE() {
            SocketAsyncEventArgs sae = null;
            lock (m_obj_sync) {
                if (m_que_sae.Count != 0) {
                    sae = m_que_sae.Dequeue();
                    return sae;
                }
            }
            sae = new SocketAsyncEventArgs();
            sae.Completed += new EventHandler<SocketAsyncEventArgs>(IO_Completed);
            sae.SetBuffer(new byte[2048], 0, 2048);

            return sae;
        }

        private void PushSAE(SocketAsyncEventArgs sae) {
            lock (m_obj_sync) {
                if (base._IsDisposed) return;
                m_que_sae.Enqueue(sae);
            }
        }

        private TCPScanTaskInfo CreateTaskInfo(int nPort, EndPoint endPoint, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbes) {
            TCPScanTaskInfo ti = null;
            lock (m_obj_sync) {
                ti = m_que_task.Dequeue();
            }
            ti.Retry = nRetry;
            ti.RunedRetry = 0;
            ti.Port = nPort;
            ti.EndPoint = endPoint;
            ti.IsStarted = false;
            ti.IsTotalTimeout = false;
            //ti.Socket = this.GetNextSocket(nTimeout);
            ti.CanConnect = false;
            ti.Timeout = nTimeout;
            ti.TotalTimeout = nTotalTimeout;
            ti.CurrentProbe = null;
            if (nProbes < 0)
                ti.SendProbes = m_configer.GetProbesQueue(ProbeType.Tcp, nPort, 0);
            else if (nProbes > 0)
                ti.SendProbes = m_configer.GetProbesQueue(ProbeType.Tcp, nPort, nProbes);
            else ti.SendProbes = null;
            if (!bUseNullProbes && ti.SendProbes != null && ti.SendProbes.Count != 0)
                ti.CurrentProbe = ti.SendProbes.Dequeue();
            return ti;
        }

        private void IO_Completed(object sender, SocketAsyncEventArgs e) {
            switch (e.LastOperation) {
                case SocketAsyncOperation.Connect:
                    this.ProcessConnect(e);
                    break;
                case SocketAsyncOperation.Send:
                    this.ProcessSend(e);
                    break;
                case SocketAsyncOperation.Receive:
                    this.ProcessRecv(e);
                    break;
            }
        }

        private void ProcessConnect(SocketAsyncEventArgs e) {
            TCPScanTaskInfo ti = e.UserToken as TCPScanTaskInfo;
            ti.LastTime = DateTime.Now;
            Socket sock = ti.Socket;
            ProbeInfo pi = ti.CurrentProbe;
            //SocketError.AccessDenied
            switch (e.SocketError) {
                case SocketError.Success:
                    ti.RunedRetry = 0;
                    ti.CanConnect = true;
                    break;
                case SocketError.ConnectionReset:       //此连接由远程对等计算机重置
                case SocketError.ConnectionRefused:     //远程主机正在主动拒绝连接
                case SocketError.AddressNotAvailable:   //选定的 IP 地址在此上下文中无效
                case SocketError.Fault:                 //基础套接字提供程序检测到无效的指针地址
                case SocketError.HostDown:              //由于远程主机被关闭 操作失败
                case SocketError.HostNotFound:          //无法识别这种主机 该名称不是正式的主机名或别名
                case SocketError.HostUnreachable:       //没有到指定主机的网络路由
                case SocketError.NetworkDown:           //网络不可用
                case SocketError.NetworkUnreachable:    //不存在到远程主机的路由
                    this.PushSAE(e);
                    this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, ti.CanConnect, e.SocketError.ToString()));
                    return;
            }
            if (SocketError.Success != e.SocketError || !ti.IsStarted) {
                this.PushSAE(e);
                if (++ti.RunedRetry > ti.Retry || ti.IsTotalTimeout)
                    this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, ti.CanConnect, e.SocketError.ToString()));
                else
                    this.StartConnect(ti);
                return;
            }
            try {
                if (!sock.ReceiveAsync(ti.RecvSAE)) IOProcessPool.QueueWork(this.ProcessRecv, ti.RecvSAE);
            } catch (Exception ex) {
                this.PushSAE(e);
                this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, ti.CanConnect, "[SOCKET-RECV]-" + ex.Message));
                return;
            }
            try {
                if (pi != null) {
                    if (e.Buffer.Length < pi.Data.Length)
                        e.SetBuffer(new byte[pi.Data.Length], 0, pi.Data.Length);
                    Array.Copy(pi.Data, e.Buffer, pi.Data.Length);
                    e.SetBuffer(0, pi.Data.Length);
                    if (!sock.SendAsync(e)) IOProcessPool.QueueWork(this.ProcessSend, e);
                } else this.PushSAE(e);
            } catch {
                this.PushSAE(e);
            }
        }

        private void ProcessSend(SocketAsyncEventArgs e) {
            TCPScanTaskInfo ti = e.UserToken as TCPScanTaskInfo;
            ti.LastTime = DateTime.Now;
            this.PushSAE(e);
        }

        private void ProcessRecv(SocketAsyncEventArgs e) {
            TCPScanTaskInfo ti = e.UserToken as TCPScanTaskInfo;
            ti.LastTime = DateTime.Now;
            if (e.SocketError != SocketError.Success || e.BytesTransferred < 1) {
                if (ti.SendProbes != null && ti.SendProbes.Count != 0 && !ti.IsTotalTimeout) {
                    ti.CurrentProbe = ti.SendProbes.Dequeue();
                    this.StartConnect(ti);
                } else this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, ti.CanConnect, e.SocketError.ToString()));
                return;
            }
            MatchResult mr = new MatchResult();
            if (ti.CurrentProbe == null) {
                mr = m_configer.MatchData(e.Buffer, e.BytesTransferred, 0, ProbeType.Tcp);
            } else {
                mr = m_configer.MatchData(e.Buffer, e.BytesTransferred, ti.Port, ProbeType.Tcp, ti.CurrentProbe);
            }
            this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, mr.Name, mr.RegexLine, mr.DataString, e.Buffer, e.BytesTransferred));
        }

        private void EndTask(TCPScanTaskInfo ti, ScanEventArgs e) {
            base.CloseSocket(ti.Socket);
            ti.Socket = null;
            ti.IsStarted = false;
            lock (m_hs_task_running) m_hs_task_running.Remove(ti);
            lock (m_obj_sync) {
                if (!base._IsDisposed) m_que_task.Enqueue(ti);
            }
            base.OnCompleted(e);
            m_se.Release();
        }

        private void CheckTimeout() {
            DateTime dt = DateTime.Now;
            while (true) {
                Thread.Sleep(1000);
                dt = DateTime.Now;
                bool bDisposed = base._IsDisposed;
                lock (m_hs_task_running) {
                    foreach (var v in m_hs_task_running) {
                        if (!v.IsStarted) continue;
                        if (dt.Subtract(v.StartTime).TotalMilliseconds > v.TotalTimeout || bDisposed) {
                            v.IsStarted = false;
                            v.IsTotalTimeout = true;
                            base.CloseSocket(v.Socket);
                            continue;
                        }
                        if (dt.Subtract(v.LastTime).TotalMilliseconds > v.Timeout) {
                            v.IsStarted = false;
                            base.CloseSocket(v.Socket);
                        }
                    }
                }
                if (bDisposed) break;
            }
        }

        public override void Dispose() {
            lock (m_obj_sync) {
                if (base._IsDisposed) return;
                base._IsDisposed = true;
            }
        }
    }
}
