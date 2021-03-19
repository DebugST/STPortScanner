using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace ST.Library.Network
{
    public class UDPScanner : PortScanner
    {
        private Socket m_sock;
        private Semaphore m_se;
        private ProbeConfiger m_configer;
        private Queue<UDPScanTaskInfo> m_que_task;
        private Queue<SocketAsyncEventArgs> m_que_sae;
        private Dictionary<string, UDPScanTaskInfo> m_dic_task_running;

        public UDPScanner(int nMaxTask, ProbeConfiger probes) {
            m_se = new Semaphore(nMaxTask, nMaxTask);
            m_configer = probes;
            m_que_sae = new Queue<SocketAsyncEventArgs>();
            m_dic_task_running = new Dictionary<string, UDPScanTaskInfo>();
            m_que_task = new Queue<UDPScanTaskInfo>();
            for (int i = 0; i < nMaxTask; i++) {
                UDPScanTaskInfo ti = new UDPScanTaskInfo();
                ti.TaskID = (uint)i + 1;
                ti.SendDatas = new List<byte[]>();
                ti.SendDatasQueue = new Queue<byte[]>();
                m_que_task.Enqueue(ti);
            }
            m_sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            m_sock.Bind(new IPEndPoint(IPAddress.Any, 0));
            SocketAsyncEventArgs sae = new SocketAsyncEventArgs();
            sae.Completed += new EventHandler<SocketAsyncEventArgs>(IO_Completed);
            sae.SetBuffer(new byte[65535], 0, 65535);
            sae.UserToken = m_sock;
            sae.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            if (!m_sock.ReceiveFromAsync(sae)) IOProcessPool.QueueWork(this.ProcessRecv, sae);
            new Thread(this.CheckTimeout) { IsBackground = true }.Start();
        }

        protected override uint OnScan(int nPort, EndPoint endPoint, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbe) {
            lock (m_obj_sync) {
                if (base._IsDisposed) throw new ObjectDisposedException("UDPScanner", "The scanner was disposed");
            }
            string strError = string.Empty;
            UDPScanTaskInfo ti = null;
            m_se.WaitOne();
            try {
                ti = this.CreateTaskInfo(nPort, endPoint, nProbes, nTimeout, nRetry, nTotalTimeout);
            } catch (InvalidOperationException ex) {
                strError = ex.Message;
            }
            string strKey = endPoint.ToString();
            lock (m_dic_task_running) {
                if (m_dic_task_running.ContainsKey(strKey))
                    strError = "The task has running";
                else
                    m_dic_task_running.Add(strKey, ti);
            }
            if (strError != string.Empty) {
                this.EndTask(null, new ScanEventArgs(0, endPoint, strError));
                return 0;
            }
            ti.StartTime = DateTime.Now;
            this.SendData(ti);
            //ti.IsStarted = true;
            return ti.TaskID;
        }

        private void SendData(UDPScanTaskInfo ti) {
            SocketAsyncEventArgs sae = this.PopSAE();
            byte[] byData = ti.SendDatasQueue.Dequeue();
            if (sae.Buffer.Length < byData.Length)
                sae.SetBuffer(new byte[byData.Length], 0, byData.Length);
            Array.Copy(byData, sae.Buffer, byData.Length);
            sae.SetBuffer(0, byData.Length);
            ti.LastTime = DateTime.Now;
            sae.RemoteEndPoint = ti.EndPoint;
            if (!m_sock.SendToAsync(sae)) IOProcessPool.QueueWork(this.ProcessSend, sae);
        }

        private SocketAsyncEventArgs PopSAE() {
            lock (m_obj_sync) {
                if (m_que_sae.Count != 0) return m_que_sae.Dequeue();
            }
            SocketAsyncEventArgs sae = new SocketAsyncEventArgs();
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

        private UDPScanTaskInfo CreateTaskInfo(int nPort, EndPoint endPoint, int nProbes, int nTimeout, int nRetry, int nTotalTimeout) {
            UDPScanTaskInfo ti = null;
            lock (m_obj_sync) {
                ti = m_que_task.Dequeue();
            }
            ti.Retry = nRetry;
            ti.RunedRetry = 0;
            ti.Port = nPort;
            ti.EndPoint = endPoint;
            ti.IsStarted = false;
            ti.Timeout = nTimeout;
            ti.TotalTimeout = nTotalTimeout;
            Queue<ProbeInfo> pi = null;
            if (nProbes < 0)
                pi = m_configer.GetProbesQueue(ProbeType.Udp, nPort, 0);
            else
                pi = m_configer.GetProbesQueue(ProbeType.Udp, nPort, nProbes);
            if (pi.Count == 0)
                throw new InvalidOperationException("Can not match the probes whith port [" + nPort + "]");
            ti.SendDatas.Clear();
            ti.SendDatasQueue.Clear();
            foreach (var v in pi) {
                ti.SendDatas.Add(v.Data);
                ti.SendDatasQueue.Enqueue(v.Data);
            }
            return ti;
        }

        void IO_Completed(object sender, SocketAsyncEventArgs e) {
            switch (e.LastOperation) {
                case SocketAsyncOperation.SendTo:
                    this.ProcessSend(e);
                    break;
                case SocketAsyncOperation.ReceiveFrom:
                    this.ProcessRecv(e);
                    break;
            }
        }

        private void ProcessSend(SocketAsyncEventArgs e) {
            string strKey = e.RemoteEndPoint.ToString();
            this.PushSAE(e);
            UDPScanTaskInfo ti = null;
            lock (m_dic_task_running) {
                if (!m_dic_task_running.ContainsKey(strKey)) return;
                ti = m_dic_task_running[strKey];
            }
            ti.LastTime = DateTime.Now;
            if (ti.SendDatasQueue.Count != 0) this.SendData(ti);
            else ti.IsStarted = true;
        }

        private void ProcessRecv(SocketAsyncEventArgs e) {
            Socket sock = e.UserToken as Socket;
            if (e.SocketError == SocketError.Success && e.BytesTransferred > 0) {
                //add code
                bool bOK = true;
                UDPScanTaskInfo ti = null;
                string strKey = e.RemoteEndPoint.ToString();
                lock (m_dic_task_running) {
                    if (!m_dic_task_running.ContainsKey(strKey)) bOK = false;
                    else {
                        ti = m_dic_task_running[strKey];
                        ti.IsStarted = false;
                        m_dic_task_running.Remove(strKey);
                    }
                }
                if (bOK) {
                    MatchResult mr = m_configer.MatchData(e.Buffer, e.BytesTransferred, ((IPEndPoint)e.RemoteEndPoint).Port, ProbeType.Udp);
                    this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, mr.Name, mr.RegexLine, mr.DataString, e.Buffer, e.BytesTransferred));
                }
            }
            if (!sock.ReceiveFromAsync(e)) this.ProcessRecv(e);
        }

        private void EndTask(UDPScanTaskInfo ti, ScanEventArgs e) {
            //ti.IsStarted = false;
            if (ti != null) {
                ti.IsStarted = false;
                lock (m_que_task) m_que_task.Enqueue(ti);
            }
            base.OnCompleted(e);
            m_se.Release();
        }

        private void CheckTimeout() {
            DateTime dt = DateTime.Now;
            //List<UDPScanTaskInfo> lst_remove = new List<UDPScanTaskInfo>();
            HashSet<UDPScanTaskInfo> hs = new HashSet<UDPScanTaskInfo>();
            while (true) {
                Thread.Sleep(1000);
                hs.Clear();
                dt = DateTime.Now;
                bool bDisposed = base._IsDisposed;
                lock (m_dic_task_running) {
                    foreach (var v in m_dic_task_running) {
                        if (!v.Value.IsStarted) continue;
                        if (dt.Subtract(v.Value.StartTime).TotalMilliseconds > v.Value.TotalTimeout || bDisposed) {
                            hs.Add(v.Value);
                            continue;
                        }
                        if (dt.Subtract(v.Value.LastTime).TotalMilliseconds > v.Value.Timeout) {
                            if (v.Value.Retry-- != 0) {
                                v.Value.IsStarted = false;
                                foreach (var d in v.Value.SendDatas) v.Value.SendDatasQueue.Enqueue(d);
                                this.SendData(v.Value);
                            } else hs.Add(v.Value);
                        }
                    }
                    foreach (var v in hs) {
                        this.EndTask(v, new ScanEventArgs(v.TaskID, v.EndPoint, "Timeout"));
                        m_dic_task_running.Remove(v.EndPoint.ToString());
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
