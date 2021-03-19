using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace ST.Library.Network
{
    public class SmbScanner : PortScanner
    {
        #region smb_packet

        private static int[] m_byNext;

        private static byte[] m_byNTLMSSP;

        private static byte[] m_bySmbHeader = new byte[] { 0xFF, 0x53, 0x4D, 0x42 };

        private static byte[] m_bySmb1 = new byte[]{
            0x00,0x00,0x00,0x85,0xff,0x53,0x4d,0x42,0x72,0x00 
            ,0x00,0x00,0x00,0x18,0x53,0xc8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ,0x00,0x00,0x00,0x00,0xff,0xfe,0x00,0x00,0x00,0x00,0x00,0x62,0x00,0x02,0x50,0x43
            ,0x20,0x4e,0x45,0x54,0x57,0x4f,0x52,0x4b,0x20,0x50,0x52,0x4f,0x47,0x52,0x41,0x4d
            ,0x20,0x31,0x2e,0x30,0x00,0x02,0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x31,0x2e,0x30,0x00
            ,0x02,0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x20,0x66,0x6f,0x72,0x20,0x57,0x6f,0x72
            ,0x6b,0x67,0x72,0x6f,0x75,0x70,0x73,0x20,0x33,0x2e,0x31,0x61,0x00,0x02,0x4c,0x4d
            ,0x31,0x2e,0x32,0x58,0x30,0x30,0x32,0x00,0x02,0x4c,0x41,0x4e,0x4d,0x41,0x4e,0x32
            ,0x2e,0x31,0x00,0x02,0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00
        };

        private static byte[] m_bySmb2 = new byte[]{
            0x00,0x00,0x01,0x0a,0xff,0x53,0x4d,0x42,0x73,0x00,0x00,0x00,0x00,0x18,0x07,0xc8
            ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xfe
            ,0x00,0x00,0x40,0x00,0x0c,0xff,0x00,0x0a,0x01,0x04,0x41,0x32,0x00,0x00,0x00,0x00
            ,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00,0x00,0xd4,0x00,0x00,0xa0,0xcf,0x00,0x60
            ,0x48,0x06,0x06,0x2b,0x06,0x01,0x05,0x05,0x02,0xa0,0x3e,0x30,0x3c,0xa0,0x0e,0x30
            ,0x0c,0x06,0x0a,0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2,0x2a,0x04
            ,0x28,0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x01,0x00,0x00,0x00,0x07,0x82,0x08
            ,0xa2,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ,0x00,0x05,0x02,0xce,0x0e,0x00,0x00,0x00,0x0f,0x00,0x57,0x00,0x69,0x00,0x6e,0x00
            ,0x64,0x00,0x6f,0x00,0x77,0x00,0x73,0x00,0x20,0x00,0x53,0x00,0x65,0x00,0x72,0x00
            ,0x76,0x00,0x65,0x00,0x72,0x00,0x20,0x00,0x32,0x00,0x30,0x00,0x30,0x00,0x33,0x00
            ,0x20,0x00,0x33,0x00,0x37,0x00,0x39,0x00,0x30,0x00,0x20,0x00,0x53,0x00,0x65,0x00
            ,0x72,0x00,0x76,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x20,0x00,0x50,0x00,0x61,0x00
            ,0x63,0x00,0x6b,0x00,0x20,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x57,0x00,0x69,0x00
            ,0x6e,0x00,0x64,0x00,0x6f,0x00,0x77,0x00,0x73,0x00,0x20,0x00,0x53,0x00,0x65,0x00
            ,0x72,0x00,0x76,0x00,0x65,0x00,0x72,0x00,0x20,0x00,0x32,0x00,0x30,0x00,0x30,0x00
            ,0x33,0x00,0x20,0x00,0x35,0x00,0x2e,0x00,0x32,0x00,0x00,0x00,0x00,0x00
        };

        #endregion

        private Semaphore m_se;
        private Queue<SmbScanTaskInfo> m_que_task;
        private Queue<SocketAsyncEventArgs> m_que_sae;
        private HashSet<SmbScanTaskInfo> m_hs_task_running;
        private StringBuilder m_strBuffer = new StringBuilder();
        //private object m_obj_sync = new object();

        private static Dictionary<int, string> m_dic_netbios = new Dictionary<int, string>();

        //private bool _IsDisposed = false;

        //public bool IsDisposed {
        //    get { return _IsDisposed; }
        //}

        public SmbScanner(int nMaxTask) {
            m_dic_netbios.Add(1, "NetBIOS computer name ");
            m_dic_netbios.Add(2, "NetBIOS domain name   ");
            m_dic_netbios.Add(3, "DNS computer name     ");
            m_dic_netbios.Add(4, "DNS domain name       ");
            m_dic_netbios.Add(6, "Flags                 ");
            m_dic_netbios.Add(7, "Timestamp             ");
            m_se = new Semaphore(nMaxTask, nMaxTask);
            m_que_sae = new Queue<SocketAsyncEventArgs>();
            m_que_task = new Queue<SmbScanTaskInfo>();
            m_hs_task_running = new HashSet<SmbScanTaskInfo>();
            for (int i = 0; i < nMaxTask; i++) {
                SmbScanTaskInfo ti = new SmbScanTaskInfo();
                SocketAsyncEventArgs sae = new SocketAsyncEventArgs();
                sae.Completed += new EventHandler<SocketAsyncEventArgs>(IO_Completed);
                sae.SetBuffer(new byte[1500], 0, 1500);
                ti.RecvSAE = sae;
                sae.UserToken = ti;
                m_que_task.Enqueue(ti);
            }
            m_byNTLMSSP = Encoding.UTF8.GetBytes("NTLMSSP\0");
            m_byNext = SmbScanner.GetNextVal(m_byNTLMSSP);
            new Thread(this.CheckTimeout) { IsBackground = true }.Start();
        }

        protected override uint OnScan(int nPort, EndPoint endPoint, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbes) {
            lock (m_obj_sync) {
                if (base._IsDisposed) throw new ObjectDisposedException("TCPScanner", "The scanner was disposed");
            }
            m_se.WaitOne();
            SmbScanTaskInfo ti = this.CreateTaskInfo(445, endPoint, 0, nTimeout, nRetry, nTotalTimeout, false);
            ti.StartTime = DateTime.Now;
            this.StartConnect(ti);
            return ti.TaskID;
        }

        private SmbScanTaskInfo CreateTaskInfo(int nPort, EndPoint endPoint, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbe) {
            SmbScanTaskInfo ti = null;
            lock (m_obj_sync) {
                ti = m_que_task.Dequeue();
            }
            ti.Retry = nRetry;
            ti.RunedRetry = 0;
            ti.Port = nPort;
            ti.EndPoint = endPoint;
            ti.IsStarted = false;
            ti.Socket = this.GetNextSocket(nTimeout);
            ti.CanConnect = false;
            ti.Timeout = nTimeout;
            ti.TotalTimeout = nTotalTimeout;
            ti.Step = 1;
            return ti;
        }

        private void StartConnect(SmbScanTaskInfo ti) {
            if (ti.Socket != null) base.CloseSocket(ti.Socket);
            ti.Socket = this.GetNextSocket(ti.Timeout);
            ti.LastTime = DateTime.Now;
            ti.IsStarted = true;
            lock (m_hs_task_running) m_hs_task_running.Add(ti);
            SocketAsyncEventArgs sae = this.PopSAE();
            sae.SetBuffer(0, 0);
            sae.RemoteEndPoint = ti.EndPoint;
            sae.UserToken = ti;
            try {
                if (!ti.Socket.ConnectAsync(sae)) IOProcessPool.QueueWork(this.ProcessConnect, sae);
            } catch (Exception ex) {
                this.PushSAE(sae);
                this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, ti.CanConnect, "[SOCKET]-" + ex.Message));
            }
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
            SmbScanTaskInfo ti = e.UserToken as SmbScanTaskInfo;
            ti.LastTime = DateTime.Now;
            Socket sock = ti.Socket;
            if (e.SocketError != SocketError.Success) {
                this.PushSAE(e);
                if (++ti.RunedRetry > ti.Retry)
                    this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, ti.CanConnect, e.SocketError.ToString()));
                else
                    this.StartConnect(ti);
                return;
            }
            ti.RunedRetry = 0;
            ti.CanConnect = true;
            try {
                if (!sock.ReceiveAsync(ti.RecvSAE)) IOProcessPool.QueueWork(this.ProcessRecv, ti.RecvSAE);
            } catch (Exception ex) {
                this.PushSAE(e);
                this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, ti.CanConnect, "[SOCKET]-" + ex.Message));
                return;
            }
            try {
                Array.Copy(m_bySmb1, e.Buffer, m_bySmb1.Length);
                e.SetBuffer(0, m_bySmb1.Length);
                if (!sock.SendAsync(e)) IOProcessPool.QueueWork(this.ProcessSend, e);
            } catch {
                this.PushSAE(e);
            }
        }

        private void ProcessSend(SocketAsyncEventArgs e) {
            this.PushSAE(e);
        }

        private void ProcessRecv(SocketAsyncEventArgs e) {
            SmbScanTaskInfo ti = e.UserToken as SmbScanTaskInfo;
            ti.LastTime = DateTime.Now;
            if (e.SocketError != SocketError.Success || e.BytesTransferred < 1) {
                //if (ti.RunedRetry < ti.Retry) {
                //    ti.Step = 1;
                //    this.StartConnect(ti);
                //} else this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, ti.CanConnect, e.SocketError.ToString()));
                this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, ti.CanConnect, e.SocketError.ToString()));
                return;
            }
            if (!SmbScanner.CheckHeader(e.Buffer)) {
                this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, true, "The header is not smb"));
                return;
            }
            if (ti.Step == 1) {
                SocketAsyncEventArgs sae = this.PopSAE();
                try {
                    Array.Copy(m_bySmb2, sae.Buffer, m_bySmb2.Length);
                    sae.SetBuffer(0, m_bySmb2.Length);//buffer
                    if (!ti.Socket.SendAsync(sae)) IOProcessPool.QueueWork(this.ProcessSend, sae);
                } catch {
                    this.PushSAE(sae);
                }
                try {
                    ti.Step++;
                    if (!ti.Socket.ReceiveAsync(e)) IOProcessPool.QueueWork(this.ProcessRecv, e);
                } catch (Exception ex) {
                    this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, ex.Message));
                    return;
                }
            } else {
                string strResult = string.Empty;
                int nOffsetNtlmssp = SmbScanner.KmpIndexOf(0, e.Buffer, m_byNTLMSSP, m_byNext);
                if (nOffsetNtlmssp == -1) {
                    this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, "SMB", -1, "", e.Buffer, e.BytesTransferred));
                    return;
                }
                lock (m_strBuffer) {
                    try {
                        m_strBuffer.Remove(0, m_strBuffer.Length);
                        m_strBuffer.Append("Target Name           :");
                        m_strBuffer.Append(Encoding.Unicode.GetString(e.Buffer, e.Buffer[nOffsetNtlmssp + 16] + nOffsetNtlmssp, e.Buffer[nOffsetNtlmssp + 12]));
                        int nOffsetData = e.Buffer[nOffsetNtlmssp + 16] + nOffsetNtlmssp + e.Buffer[nOffsetNtlmssp + 12];
                        while (e.Buffer[nOffsetData] != 0) {
                            if (m_dic_netbios.ContainsKey(e.Buffer[nOffsetData]))
                                m_strBuffer.Append("\r\n" + m_dic_netbios[e.Buffer[nOffsetData]] + ":");
                            else
                                m_strBuffer.Append("\r\n" + e.Buffer[nOffsetData].ToString("X2") + ":");
                            if (!m_dic_netbios.ContainsKey(e.Buffer[nOffsetData]) || e.Buffer[nOffsetData] == 6 || e.Buffer[nOffsetData] == 7) {
                                for (int i = nOffsetData + 4; i < nOffsetData + 4 + e.Buffer[nOffsetData + 2]; i++)
                                    m_strBuffer.Append(((int)e.Buffer[i]).ToString("X2"));
                            } else {
                                m_strBuffer.Append(Encoding.Unicode.GetString(e.Buffer, nOffsetData + 4, e.Buffer[nOffsetData + 2]));
                            }
                            nOffsetData += e.Buffer[nOffsetData + 2] + 4;
                        }
                        m_strBuffer.Append("\r\n----------OS----------\r\n" + Encoding.Unicode.GetString(e.Buffer, nOffsetData + 4, e.BytesTransferred - nOffsetData - 4).Replace("\0", "\r\n"));
                        strResult = m_strBuffer.ToString();
                    } catch {
                        strResult = "[ERROR] - Can not format the data";
                    }
                }
                this.EndTask(ti, new ScanEventArgs(ti.TaskID, ti.EndPoint, "SMB", -1, strResult, e.Buffer, e.BytesTransferred));
            }
        }

        private void EndTask(SmbScanTaskInfo ti, ScanEventArgs e) {
            this.CloseSocket(ti.Socket);
            ti.Socket = null;
            ti.IsStarted = false;
            lock (m_hs_task_running) m_hs_task_running.Remove(ti);
            lock (m_obj_sync) {
                if (!base._IsDisposed) m_que_task.Enqueue(ti);
            }
            base.OnCompleted(e);
            m_se.Release();
        }

        private Socket GetNextSocket(int nTimeout) {
            Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            sock.SendTimeout = sock.ReceiveTimeout = nTimeout;
            return sock;
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

        public override void Dispose() {
            lock (m_obj_sync) {
                if (base._IsDisposed) return;
                base._IsDisposed = true;
            }
        }

        private void CheckTimeout() {
            DateTime dt = DateTime.Now;
            while (true) {
                dt = DateTime.Now;
                Thread.Sleep(500);
                bool bDisposed = base._IsDisposed;
                lock (m_hs_task_running) {
                    foreach (var v in m_hs_task_running) {
                        if (!v.IsStarted) continue;
                        if (dt.Subtract(v.StartTime).TotalMilliseconds > v.TotalTimeout || bDisposed) {
                            v.Socket.Close();
                            continue;
                        }
                        if (dt.Subtract(v.LastTime).TotalMilliseconds > v.Timeout) {
                            v.Socket.Close();
                        }
                    }
                }
                if (bDisposed) break;
            }
        }

        private static bool CheckHeader(byte[] byBuffer) {
            if (byBuffer[0] != 0) return false;
            for (int i = 0; i < m_bySmbHeader.Length; i++) {
                if (m_bySmbHeader[i] != byBuffer[i + 4]) return false;
            }
            return true;
        }

        private static int KmpIndexOf(int nIndex, byte[] byParent, byte[] bySub, int[] nextVal) {
            int i = nIndex, j = -1;
            if (nextVal == null) nextVal = SmbScanner.GetNextVal(bySub);

            while (i < byParent.Length && j < bySub.Length) {
                if (j == -1 || byParent[i] == bySub[j]) {
                    i++;
                    j++;
                } else {
                    j = nextVal[j];
                }
            }
            return j >= bySub.Length ? i - bySub.Length : -1;
        }

        private static int[] GetNextVal(byte[] bySub) {
            int j = 0, k = -1;
            int[] nextVal = new int[bySub.Length];

            nextVal[0] = -1;

            while (j < bySub.Length - 1) {
                if (k == -1 || bySub[j] == bySub[k]) {
                    j++;
                    k++;
                    nextVal[j] = bySub[j] != bySub[k] ? k : nextVal[k];
                } else {
                    k = nextVal[k];
                }
            }
            return nextVal;
        }
    }
}
