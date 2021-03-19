using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Net;
using System.Threading;
using System.Net.Sockets;
using System.Diagnostics;

namespace ST.Library.Network
{
    public class IcmpScanner : IDisposable
    {
        private Random m_rnd;
        private Socket m_sock;
        private Semaphore m_se;
        private Queue<TaskInfo> m_que_taskInfo;
        private object m_obj_sync = new object();
        private Queue<SocketAsyncEventArgs> m_que_sae;
        private Dictionary<uint, TaskInfo> m_dic_task_running;

        private Stopwatch m_sw = new Stopwatch();

        private bool _IsDisposed;

        private byte[] by_icmp = new byte[] {
            0x08,
            0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00
        };

        private class TaskInfo
        {
            public uint ID;
            public int Retry;
            public int Timeout;
            public int DataLen;
            public int RunedRetry;
            public bool IsStarted;
            public byte[] HeadPacket;
            public byte[] TempPacket;
            public EndPoint EndPoint;
            public long StartTime;
            public long LastTime;
        }

        public event IcmpEventHandler Completed;

        protected virtual void OnCompleted(IcmpEventArgs e) {
            if (this.Completed != null) this.Completed(this, e);
        }

        public IcmpScanner(int nMaxTask) {
            if (nMaxTask > 60000) throw new ArgumentException("The [nMaxTask] must less than 60000");
            m_rnd = new Random();
            m_que_taskInfo = new Queue<TaskInfo>();
            m_se = new Semaphore(nMaxTask, nMaxTask);
            m_que_sae = new Queue<SocketAsyncEventArgs>();
            m_dic_task_running = new Dictionary<uint, TaskInfo>();

            for (int i = 0; i < nMaxTask; i++) {
                TaskInfo ti = new TaskInfo();
                ti.ID = (uint)(i + 1);
                ti.HeadPacket = new byte[]  {
                    0x08, 0x00,                     //type:8 code:0 - request ping
                    0x00, 0x00,                     //checksum
                    0x00, (byte)((i % 10) + 1),     //flag_id
                    (byte)(ti.ID >> 8), (byte)ti.ID //seq
                };
                ti.TempPacket = new byte[ti.HeadPacket.Length + 1];
                m_que_taskInfo.Enqueue(ti);
            }
            m_sw.Start();
            m_sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
            SocketAsyncEventArgs sae = new SocketAsyncEventArgs();
            sae.Completed += new EventHandler<SocketAsyncEventArgs>(IO_Completed);
            sae.SetBuffer(new byte[65535], 0, 65535);
            sae.UserToken = m_sock;
            sae.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            if (!m_sock.ReceiveFromAsync(sae)) IOProcessPool.QueueWork(this.ProcessRecv, sae);
            new Thread(this.CheckTimeout) { IsBackground = true }.Start();
        }

        private SocketAsyncEventArgs PopSAE() {
            lock (m_obj_sync) {
                if (m_que_sae.Count != 0) return m_que_sae.Dequeue();
            }
            SocketAsyncEventArgs sae = new SocketAsyncEventArgs();
            sae.Completed += new EventHandler<SocketAsyncEventArgs>(IO_Completed);
            sae.SetBuffer(new byte[9], 0, 9);
            return sae;
        }

        private void PushSAE(SocketAsyncEventArgs sae) {
            lock (m_obj_sync) {
                if (this._IsDisposed) return;
                m_que_sae.Enqueue(sae);
            }
        }

        public uint Ping(IPAddress ipAddr, int nTimeout) {
            return this.Ping(ipAddr, nTimeout, 3, null);
        }

        public uint Ping(IPAddress ipAddr, int nTimeout, int nRetry) {
            return this.Ping(ipAddr, nTimeout, nRetry, null);
        }

        public uint Ping(IPAddress ipAddr, int nTimeout, int nRetry, byte[] byData) {
            lock (m_obj_sync) {
                if (this._IsDisposed) throw new ObjectDisposedException("IcmpScanner", "The scanner was disposed");
            }
            m_se.WaitOne();
            TaskInfo ti = this.CreateTaskInfo(ipAddr, nRetry, byData);
            lock (m_dic_task_running) {
                m_dic_task_running.Add(ti.ID, ti);
            }
            ti.StartTime = m_sw.ElapsedMilliseconds;
            this.SendData(ti);
            return ti.ID;
        }

        private TaskInfo CreateTaskInfo(IPAddress ipAddr, int nRetry, byte[] byData) {
            TaskInfo ti = null;
            lock (m_que_taskInfo) ti = m_que_taskInfo.Dequeue();
            if (byData != null) {
                if (byData.Length > 1400) throw new ArgumentException("The [byData.Length] must less than 1400");
                if (byData.Length + ti.HeadPacket.Length > ti.TempPacket.Length) {
                    ti.TempPacket = new byte[byData.Length + ti.HeadPacket.Length];
                    Array.Copy(ti.HeadPacket, ti.TempPacket, ti.HeadPacket.Length);
                    Array.Copy(byData, 0, ti.TempPacket, ti.HeadPacket.Length, byData.Length);
                }
                ti.DataLen = ti.HeadPacket.Length + byData.Length;
            } else {
                ti.DataLen = ti.HeadPacket.Length + 1;
                Array.Copy(ti.HeadPacket, ti.TempPacket, ti.HeadPacket.Length);
                lock (m_rnd) ti.TempPacket[ti.HeadPacket.Length] = (byte)m_rnd.Next('a', 'z');
            }
            ti.TempPacket[2] = 0;
            ti.TempPacket[3] = 0;
            uint sum = RAWDefine.CheckSum(ti.TempPacket, ti.TempPacket.Length);
            ti.TempPacket[2] = (byte)sum;
            ti.TempPacket[3] = (byte)(sum >> 8);
            ti.EndPoint = new IPEndPoint(ipAddr, 0);
            ti.Retry = nRetry;
            ti.RunedRetry = 0;
            return ti;
        }

        private void SendData(TaskInfo ti) {
            SocketAsyncEventArgs sae = this.PopSAE();
            if (sae.Buffer.Length < ti.DataLen) {
                sae.SetBuffer(new byte[ti.DataLen], 0, ti.DataLen);
            }
            Array.Copy(ti.TempPacket, 0, sae.Buffer, 0, ti.DataLen);
            sae.SetBuffer(0, ti.DataLen);
            sae.RemoteEndPoint = ti.EndPoint;
            ti.LastTime = m_sw.ElapsedMilliseconds;
            ti.IsStarted = true;
            if (!m_sock.SendToAsync(sae)) IOProcessPool.QueueWork(this.ProcessSend, sae);
        }

        private void FullCheckSum(byte[] byPacket) {
            uint sum = RAWDefine.CheckSum(byPacket, byPacket.Length);
            byPacket[2] = (byte)sum;
            byPacket[3] = (byte)(sum >> 8);
        }

        private void IO_Completed(object sender, SocketAsyncEventArgs e) {
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
            this.PushSAE(e);
        }

        private void ProcessRecv(SocketAsyncEventArgs e) {
            Socket sock = e.UserToken as Socket;
            if (e.SocketError == SocketError.Success && e.BytesTransferred > 0) {
                bool b = true;
                TaskInfo ti = null;
                int nOffset = (e.Buffer[0] & 0x0F) * 4;
                uint uID = (uint)((e.Buffer[nOffset + 6] << 8) + e.Buffer[nOffset + 7]);
                if (e.BytesTransferred < 28) b = false;
                else if (e.Buffer[9] != RAWDefine.PROTO_ICMP) b = false;
                else if (nOffset < 20 || e.BytesTransferred - 9 < nOffset) b = false;
                if (b) {
                    lock (m_dic_task_running) {
                        if (m_dic_task_running.ContainsKey(uID)) {
                            ti = m_dic_task_running[uID];
                            m_dic_task_running.Remove(uID);
                        }
                    }
                }
                if (ti != null) {
                    if (e.Buffer[nOffset] + e.Buffer[nOffset + 1] == 0x00)
                        this.EndTask(ti, new IcmpEventArgs(uID,
                            ((IPEndPoint)ti.EndPoint).Address,
                            e.Buffer[8],
                            true,
                            (int)(m_sw.ElapsedMilliseconds - (ti.RunedRetry > 0 ? ti.StartTime : ti.LastTime)),
                            ti.RunedRetry));
                    else
                        this.EndTask(ti, new IcmpEventArgs(uID, ((IPEndPoint)ti.EndPoint).Address, ti.RunedRetry));
                }
            }
            if (!sock.ReceiveFromAsync(e)) IOProcessPool.QueueWork(this.ProcessRecv, e);
        }

        private void EndTask(TaskInfo ti, IcmpEventArgs e) {
            ti.IsStarted = false;
            this.OnCompleted(e);
            lock (m_que_taskInfo) {
                m_que_taskInfo.Enqueue(ti);
            }
            m_se.Release();
        }

        private void CheckTimeout() {
            long nTimes = 0;
            List<TaskInfo> lst_remove = new List<TaskInfo>();
            while (true) {
                Thread.Sleep(1000);
                lst_remove.Clear();
                nTimes = m_sw.ElapsedMilliseconds;
                bool bDisposed = this._IsDisposed;
                lock (m_dic_task_running) {
                    foreach (var v in m_dic_task_running) {
                        if (!v.Value.IsStarted) continue;
                        if (nTimes - v.Value.LastTime > v.Value.Timeout) {
                            if ((v.Value.RunedRetry + 1) <= v.Value.Retry) {
                                v.Value.IsStarted = false;
                                v.Value.RunedRetry++;
                                this.SendData(v.Value);
                            } else lst_remove.Add(v.Value);
                        }
                    }
                    foreach (var v in lst_remove) {
                        m_dic_task_running.Remove(v.ID);
                        this.EndTask(v, new IcmpEventArgs(v.ID, ((IPEndPoint)v.EndPoint).Address, v.RunedRetry));
                    }
                }
                if (bDisposed) break;
            }
        }

        public void Dispose() {
            lock (m_obj_sync) {
                if (this._IsDisposed) return;
                this._IsDisposed = true;
            }
        }
    }
}
