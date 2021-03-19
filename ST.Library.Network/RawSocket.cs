using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Net;
using System.Net.Sockets;

namespace ST.Library.Network
{
    public class RawSocket
    {
        private static Socket m_sock_raw;
        private static Queue<SocketAsyncEventArgs> m_que_sae;

        public static event EventHandler<SocketAsyncEventArgs> RecvCompleted;

        private static object m_obj_sync = new object();

        private static bool _IsDisposed;

        public static bool IsDisposed {
            get { return _IsDisposed; }
        }

        public static void InitRawSocket(EndPoint bindEndPoint) {
            lock (m_obj_sync) {
                if (m_sock_raw != null) return;
                m_que_sae = new Queue<SocketAsyncEventArgs>();

                if (bindEndPoint == null) {
                    foreach (var v in Dns.GetHostAddresses(Dns.GetHostName())) {
                        if (v.IsIPv6LinkLocal || v.IsIPv6Multicast || v.IsIPv6SiteLocal) continue;
                        bindEndPoint = new IPEndPoint(v, 0);
                    }
                }
                m_sock_raw = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
                m_sock_raw.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                m_sock_raw.Bind(bindEndPoint);
                m_sock_raw.IOControl(IOControlCode.ReceiveAll, new byte[] { 1, 0, 0, 0 }, null);

                SocketAsyncEventArgs sae = new SocketAsyncEventArgs();
                sae.Completed += new EventHandler<SocketAsyncEventArgs>(IO_Completed);
                sae.SetBuffer(new byte[65535], 0, 65535);
                sae.UserToken = m_sock_raw;
                sae.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                if (!m_sock_raw.ReceiveFromAsync(sae)) IOProcessPool.QueueWork(RawSocket.ProcessRecv, sae);
            }
        }

        private static void OnRecvCompleted(SocketAsyncEventArgs e) {
            if (RawSocket.RecvCompleted != null) RawSocket.RecvCompleted(null, e);
        }

        public static void SendData(byte[] byData, int nIndex, int nLen) {
            SocketAsyncEventArgs sae = RawSocket.PopSAE();
            if (sae.Buffer == null || sae.Buffer.Length < nLen) {
                sae.SetBuffer(byData, nIndex, nLen);
            } else Array.Copy(byData, nIndex, sae.Buffer, 0, nLen);
            //sae.remo
            if (!m_sock_raw.SendToAsync(sae)) IOProcessPool.QueueWork(RawSocket.ProcessRecv, sae);
        }

        private static void IO_Completed(object sender, SocketAsyncEventArgs e) {
            switch (e.LastOperation) {
                case SocketAsyncOperation.SendTo:
                    RawSocket.ProcessSend(e);
                    break;
                case SocketAsyncOperation.ReceiveFrom:
                    RawSocket.ProcessRecv(e);
                    break;
            }
        }

        private static void ProcessSend(SocketAsyncEventArgs e) {
            RawSocket.PushSAE(e);
        }

        private static void ProcessRecv(SocketAsyncEventArgs e) {
            Socket sock = e.UserToken as Socket;
            if (e.SocketError == SocketError.Success && e.BytesTransferred > 0) {
                RawSocket.OnRecvCompleted(e);
            }
            try {
                if (!m_sock_raw.ReceiveFromAsync(e)) IOProcessPool.QueueWork(RawSocket.ProcessRecv, e);
            } catch { }
        }

        private static SocketAsyncEventArgs PopSAE() {
            lock (m_obj_sync) {
                if (m_que_sae.Count != 0) return m_que_sae.Dequeue();
            }
            SocketAsyncEventArgs sae = new SocketAsyncEventArgs();
            sae.Completed += new EventHandler<SocketAsyncEventArgs>(IO_Completed);
            sae.SetBuffer(new byte[9], 0, 9);
            sae.RemoteEndPoint = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 0);
            return sae;
        }

        private static void PushSAE(SocketAsyncEventArgs sae) {
            lock (m_obj_sync) {
                m_que_sae.Enqueue(sae);
            }
        }

        public static void Dispose() {
            lock (m_obj_sync) {
                if (RawSocket._IsDisposed) return;
                RawSocket._IsDisposed = true;
                try {
                    m_sock_raw.Shutdown(SocketShutdown.Both);
                } catch { }
                m_sock_raw.Close();
            }
        }
    }
}
