using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace ST.Library.Network
{
    public abstract class PortScanner : IPortScanner, IDisposable
    {
        internal bool _IsDisposed = false;

        public bool IsDisposed {
            get { return _IsDisposed; }
        }

        public uint Scan(uint uIP, int nPort) {
            //return this.Scan(nPort, new IPEndPoint(new IPAddress(uIP), nPort), 3, 3000, 1, 18000, false);
            return this.OnScan(nPort, new IPEndPoint(new IPAddress(uIP), nPort), 3, 3000, 1, 60000, false);
        }

        public uint Scan(uint uIP, int nPort, int nProbes) {
            //return Scan(nPort, new IPEndPoint(new IPAddress(uIP), nPort), nProbes, 3000, 1, ((nProbes + 1) * 2 * 3000), false);
            return OnScan(nPort, new IPEndPoint(new IPAddress(uIP), nPort), nProbes, 3000, 1, 60000, false);
        }

        public uint Scan(uint uIP, int nPort, int nProbes, int nTimeout) {
            //return Scan(nPort, new IPEndPoint(new IPAddress(uIP), nPort), nProbes, nTimeout, 1, ((nProbes + 1) * 2 * nTimeout), false);
            return OnScan(nPort, new IPEndPoint(new IPAddress(uIP), nPort), nProbes, nTimeout, 1, 60000, false);
        }

        public uint Scan(uint uIP, int nPort, int nProbes, int nTimeout, int nRetry) {
            //return Scan(nPort, new IPEndPoint(new IPAddress(uIP), nPort), nProbes, nTimeout, nRetry, ((nProbes + 1) * (nRetry + 1) * nTimeout), false);
            return OnScan(nPort, new IPEndPoint(new IPAddress(uIP), nPort), nProbes, nTimeout, nRetry, 60000, false);
        }

        public uint Scan(uint uIP, int nPort, int nProbes, int nTimeout, int nRetry, int nTotalTimeout) {
            return OnScan(nPort, new IPEndPoint(new IPAddress(uIP), nPort), nProbes, nTimeout, nRetry, nTotalTimeout, false);
        }

        public uint Scan(uint uIP, int nPort, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbe) {
            return OnScan(nPort, new IPEndPoint(new IPAddress(uIP), nPort), nProbes, nTimeout, nRetry, nTotalTimeout, bUseNullProbe);
        }

        public uint Scan(string strIP, int nPort) {
            //return this.Scan(nPort, new IPEndPoint(IPAddress.Parse(strIP), nPort), 3, 3000, 1, 18000, false);
            return this.OnScan(nPort, new IPEndPoint(IPAddress.Parse(strIP), nPort), 3, 3000, 1, 60000, false);
        }

        public uint Scan(string strIP, int nPort, int nProbes) {
            //return this.Scan(nPort, new IPEndPoint(IPAddress.Parse(strIP), nPort), nProbes, 3000, 1, ((nProbes + 1) * 2 * 3000), false);
            return this.OnScan(nPort, new IPEndPoint(IPAddress.Parse(strIP), nPort), nProbes, 3000, 1, 60000, false);
        }

        public uint Scan(string strIP, int nPort, int nProbes, int nTimeout) {
            //return this.Scan(nPort, new IPEndPoint(IPAddress.Parse(strIP), nPort), nProbes, nTimeout, 1, ((nProbes + 1) * 2 * nTimeout), false);
            return this.OnScan(nPort, new IPEndPoint(IPAddress.Parse(strIP), nPort), nProbes, nTimeout, 1, 60000, false);
        }

        public uint Scan(string strIP, int nPort, int nProbes, int nTimeout, int nRetry) {
            //return this.Scan(nPort, new IPEndPoint(IPAddress.Parse(strIP), nPort), nProbes, nTimeout, nRetry, ((nProbes + 1) * (nRetry + 1) * nTimeout), false);
            return this.OnScan(nPort, new IPEndPoint(IPAddress.Parse(strIP), nPort), nProbes, nTimeout, nRetry, 60000, false);
        }

        public uint Scan(string strIP, int nPort, int nProbes, int nTimeout, int nRetry, int nTotalTimeout) {
            return this.OnScan(nPort, new IPEndPoint(IPAddress.Parse(strIP), nPort), nProbes, nTimeout, nRetry, nTotalTimeout, false);
        }

        public uint Scan(string strIP, int nPort, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbe) {
            return this.OnScan(nPort, new IPEndPoint(IPAddress.Parse(strIP), nPort), nProbes, nTimeout, nRetry, nTotalTimeout, bUseNullProbe);
        }

        public uint Scan(int nPort, EndPoint endPoint, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbe) {
            return this.OnScan(nPort, endPoint, nProbes, nTimeout, nRetry, nTotalTimeout, bUseNullProbe);
        }
        //========================================
        public event ScanEventHandler Completed;
        protected virtual void OnCompleted(ScanEventArgs e) {
            if (this.Completed != null) this.Completed(this, e);
        }

        protected object m_obj_sync = new object();

        internal PortScanner() { }

        protected void CloseSocket(Socket sock) {
            lock (m_obj_sync) {
                if (sock == null /*|| !sock.Connected*/) return;
                //if (sock.Connected) {
                //    try {
                //        sock.Shutdown(SocketShutdown.Both);
                //    } catch (Exception ex) { Console.WriteLine("EX:" + ex.Message); }
                //}
                sock.Close();
            }
        }

        public abstract void Dispose();
        protected abstract uint OnScan(int nPort, EndPoint endPoint, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbe);
    }
}
