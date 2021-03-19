using System;
using System.Collections.Generic;
using System.Text;

using System.Net;
using System.Net.Sockets;

namespace ST.Library.Network
{
    public delegate void IcmpEventHandler(object sender,IcmpEventArgs e);
    public delegate void ScanEventHandler(object sender, ScanEventArgs e);

    internal class ScanTaskInfo
    {
        public uint TaskID;
        public int Retry;
        public int RunedRetry;
        public int Port;
        public EndPoint EndPoint;
        public bool IsStarted;
        public bool IsTotalTimeout;
        public DateTime StartTime;
        public DateTime LastTime;
        public int Timeout;
        public int TotalTimeout;
    }

    internal class TCPScanTaskInfo : ScanTaskInfo
    {
        public Socket Socket;
        public bool CanConnect;
        public ProbeInfo CurrentProbe;
        public Queue<ProbeInfo> SendProbes;
        public SocketAsyncEventArgs RecvSAE;
    }

    internal class SYNScanTaskInfo : ScanTaskInfo
    {
        public byte[] SYNPacket;
        public int Probes;
        public bool IsUseNullProbe;
        public uint SEQ;
        public uint UIP;
    }

    internal class UDPScanTaskInfo : ScanTaskInfo
    {
        //public ProbeInfo CurrentProbe;
        public List<byte[]> SendDatas;
        public Queue<byte[]> SendDatasQueue;
        //public Queue<ProbeInfo> SendProbes;
    }

    internal class SmbScanTaskInfo : ScanTaskInfo {
        public int Step;
        public Socket Socket;
        public bool CanConnect;
        public SocketAsyncEventArgs RecvSAE;
    }
}
