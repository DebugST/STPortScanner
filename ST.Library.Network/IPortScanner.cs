using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Net;

namespace ST.Library.Network
{
    public interface IPortScanner : IDisposable
    {
        event ScanEventHandler Completed;
        uint Scan(uint uIP, int nPort);
        uint Scan(uint uIP, int nPort, int nProbes);
        uint Scan(uint uIP, int nPort, int nProbes, int nTimeout);
        uint Scan(uint uIP, int nPort, int nProbes, int nTimeout, int nRetry);
        uint Scan(uint uIP, int nPort, int nProbes, int nTimeout, int nRegry, int nTotalTimeout);
        uint Scan(uint uIP, int nPort, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbes);
        uint Scan(string strIP, int nPort);
        uint Scan(string strIP, int nPort, int nProbes);
        uint Scan(string strIP, int nPort, int nProbes, int nTimeout);
        uint Scan(string strIP, int nPort, int nProbes, int nTimeout, int nRetry);
        uint Scan(string strIP, int nPort, int nProbes, int nTimeout, int nRetry, int nTotalTimeout);
        uint Scan(string strIP, int nPort, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbe);
        uint Scan(int nPort, EndPoint endPoint, int nProbes, int nTimeout, int nRetry, int nTotalTimeout, bool bUseNullProbe);
    }
}
