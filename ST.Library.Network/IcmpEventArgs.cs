using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Net;

namespace ST.Library.Network
{
    public class IcmpEventArgs : EventArgs
    {
        private uint _ID;

        private uint ID {
            get { return _ID; }
        }

        private IPAddress _IPAddress;

        public IPAddress IPAddress {
            get { return _IPAddress; }
        }

        private int _TTL;

        public int TTL {
            get { return _TTL; }
        }

        private bool _CanAccess;

        public bool CanAccess {
            get { return _CanAccess; }
        }

        private double _Times;

        public double Times {
            get { return _Times; }
        }

        private int _Retryed;

        public int Retryed {
            get { return _Retryed; }
        }

        public IcmpEventArgs(uint uID, IPAddress ipAddr, int nRetryed) 
            : this(uID, ipAddr, 0, false, 0, nRetryed) { }

        public IcmpEventArgs(uint uID, IPAddress ipAddr, int nTTL, bool canAccess, double nTimes, int nRetryed) {
            this._ID = uID;
            this._IPAddress = ipAddr;
            this._TTL = nTTL;
            this._CanAccess = canAccess;
            this._Times = nTimes;
            this._Retryed = nRetryed;
        }
    }
}
