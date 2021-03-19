using System;
using System.Collections.Generic;
using System.Text;

using System.Net;

namespace ST.Library.Network
{
  public class ScanEventArgs : EventArgs
    {
        private uint _TaskID;

        public uint TaskID {
            get { return _TaskID; }
            internal set { _TaskID = value; }
        }

        private bool _CanConnect;

        public bool CanConnect {
            get { return _CanConnect; }
        }

        private EndPoint  _EndPoint;

        public EndPoint EndPoint {
            get { return _EndPoint; }
        }

        private string _Protocol;

        public string Protocol {
            get { return _Protocol; }
        }

        private int _RegexLine;

        public int RegexLine {
            get { return _RegexLine; }
        }

        private string _Banner;
        /// <summary>
        /// banner信息
        /// </summary>
        public string Banner {
            get { return _Banner; }
        }

        private byte[] _Data;

        public byte[] Data {
            get { return _Data; }
        }

        private int _Length;

        public int Length {
            get { return _Length; }
        }

        private string _ErrorMessage;
        /// <summary>
        /// 连接过程中最后一次错误信息
        /// </summary>
        public string ErrorMessage {
            get { return _ErrorMessage; }
        }

        public ScanEventArgs(uint uid, EndPoint endPoint, string strError) {
            this._TaskID = uid;
            this._EndPoint = endPoint;
            this._ErrorMessage = strError;
            this._CanConnect = false;
        }

        public ScanEventArgs(uint uid, EndPoint endPoint, bool bCanConnect, string strError) {
            this._TaskID = uid;
            this._CanConnect = bCanConnect;
            this._ErrorMessage = strError;
            this._EndPoint = endPoint;
        }

        public ScanEventArgs(uint uid, EndPoint endPoint, string strPro, int nRegexLine, string strBanner, byte[] byData, int nLen) {
            this._TaskID = uid;
            this._EndPoint = endPoint;
            this._Protocol = strPro;
            this._RegexLine = nRegexLine;
            this._Banner = strBanner;
            this._Data = byData;
            this._Length = nLen;
            this._CanConnect = true;
        }
    }
}
