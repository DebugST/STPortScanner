using System;
using System.Collections.Generic;
using System.Text;

using System.IO;
using System.Text.RegularExpressions;

namespace ST.Library.Network
{
    public class ProbeConfiger
    {
        private static string m_strHead = @"# Create by -> Crystal_lz : {DATA}
# 正则99.99999%来自[nmap-service-probes]
# 删除该文件将运行时将自动生成初始文件
# 格式:
#   **[PROBE_S]**与**[PROBE_E]**之间为一个探测节点
#   PROBE_DATA  [TCP or UDP] {数据} -> 探测协议需要发送的数据包支持(\r,\n,\t,\0,\x??)
#   PROBE_PORTS [端口]              -> (默认:0)当探测到该端口开放时候 发送上面数据包 (可多个用[,] 支持[-]定义范围)
#   PROBE_INDEX [顺序]              -> (默认:0)当无法确认目标端口协议时优先尝试该探测节点的顺序 数字越小越先尝试探测 只能一个值
#   PROBE_REGEX [协议]       {正则} -> (该数据可以多行)从返回的数据包中匹配 若匹配成功返回协议作为显示 匹配顺序从上至下
#   非以上开头的行将被忽略
# 正则模式修正符号:
#   i -> 不区分大小写
#   g -> 全局匹配
#   m -> 若存在换行 将字符串视为多行 则$符号匹配每行的结束而非文本结束
#   s -> 将字符串视为单行 则.符号可匹配换行符
#   x -> 忽略空白
#   其他自行百度
# eg:
# **[PROBE_S]**
# PROBE_DATA  [TCP]  {GET / HTTP/1.1\r\n\r\n}
# PROBE_INDEX [1]
# PROBE_PORTS [80,443,8080,8888]
# PROBE_REGEX [http] {(?is)http/\d\.\d \d+}
# PROBE_REGEX [http] {(?i)\<html\>}
# **[PROBE_E]**";
        private Dictionary<int, List<ProbeInfo>> _ProbesDictionary;

        public Dictionary<int, List<ProbeInfo>> ProbesDictionary {
            get { return this._ProbesDictionary; }
        }

        private List<ProbeInfo> _AllProbes;

        public List<ProbeInfo> AllProbes {
            get { return _AllProbes; }
        }

        private Dictionary<int, string> _DefaultProtocol;

        public Dictionary<int, string> DefaultProtocol {
            get { return _DefaultProtocol; }
        }

        public object m_obj_sync = new object();

        public ProbeConfiger(string strConfigProbes, string strConfigDefault)
            : this(strConfigProbes, strConfigDefault, false) {

        }

        public ProbeConfiger(string strConfigProbes, string strConfigDefault, bool bNmapProbesConfig) {
            if (bNmapProbesConfig)
                this.LoadNmapProbeConfig(strConfigProbes);
            else
                this.LoadProbeConfig(strConfigProbes);
            this.LoadDefportsConfig(strConfigDefault);
        }

        public void LoadDefportsConfig(string strConfigDefault) {
            string[] strLines = strConfigDefault.Split('\n');
            Dictionary<int, string> dic = new Dictionary<int, string>();
            int nPort = 0;
            foreach (var v in strLines) {
                string strLine = v.Trim();
                if (strLine == string.Empty) continue;
                if (strLine[0] == '#') continue;
                string[] s = strLine.Split('\t');
                if (s.Length != 2) continue;
                nPort = int.Parse(s[0]);
                if (dic.ContainsKey(nPort)) continue;
                else dic.Add(nPort, s[1]);
            }
            lock (m_obj_sync) this._DefaultProtocol = dic;
        }

        public void LoadProbeConfig(string strConfigProbes) {
            string[] strLines = strConfigProbes.Split('\n');
            List<ProbeInfo> lst = new List<ProbeInfo>();
            ProbeInfo pi = null;
            char[] spliter = new char[] { ',', '-' };
            int nLine = 0;
            string strLine = string.Empty;
            try {
                foreach (var n in strLines) {
                    nLine++;
                    strLine = n.Trim();
                    if (strLine == string.Empty || strLine[0] == '#') continue;
                    if (strLine.StartsWith("**[PROBE_S]**")) {
                        pi = new ProbeInfo();
                    }
                    if (strLine.StartsWith("**[PROBE_E]**")) {
                        if (pi.Ports.Count == 0) pi.Ports.Add(0);
                        lst.Add(pi);
                        pi = null;
                    }
                    if (strLine.StartsWith("PROBE_DATA")) {
                        var m = Regex.Match(strLine, @"\[(.*?)\]\s*\{(.*)\}");
                        pi.IsTcp = m.Groups[1].Value.Trim().ToLower() == "tcp";
                        pi.Data = ProbeConfiger.StringToByte(m.Groups[2].Value);
                    } else if (strLine.StartsWith("PROBE_PORTS")) {
                        foreach (var v in Regex.Match(strLine, @"\[(.*)\]").Groups[1].Value.Trim().Trim(',').Split(',')) {
                            foreach (var p in v.Trim().Trim('-').Split('-'))
                                pi.Ports.Add(int.Parse(p));
                        }
                    } else if (strLine.StartsWith("PROBE_INDEX")) {
                        pi.Index = int.Parse(Regex.Match(strLine, @"\[(.*)\]").Groups[1].Value);
                    } else if (strLine.StartsWith("PROBE_REGEX")) {
                        Match mr = Regex.Match(strLine, @"\[(.*?)\]\s*\{(.*)\}");
                        ProbeInfo.RegexInfo ri = new ProbeInfo.RegexInfo();
                        if (mr.Groups[1].Value == string.Empty || mr.Groups[2].Value == string.Empty) throw new Exception();
                        ri.Name = mr.Groups[1].Value;
                        ri.RegLine = nLine;
                        ri.Regex = new Regex(mr.Groups[2].Value);
                        pi.RegexList.Add(ri);
                    }
                }
            } catch (ArgumentException ex) {
                throw new Exception("Load probes error on Line:" + nLine, ex);
            }
            int nLen = lst.Count;
            int nFlag = nLen;
            while (nFlag > 0) {
                nLen = nFlag;
                nFlag = 0;
                for (int i = 1; i < nLen; i++) {
                    if (lst[i - 1].Index > lst[i].Index) {
                        var temp = lst[i - 1];
                        lst[i - 1] = lst[i];
                        lst[i] = temp;
                    }
                }
            }
            Dictionary<int, List<ProbeInfo>> dic = new Dictionary<int, List<ProbeInfo>>();
            lst.ForEach(p => {
                foreach (var x in p.Ports) {
                    if (dic.ContainsKey(x)) dic[x].Add(p);
                    else {
                        List<ProbeInfo> l = new List<ProbeInfo>();
                        l.Add(p);
                        dic.Add(x, l);
                    }
                }
            });
            lock (m_obj_sync) {
                this._ProbesDictionary = dic;
                this._AllProbes = lst;
            }
        }

        public void LoadNmapProbeConfig(string strNmapProbesConfig) {
            this.LoadProbeConfig(ProbeConfiger.ConvertNmapProbe(strNmapProbesConfig));
        }

        public Queue<ProbeInfo> GetProbesQueue(ProbeType type, int nPort) { return this.GetProbesQueue(type, nPort, 0); }

        public Queue<ProbeInfo> GetProbesQueue(ProbeType type, int nPort, int nCount) {
            int nTimes = 0;
            Queue<ProbeInfo> que = new Queue<ProbeInfo>();
            Dictionary<int, List<ProbeInfo>> probesDic = this._ProbesDictionary;
            List<ProbeInfo> allProbes = this._AllProbes;
            if (probesDic.ContainsKey(nPort)) {
                foreach (var p in probesDic[nPort]) {
                    if (type == ProbeType.Tcp && !p.IsTcp) continue;
                    if (type == ProbeType.Udp && p.IsTcp) continue;
                    que.Enqueue(p);
                    if (nCount <= 0) continue;
                    if (++nTimes >= nCount) return que;
                }
            }
            if (nCount <= 0) return que;
            //while (nTimes < nCount) {
            foreach (var p in allProbes) {
                if (p.Ports.Contains(nPort)) continue;
                if (type == ProbeType.Tcp && !p.IsTcp) continue;
                if (type == ProbeType.Udp && p.IsTcp) continue;
                que.Enqueue(p);
                if (++nTimes >= nCount) break;
            }
            //}
            return que;
        }

        public MatchResult MatchData(byte[] byBuffer, int nLen, ProbeType type) {
            return this.MatchData(byBuffer, nLen, 0, type, null);
        }

        public MatchResult MatchData(byte[] byBuffer, int nLen, int nPort, ProbeType type) {
            return this.MatchData(byBuffer, nLen, nPort, type, null);
        }

        public MatchResult MatchData(byte[] byBuffer, int nLen, int nPort, ProbeType type, ProbeInfo probeInfo) {
            StringBuilder sb_m = new StringBuilder();
            StringBuilder sb_r = new StringBuilder();
            string strMatch = string.Empty;
            string strResult = string.Empty;
            for (int i = 0; i < nLen; i++) {
                sb_m.Append((char)byBuffer[i]);
                sb_r.Append(ProbeConfiger.ByteToChar(byBuffer[i]));
            }
            strMatch = sb_m.ToString();
            strResult = sb_r.ToString();

            var probesDic = this._ProbesDictionary;
            if (probeInfo != null) {
                foreach (var r in probeInfo.RegexList) {
                    if (r.Regex.IsMatch(strMatch)) return new MatchResult(r.Name, strResult, r.RegLine);
                }
            }
            HashSet<ProbeInfo> hs = new HashSet<ProbeInfo>();
            hs.Add(probeInfo);
            if (probesDic.ContainsKey(nPort)) {
                foreach (var p in probesDic[nPort]) {
                    if (!p.IsTcp) continue;
                    if (type == ProbeType.Tcp && !p.IsTcp) continue;
                    if (type == ProbeType.Udp && p.IsTcp) continue;
                    if (hs.Contains(p)) continue;
                    foreach (var r in p.RegexList) {
                        if (r.Regex.IsMatch(strMatch)) {
                            return new MatchResult(r.Name, strResult, r.RegLine);
                        }
                    }
                    hs.Add(p);
                }
            }
            var allProbes = this._AllProbes;
            foreach (var p in allProbes) {
                if (type == ProbeType.Tcp && !p.IsTcp) continue;
                if (type == ProbeType.Udp && p.IsTcp) continue;
                if (hs.Contains(p)) continue;
                foreach (var r in p.RegexList) {
                    if (r.Regex.IsMatch(strMatch)) {
                        return new MatchResult(r.Name, strResult, r.RegLine);
                    }
                }
            }
            return new MatchResult(null, strResult, 0);
        }
        //=====================================================================
        public static string ConvertNmapProbe(string strNmapProbesConfig) {
            string strData = DateTime.Now.ToString("yyyy-MM-dd");
            strNmapProbesConfig = strNmapProbesConfig.Replace("##############################NEXT PROBE##############################", "");
            strNmapProbesConfig = Regex.Replace(strNmapProbesConfig, @"Probe TCP NULL q\|\|", "##############################NEXT PROBE##############################\r\n**[PROBE_S]**\r\nPROBE_DATA     [TCP]    {}");
            strNmapProbesConfig = Regex.Replace(strNmapProbesConfig, @"^(\w*?match) (.*?) m(.)(.*?)\3.*?$", "PROBE_REGEX    [$2]    {(?is)$4}", RegexOptions.Multiline);
            strNmapProbesConfig = Regex.Replace(strNmapProbesConfig, @"^\s*Probe (\w+).*?q\|(.*?)\|", "**[PROBE_E]**\r\n##############################NEXT PROBE##############################\r\n**[PROBE_S]**\r\nPROBE_DATA     [$1]    {$2}", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            strNmapProbesConfig = Regex.Replace(strNmapProbesConfig, @"^\s*rarity\s*?(\d+)", "PROBE_INDEX    [$1]", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            strNmapProbesConfig = Regex.Replace(strNmapProbesConfig, @"^\s*ports\s*([\d,\-]*)", "PROBE_PORTS    [$1]", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            strNmapProbesConfig = Regex.Replace(strNmapProbesConfig, @"^\s*sslports\s*([\d,\-]*)", "PROBE_PORTS    [$1]", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            return m_strHead.Replace("{DATA}", strData) + "\r\n" + strNmapProbesConfig + "\r\n**[PROBE_E]**\r\n#Convert from [nmap-service-probes] by Crystal_lz " + strData;
        }

        private static string ByteToChar(byte by) {
            if (by == 0) return "\\0";
            if (by == '\\') return "\\\\";
            if (by == '\r') return "\r";//"\\r"
            if (by == '\n') return "\n";//"\\n"
            if (by == '\t') return "\t";//"\\t"
            if (by == '\a') return "\\a";
            if (by == '\b') return "\\b";
            if (by == '\v') return "\\v";
            if (by == '\f') return "\\f";
            if (by >= 32 && by <= 126) return ((char)by).ToString();
            return "\\x" + by.ToString("X2");
        }

        public static byte[] StringToByte(string strText) {
            List<byte> lst = new List<byte>();
            bool bStart = false;
            int nInex = 0, nLen = strText.Length;
            while (nInex < nLen) {
                if (strText[nInex] == '\\' && !bStart)
                    bStart = true;
                else {
                    if (!bStart) lst.Add((byte)strText[nInex]);
                    else {
                        switch (strText[nInex]) {
                            case '0': lst.Add(0); break;
                            case 'r': lst.Add((byte)'\r'); break;
                            case 'n': lst.Add((byte)'\n'); break;
                            case 't': lst.Add((byte)'\t'); break;
                            case 'a': lst.Add((byte)'\a'); break;
                            case 'b': lst.Add((byte)'\b'); break;
                            case 'v': lst.Add((byte)'\v'); break;
                            case 'f': lst.Add((byte)'\f'); break;
                            case '\\': lst.Add((byte)'\\'); break;
                            case 'x':
                                lst.Add((byte)Convert.ToByte(strText.Substring(nInex + 1, 2), 16));
                                nInex += 2;
                                break;
                            default:
                                lst.Add((byte)strText[nInex]);
                                break;
                        }
                        bStart = false;
                    }
                }
                nInex++;
            }
            return lst.ToArray();
            //strText = strText.Replace("\\0", "\0")
            //    .Replace("\\r", "\r")
            //    .Replace("\\n", "\n")
            //    .Replace("\\t", "\t")
            //    .Replace("\\a", "\a")
            //    .Replace("\\b", "\b")
            //    .Replace("\\v", "\v")
            //    .Replace("\\f", "\f");
            //Match m = null;
            //while ((m = Regex.Match(strText, @"\\x(..)", RegexOptions.IgnoreCase)).Success) {
            //    strText = strText.Replace(m.Value, ((char)Convert.ToByte(m.Groups[1].Value, 16)).ToString());
            //}
            //byte[] ret = new byte[strText.Length];
            //for (int i = 0; i < ret.Length; i++) {
            //    ret[i] = (byte)strText[i];
            //}
            //return ret;
        }
    }
    /// <summary>
    /// 存放配置文件中探测项的类
    /// </summary>
    public class ProbeInfo
    {
        private HashSet<int> _Ports;
        /// <summary>
        /// 该数探测项包含端口列表集合 即那些端口适用发送该探测项
        /// </summary>
        //[Description("该数探测项包含端口列表集合 即那些端口适用发送该探测项")]
        public HashSet<int> Ports {
            get {
                if (_Ports == null) _Ports = new HashSet<int>();
                return _Ports;
            }
        }

        private bool _IsTcp;
        /// <summary>
        /// 该探测项是否是用于探测TCP协议
        /// </summary>
        //[Description("该探测项是否是用于探测TCP协议")]
        public bool IsTcp {
            get { return _IsTcp; }
            set { _IsTcp = value; }
        }

        private int _Index = int.MaxValue;
        /// <summary>
        /// 该探测项优先级
        /// </summary>
        //[Description("该探测项优先级")]
        public int Index {
            get { return _Index; }
            set { _Index = value; }
        }

        private byte[] _Data;
        /// <summary>
        /// 该探测项需要发送是数据包列表
        /// </summary>
        //[Description("该探测项需要发送是数据包列表")]
        public byte[] Data {
            get { return _Data; }
            set { _Data = value; }
        }

        private List<RegexInfo> _RegexList;
        /// <summary>
        /// 匹配banner正则列表
        /// </summary>
        public List<RegexInfo> RegexList {
            get {
                if (_RegexList == null) _RegexList = new List<RegexInfo>();
                return _RegexList;
            }
        }

        public struct RegexInfo
        {
            /// <summary>
            /// 该正则位于配置文件中第几行
            /// </summary>
            public int RegLine;
            /// <summary>
            /// 该正则规则名 即匹配成功后协议名称
            /// </summary>
            public string Name;
            /// <summary>
            /// 正则
            /// </summary>
            public Regex Regex;
        }
    }

    public struct MatchResult
    {
        private string _Name;

        public string Name {
            get { return _Name; }
        }

        private string _DataString;

        public string DataString {
            get { return _DataString; }
        }

        private int _RegexLine;

        public int RegexLine {
            get { return _RegexLine; }
        }

        public MatchResult(string strName, string strDataString, int nRegexLine) {
            this._Name = strName;
            this._DataString = strDataString;
            this._RegexLine = nRegexLine;
        }
    }

    public enum ProbeType
    {
        Tcp,
        Udp,
        All
    }
}
