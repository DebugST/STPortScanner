using System;
using System.Collections.Generic;
using System.Text;

using System.Runtime.InteropServices;

namespace ST.Library.Network
{
    internal class RAWDefine
    {
        public static byte PROTO_TCP = 0x06;
        public static byte PROTO_ICMP = 0x01;
        private static Random m_rnd = new Random();
        private static Dictionary<string, byte> m_dic_ip;

        static RAWDefine() {
            m_dic_ip = new Dictionary<string, byte>();
            for (int i = 0; i < 256; i++) m_dic_ip.Add(i.ToString(), (byte)i);
        }

        private static byte[] m_bySyn = new byte[]{
            //IP协议头
            0x45                    //IP版本号码4 首部长度5(5个32Bit 20字节)
            ,0x00                   //TOS服务类型
            ,0x00,0x28              //数据总长度 40字节
            ,0x01,0x00              //标识
            ,0x00,0x00              //3位标志+13位片偏移
            ,0x80                   //ttl = 128
            ,0x06                   //使用TCP协议
            ,0xb5,0x10              //数据校验和
            ,0xc0,0xa8,0x00,0x77    //来源端口 192.168.0.119
            ,0x08,0x08,0x08,0x08    //目标端口 8.8.8.8
            //TCP协议头
            ,0x05,0xa5              //来源端口 1445
            ,0x00,0x35              //目标端口 53
            ,0x92,0x67,0x39,0x08    //seq顺序号
            ,0x00,0x00,0x00,0x00    //ack确认号
            ,0x50                   //首部长度5(5个32Bit 28字节)
            ,0x02                   //SYN
            ,0x20,0x00              //窗口大小
            ,0xe5,0xb5              //检验和
            ,0x00,0x00              //紧急指针
        };
        private static byte[] m_byPsd = new byte[]{
            0x00,0x00,0x00,0x00,    //sip
            0x00,0x00,0x00,0x00,    //dip
            0x00,
            0x06,                   //tcp
            0x00,0x14               //len
        };
        private static byte[] m_byTemp = new byte[32];
        //字节反转
        public static ushort Reverse(ushort num) {
            return (ushort)((num << 8) | (num >> 8));
        }
        //反转字节
        public static int Reverse(int num) {
            int temp = (num << 24);
            temp |= (num << 8) & 0x00FF0000;
            temp |= (num >> 8) & 0x0000FF00;
            temp |= (num >> 24) & 0x000000FF;
            return temp;
        }

        public static uint IPToINT(string strIP) {
            return RAWDefine.IPToINT(strIP, false);
        }

        public static uint IPToINT(string strIP, bool bBig) {
            uint num = 0;
            string[] strs = strIP.Split('.');
            if (!bBig) {
                num = m_dic_ip[strs[3]];
                num <<= 8;
                num |= m_dic_ip[strs[2]];
                num <<= 8;
                num |= m_dic_ip[strs[1]];
                num <<= 8;
                num |= m_dic_ip[strs[0]];
            } else {
                num = m_dic_ip[strs[0]];
                num <<= 8;
                num |= m_dic_ip[strs[1]];
                num <<= 8;
                num |= m_dic_ip[strs[2]];
                num <<= 8;
                num |= m_dic_ip[strs[3]];
            }
            return num;
        }

        public static ushort CheckSum(byte[] byData, int size) {
            ulong cksum = 0;
            int index = 0;
            while (size > 1) {
                cksum += BitConverter.ToUInt16(byData, index);
                index += 2;
                size -= 2;
            }
            if (size == 1) {
                cksum += byData[index];
            }
            cksum = (cksum >> 16) + (cksum & 0xFFFF);
            cksum += (cksum >> 16);
            return (ushort)(~cksum);
        }

        public static byte[] GetSynPacket(string strSIP, string strDIP, ushort usSPort, ushort usDPort) {
            return RAWDefine.GetSynPacket(RAWDefine.IPToINT(strSIP), RAWDefine.IPToINT(strDIP), usSPort, usDPort);
        }

        public static byte[] GetSyncPacket(string strSIP, string strDIP, ushort usSPort, ushort usDPort, uint uSeq) {
            return RAWDefine.GetSynPacket(RAWDefine.IPToINT(strSIP), RAWDefine.IPToINT(strDIP), usSPort, usDPort, uSeq);
        }
        public static byte[] GetSynPacket(uint uSIP, uint uDIP, ushort usSPort, ushort usDPort) {
            uint uSeq = 0;
            lock (m_rnd) uSeq = (uint)m_rnd.Next();
            return GetSynPacket(uSIP, uDIP, usSPort, usDPort, uSeq);
        }

        public static byte[] GetSynPacket(uint uSIP, uint uDIP, ushort usSPort, ushort usDPort, uint uSeq) {
            byte[] byRet = new byte[m_bySyn.Length];
            RAWDefine.GetSynPacket(byRet, uSIP, uDIP, usSPort, usDPort, uSeq);
            return byRet;
        }


        public static uint GetSynPacket(byte[] byBuffer, string strSIP, string strDIP, ushort usSPort, ushort usDPort) {
            uint uSeq = 0;
            lock (m_rnd) uSeq = (uint)m_rnd.Next();
            return RAWDefine.GetSynPacket(byBuffer, RAWDefine.IPToINT(strSIP), RAWDefine.IPToINT(strDIP), usSPort, usDPort, uSeq);
        }

        public static uint GetSynPacket(byte[] byBuffer, string strSIP, string strDIP, ushort usSPort, ushort usDPort, uint uSeq) {
            return RAWDefine.GetSynPacket(byBuffer, RAWDefine.IPToINT(strSIP), RAWDefine.IPToINT(strDIP), usSPort, usDPort, uSeq);
        }

        public static uint GetSynPacket(byte[] byBuffer, uint uSIP, uint uDIP, ushort usSPort, ushort usDPort) {
            uint uSeq = 0;
            lock (m_rnd) uSeq = (uint)m_rnd.Next();
            return RAWDefine.GetSynPacket(byBuffer, uSIP, uDIP, usSPort, usDPort, uSeq);
        }

        public static uint GetSynPacket(byte[] byBuffer, uint uSIP, uint uDIP, ushort usSPort, ushort usDPort, uint uSeq) {
            Array.Copy(m_bySyn, byBuffer, m_bySyn.Length);
            uint useq = RAWDefine.SetSynData(byBuffer, uSIP, uDIP, usSPort, usDPort, uSeq);
            RAWDefine.CheckSum(byBuffer);
            return useq;
        }

        private static uint SetSynData(byte[] bySyn, uint uSIP, uint uDIP, ushort usSPort, ushort usDPort, uint uSeq) {
            bySyn[10] = bySyn[11] = 0;//ip_sum
            bySyn[12] = (byte)uSIP;
            bySyn[13] = (byte)(uSIP >> 8);
            bySyn[14] = (byte)(uSIP >> 16);
            bySyn[15] = (byte)(uSIP >> 24);
            bySyn[16] = (byte)uDIP;
            bySyn[17] = (byte)(uDIP >> 8);
            bySyn[18] = (byte)(uDIP >> 16);
            bySyn[19] = (byte)(uDIP >> 24);

            bySyn[20] = (byte)(usSPort >> 8);
            bySyn[21] = (byte)(usSPort);
            bySyn[22] = (byte)(usDPort >> 8);
            bySyn[23] = (byte)(usDPort);

            bySyn[24] = (byte)(uSeq >> 24);
            bySyn[25] = (byte)(uSeq >> 16);
            bySyn[26] = (byte)(uSeq >> 8);
            bySyn[27] = (byte)uSeq;

            bySyn[36] = bySyn[37] = 0;//tcp_sum
            //Console.WriteLine("seq - " + useq.ToString("X"));
            return uSeq;
        }

        public static uint GetACKNumber(byte[] bySyn, int nOffset) {
            uint uack = 0;
            if (nOffset < 20 || nOffset > bySyn.Length - 20) return 0;
            uack = bySyn[nOffset + 8];
            uack <<= 8;
            uack |= bySyn[nOffset + 9];
            uack <<= 8;
            uack |= bySyn[nOffset + 10];
            uack <<= 8;
            uack |= bySyn[nOffset + 11];
            return uack;
        }

        private static void CheckSum(byte[] bySyn) {
            lock (m_byPsd) {
                m_byPsd[0] = bySyn[12];
                m_byPsd[1] = bySyn[13];
                m_byPsd[2] = bySyn[14];
                m_byPsd[3] = bySyn[15];
                m_byPsd[4] = bySyn[16];
                m_byPsd[5] = bySyn[17];
                m_byPsd[6] = bySyn[18];
                m_byPsd[7] = bySyn[19];

                Array.Copy(m_byPsd, m_byTemp, 12);
                Array.Copy(bySyn, 20, m_byTemp, 12, 20);
                ushort usSum = RAWDefine.CheckSum(m_byTemp, m_byTemp.Length);
                bySyn[36] = (byte)(usSum);
                bySyn[37] = (byte)(usSum >> 8);
                usSum = RAWDefine.CheckSum(bySyn, 20);
                bySyn[10] = (byte)(usSum);
                bySyn[11] = (byte)(usSum >> 8);
            }
        }
    }
}
