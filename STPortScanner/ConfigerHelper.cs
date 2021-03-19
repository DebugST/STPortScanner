using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.IO;
using System.IO.Compression;

namespace STPortScanner
{
    public class ConfigerHelper
    {
        public static byte[] Compress(byte[] byData) {
            using (MemoryStream ms = new MemoryStream()) {
                using (GZipStream gs = new GZipStream(ms, CompressionMode.Compress)) {
                    gs.Write(byData, 0, byData.Length);
                }
                return ms.ToArray();
            }
        }

        public static byte[] DeCompress(byte[] byData) {
            int nLen = 0;
            byte[] byTemp = new byte[1024];
            using (MemoryStream ms_new = new MemoryStream()) {
                using (MemoryStream ms = new MemoryStream(byData)) {
                    using (GZipStream gs = new GZipStream(ms, CompressionMode.Decompress)) {
                        while ((nLen = gs.Read(byTemp, 0, byTemp.Length)) > 0) {
                            ms_new.Write(byTemp, 0, nLen);
                        }
                    }
                }
                return ms_new.ToArray();
            }
        }

        public static void CreateConfigFile(string strFileName,bool bProbes) {
            using (FileStream fs = new FileStream(strFileName, FileMode.Create)) {
                byte[] byData = null;
                if (bProbes)
                    byData = ConfigerHelper.DeCompress(Properties.Resources.probes_compress);
                else
                    byData = ConfigerHelper.DeCompress(Properties.Resources.defports_compress);
                fs.Write(byData, 0, byData.Length);
            }
        }
    }
}
