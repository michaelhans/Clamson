using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Clamson.Clamd.Model
{
    /// <summary>
    /// Infected File POCO
    /// </summary>    
    public class InfectedFile
    {
        /// <summary>
        /// Infected File Name or Stream
        /// </summary>
        public string FileName { get; private set; }

        /// <summary>
        /// Virus Signature
        /// </summary>
        public string VirusName { get; private set; }

        /// <summary>
        /// InfectedFile CTOR
        /// </summary>
        /// <param name="file">Infected File Name or Stream</param>
        /// <param name="virus">Virus Signature</param>
        public InfectedFile(string file, string virus)
        {
            this.FileName = file;
            this.VirusName = virus;
        }        
    }
}
