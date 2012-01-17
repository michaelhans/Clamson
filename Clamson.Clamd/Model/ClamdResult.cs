using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Clamson.Clamd.Model
{
    /// <summary>
    /// Clamd Command Result
    /// </summary>
    /// <remarks>Used for results that are file/signature based (Unlike PONG or Bool based)</remarks>    
    public class ClamdResult
    {        
        /// <summary>
        /// Did the Requst have a Virus
        /// </summary>
        public bool HasVirus { get; private set; }

        /// <summary>
        /// List of Infected File(s)/Signatures
        /// </summary>
        public List<InfectedFile> InfectedFiles { get; set; }

        /// <summary>
        /// ClamdResult CTOR
        /// </summary>
        /// <param name="infectedFiles">List of Infected File(s)/Signatures (if any,else blank list)</param>
        public ClamdResult(List<InfectedFile> infectedFiles)
        {
            this.InfectedFiles = infectedFiles;
            if (infectedFiles != null & infectedFiles.Count > 0)
                HasVirus = true;
            else
                HasVirus = false;
        }
    }
}
