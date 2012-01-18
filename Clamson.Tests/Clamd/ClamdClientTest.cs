using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using NUnit.Framework;
using Clamson.Clamd;
using Clamson.Clamd.Model;

namespace Clamson.Tests.Clamd
{
    /// <summary>
    /// Integration tests to validate Clamd client public methods. 
    ///   
    /// These tests rely on a pre-defined directory structure with EICAR signatures 
    /// in them (or lack of for clean scan results). I’ve removed the ability of this 
    /// test to create these files/directories after several negative comments on this 
    /// being frowned upon in their environments. Simply put, you need to make them. 
    /// See the remarks for structure.          
    /// </summary>
    /// <remarks>
    /// Steps for creating Integration test structure
    /// 1) Determine a base directory
    /// 2) Create 2 sub directories called clean & infected
    /// 3) Create 1 file in the clean called clean.txt (fill it with random text or leave blank).
    /// 4) Create 2 files called infected_eicar_1.txt & infected_eicar_2.txt both containing
    ///    the EICAR test signature (look at the EICAR website OR copy from method 'Instream_EICAR_Signature')
    /// 5) Set the private variable baseTestDir to the base directory you created in step 1.    
    /// 
    /// Intergration Test Tree (baseTestDir)
    /// ├───clean
    /// │       clean.txt
    /// │
    /// └───infected
    ///         infected_eicar_1.txt
    ///         infected_eicar_2.txt 
    /// </remarks>      
    /// <author>Michael Hans</author>
    [TestFixture]
    [Category("Integration")]
    class ClamdClientTests
    {
        //Change these to fit your setup
        private string baseTestDir = @"C:\clamson_tests";
        private string clamdServer = "127.0.0.1";
        private int clamdPort = 3310;

        private ClamdClient clamd;
        private string cleanScanDirectory;
        private string infectedScanDirectory;

        [SetUp]
        public void SetupTests()
        {
            //Setup ClamdClient
            clamd = new ClamdClient(clamdServer, clamdPort);

            //Setup Scan Directories
            cleanScanDirectory = string.Format("{0}{1}clean{1}", baseTestDir, Path.DirectorySeparatorChar);
            infectedScanDirectory = string.Format("{0}{1}infected{1}", baseTestDir, Path.DirectorySeparatorChar);
        }

        [Test]
        public void Ping_Success()
        {
            var result = clamd.Ping();
            Assert.IsTrue(result);
        }

        [Test]
        public void Ping_Connection_Refused_Fail()
        {
            ClamdClient failClamd = new ClamdClient("NO-SERVER", 3310);
            var result = failClamd.Ping();
            Assert.IsFalse(result);
        }

        [Test]
        public void Instream_EICAR_Signature()
        {
            string eicar_signature = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            byte[] eicar_bytes = ASCIIEncoding.ASCII.GetBytes(eicar_signature);
            MemoryStream memStream = new MemoryStream(eicar_bytes);
            
            var result = clamd.Instream(memStream);

            Assert.IsTrue(result.HasVirus);
            Assert.IsNotEmpty(result.InfectedFiles);            
        }

        [Test]
        public void Instream_Success()
        {
            string eicar_signature = @"London Elektricity played while these tests were written";
            byte[] eicar_bytes = ASCIIEncoding.ASCII.GetBytes(eicar_signature);
            MemoryStream memStream = new MemoryStream(eicar_bytes);
            
            var result = clamd.Instream(memStream);

            Assert.IsFalse(result.HasVirus);
            Assert.IsEmpty(result.InfectedFiles); 
        }

        [Test]
        public void Version_Success()
        {
            var result = string.Empty;
            result = clamd.Version();
            Assert.IsNotNullOrEmpty(result);
        }

        [Test]
        public void Reload_Success()
        {
            var result = clamd.Reload();
            Assert.IsTrue(result);
        }

        [Test]
        public void Stats_Success()
        {
            var result = string.Empty;
            result = clamd.Stats();
            Assert.IsNotNullOrEmpty(result);
        }

        [Test]
        public void Scan_Directory_Clean()
        {            
            var result = clamd.Scan(cleanScanDirectory);

            Assert.IsFalse(result.HasVirus);
            Assert.IsEmpty(result.InfectedFiles);
        }

        [Test]
        public void Scan_File_Clean()
        {
            var cleanFileName = string.Format("{0}clean.txt", cleanScanDirectory);            
            var result = clamd.Scan(cleanFileName);

            Assert.IsFalse(result.HasVirus);
            Assert.IsEmpty(result.InfectedFiles);
        }

        [Test]
        public void Scan_Directory_Infected()
        {            
            var result = clamd.Scan(infectedScanDirectory);

            Assert.IsTrue(result.HasVirus);
            Assert.IsNotEmpty(result.InfectedFiles);
        }

        [Test]
        public void Scan_File_Infected()
        {
            var infectedFileName = string.Format("{0}infected_eicar_1.txt", infectedScanDirectory);            
            var result = clamd.Scan(infectedFileName);

            Assert.IsTrue(result.HasVirus);
            Assert.IsNotEmpty(result.InfectedFiles);
        }

        [Test]
        public void ContScan_Directory_Clean()
        {            
            var result = clamd.ContScan(cleanScanDirectory);

            Assert.IsFalse(result.HasVirus);
            Assert.AreEqual(0, result.InfectedFiles.Count);
        }

        [Test]
        public void ContScan_Directory_Infected()
        {            
            var result = clamd.ContScan(infectedScanDirectory);

            Assert.IsTrue(result.HasVirus);
            Assert.AreEqual(2, result.InfectedFiles.Count);
        }

        [Test]
        public void MultiScan_Directory_Clean()
        {            
            var result = clamd.MultiScan(cleanScanDirectory);

            Assert.IsFalse(result.HasVirus);
            Assert.AreEqual(0, result.InfectedFiles.Count);
        }

        [Test]
        public void MultiScan_Directory_Infected()
        {            
            var result = clamd.MultiScan(infectedScanDirectory);

            Assert.IsTrue(result.HasVirus);
            Assert.AreEqual(2, result.InfectedFiles.Count);
        }


        //[Test]
        //public void Shutdown_Success()
        //{
        //    clamd.Shutdown();
        //}
    }
}