using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Clamson.Clamd.Model;


namespace Clamson.Clamd
{
    /// <summary>
    /// Clamd Tcp Wrapper Client
    /// </summary>    
    /// <remarks>
    /// Written insanely quick for new web property... ymmv
    /// Commands taken from command enum in session.h in ClamAV/clamd source.   
    /// </remarks>
    /// <author>Michael Hans</author>
    public class ClamdClient
    {
        #region Properties & Command Helper
        /// <summary>
        /// Stream Chunk Size in Bytes
        /// </summary>
        public Int32 ChunkSize { get; private set; }

        /// <summary>
        /// Clamd Server Port
        /// </summary>
        public Int32 Port { get; private set; }

        /// <summary>
        /// Clamd Server
        /// </summary>
        public string Server { get; private set; }

        /// <summary>
        /// Clamd Supported Commands
        /// </summary>
        internal static class ClamdCommand
        {
            public const string PING = "zPING\0";
            public const string VERSION = "zVERSION\0";
            public const string RELOAD = "zRELOAD\0";
            public const string SHUTDOWN = "zSHUTDOWN\0";
            public const string INSTREAM = "zINSTREAM\0";
            public const string STATS = "zSTATS\0";
            //Formatted Commands
            public const string SCAN = "zSCAN";
            public const string CONTSCAN = "zCONTSCAN";
            public const string MULTISCAN = "zMULTISCAN";
        }
        #endregion

        #region Constructors

        /// <summary>
        /// Clamd CTOR
        /// </summary>
        /// <param name="server">Clamd Server</param>
        /// <param name="port">Clamd Server Port</param>
        /// <remarks>Defaults Chunk Size to 1024</remarks>
        public ClamdClient(string server, Int32 port) : this(server, port, 1024) { }

        /// <summary>
        /// Clamd CTOR
        /// </summary>
        /// <param name="server">Clamd Server</param>
        /// <param name="port">Clamd Server Port</param>
        /// <param name="chunkSize">Stream Chunk Size in Bytes</param>
        public ClamdClient(string server, Int32 port, Int32 chunkSize)
        {
            this.Port = port;
            this.Server = server;
            this.ChunkSize = chunkSize;
        }
        #endregion            

        #region Commands
        /// <summary>
        /// Ping Clamd Daemon
        /// </summary>
        /// <returns>Whether "PONG" response was received</returns>
        public bool Ping()
        {
            //HACK: Need to refactor all method results to include IsSuccess for clamd failures
            try
            {
                var commandResult = ExecuteCommand(ClamdCommand.PING);
                if (ExecuteCommand(ClamdCommand.PING) == "PONG\0")
                    return true;
                else
                    return false;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        /// <summary>
        /// Return ClamAV & Databaes Version
        /// </summary>
        /// <returns>ClamAV & Databaes Version</returns>
        public string Version()
        {
            return ExecuteCommand(ClamdCommand.VERSION);
        }

        /// <summary>
        /// Reload the signature database
        /// </summary>
        /// <returns>Whether database was successfully reloaded</returns>
        public bool Reload()
        {            
            if (ExecuteCommand(ClamdCommand.RELOAD) == "RELOADING\0")
                return true;
            else
                return false;                
        }

        /// <summary>
        /// Shutdown Clamd
        /// </summary>
        public void Shutdown()
        {
            ExecuteCommand(ClamdCommand.SHUTDOWN);
        }
        
        /// <summary>
        /// Scan a file or Directory for Virus Signatures
        /// </summary>
        /// <param name="path">File or Path to Scan</param>
        /// <returns>Clamd Command Result (File/Signatures)</returns>
        /// <remarks>Stops scanning on virus found</remarks>
        public ClamdResult Scan(string path)
        {
            var command = string.Format("{0} {1}\0", ClamdCommand.SCAN, path);
            var response = ExecuteCommand(command);
            var files = ParseFileResponse(response);
            
            return new ClamdResult(files);
        }

        /// <summary>
        /// Scan a Stream for Virus Signatures
        /// </summary>
        /// <param name="data">Stream to Scan</param>
        /// <returns>Clamd Command Result (File/Signatures)</returns>
        public ClamdResult Instream(Stream data)
        {
            var response = ExecuteCommand(ClamdCommand.INSTREAM, data);
            var files = ParseFileResponse(response);

            return new ClamdResult(files);
        }

        /// <summary>
        /// Scan a file or directory for Virus Signatures. Continue on when 
        /// virus found.
        /// </summary>
        /// <param name="path">File or Path to Scan</param>
        /// <returns>Clamd Command Result (File/Signatures)</returns>    
        public ClamdResult ContScan(string path)
        {
            var command = string.Format("{0} {1}\0", ClamdCommand.CONTSCAN, path);
            var response = ExecuteCommand(command);
            var files = ParseFileResponse(response);

            return new ClamdResult(files);
        }

        /// <summary>
        /// Scan a file or directory using multiple threads.
        /// </summary>
        /// <param name="path">File or Path to Scan</param>
        /// <returns>Clamd Command Result (File/Signatures)</returns>        
        public ClamdResult MultiScan(string path)
        {
            var command = string.Format("{0} {1}\0", ClamdCommand.MULTISCAN, path);
            var response = ExecuteCommand(command);
            var files = ParseFileResponse(response);

            return new ClamdResult(files);
        }

        /// <summary>
        /// Return Clamd statistics
        /// </summary>
        /// <returns>Clamd contents of scan queue and memory statistics</returns>
        public string Stats()
        {
            return ExecuteCommand(ClamdCommand.STATS);
        }

        /// <summary>
        /// Not Implemented
        /// </summary>
        /// <remarks></remarks>
        //public void IDSession() { throw new NotImplementedException(); }
        #endregion

        #region Network & File Processing

        /// <summary>
        /// Parse a Clam Response for File/Signatures
        /// </summary>
        /// <param name="resp">Clamd Response</param>
        /// <returns>List of Infected Files/Signatures (if any)</returns>
        private List<InfectedFile> ParseFileResponse(string resp)
        {
            var returnItems = new List<InfectedFile>();
            foreach (string respItem in resp.Split(new string[] { "\0" }, StringSplitOptions.RemoveEmptyEntries))
            {
                //Split Item {0} File Name : {1} Status OR Virus Signature
                var itemSplit = respItem.Split(new string[] { ": " }, StringSplitOptions.RemoveEmptyEntries);
                if (itemSplit[1].Contains("FOUND"))
                    returnItems.Add(new InfectedFile(itemSplit[0],itemSplit[1]));                    
                else if (!itemSplit[1].Contains("OK")) //if it's not OK or FOUND throw Error
                    throw new Exception("Clamd Response Not Recognized");
            }
            return returnItems;
        }

        /// <summary>
        /// Execute Clamd Command & Return String Response
        /// </summary>
        /// <param name="command">Clamd Command (ClamdCommand.)</param>
        /// <returns>Clamd String Response</returns>
        private string ExecuteCommand(string command)
        {
            return ExecuteCommand(command, null);
        }

        /// <summary>
        /// Execute Clamd Command & Return String Response
        /// </summary>
        /// <param name="command">Clamd Command (ClamdCommand.)</param>
        /// <param name="data">Stream for Instream Scan</param>
        /// <returns>Clamd String Response</returns>
        private string ExecuteCommand(string command, Stream data)
        {            
            TcpClient client = new TcpClient(Server, Port);
            NetworkStream stream = client.GetStream();
            
            //Send Clamd Command
            stream.Write(ASCIIEncoding.ASCII.GetBytes(command), 0, command.Length);

            //Chunk & Send Stream Data (if any)
            if (data != null)
            {
                int dataIndex = 0;
                int workChunkSize = ChunkSize;
                byte[] chunkBytesLen = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(workChunkSize));

                while (stream.CanWrite && dataIndex < data.Length)
                {
                    if (dataIndex + workChunkSize >= data.Length)
                    {
                        workChunkSize = (int)data.Length - dataIndex;
                        chunkBytesLen = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(workChunkSize));
                    }

                    var fileBytes = new byte[workChunkSize];
                    data.Read(fileBytes, 0, workChunkSize);
                          
                    stream.Write(chunkBytesLen, 0, chunkBytesLen.Length);                    
                    stream.Write(fileBytes, 0, workChunkSize);                    
                    dataIndex += workChunkSize;
                }

                byte[] nullByte = BitConverter.GetBytes(0);
                stream.Write(nullByte, 0, nullByte.Length);
            }

            //Retrieve Response
            StringBuilder respBuilder = new StringBuilder();
            byte[] respBytes = new Byte[256];
            int bytes;
            while ((bytes = stream.Read(respBytes, 0, respBytes.Length)) > 0)
            {
                respBuilder.Append(ASCIIEncoding.ASCII.GetString(respBytes, 0, bytes));
            }

            stream.Close();
            client.Close();           

            return respBuilder.ToString();
        }

        #endregion
    }
}
