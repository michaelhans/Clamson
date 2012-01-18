Clamson
=================================

Clamson provides a simple C# API to the ClamAV daemon (clamd) via TCP.  

Usage
-----

'''
//Instantiating the Client
//Server and Port
var clamd = new ClamdClient(“some-server”, 3310);
//Server, Port & Chunk Size
var clamd = new ClamdClient(“some-server”, 3310, 1024);

//Ping Command
var result = clamd.Ping();

//INSTREAM Command
MemoryStream memStream = new MemoryStream(eicar_bytes);
var result = clamd.Instream(memStream);
			
//VERSION Command           
var result = clamd.Version();
       
//RELOAD Command
var result = clamd.Reload();
        
//STATS Command       
var result = clamd.Stats();

//SCAN Command
var result = clamd.Scan(fileOrDirectoryName);
        
//CONTSCAN Command
var result = clamd.ContScan(fileOrDirectoryName);        
 
//MULTISCAN Command
var result = clamd.MultiScan(fileOrDirectoryName);

//SHUTDOWN Command
clamd.Shutdown();         
'''
Usage Non-Blocking - Wrap in a Task (Clamson was written at warp speed! Iterate/Evolve)

Required Runtime
----------------

.NET 2.0+ or Mono-2.10.8

TODO
----
Completion Ports/IASync Result (see Non-Blocking above) 
