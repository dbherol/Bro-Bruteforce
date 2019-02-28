@load base/frameworks/notice
@load base/protocols/ftp
@load base/utils/addrs.bro
#usage: bro -r *.pcap test.bro

module FTP;

global timeRange = 15; 
type Attempt: record{
	numAttempts: vector of time &default = vector();  
};

global failedAttempts: table[transport_proto, addr] of Attempt;

event bro_init()
	{
	print "Starting bruteforce scan";
	} 
event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
##	print fmt("The connection %s from %s on port %s to %s on port %s.", c$uid, c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
	local cmd = c$ftp$cmdarg$cmd;
	local currTime = c$start_time; 
	local currPort = get_port_transport_proto(c$id$orig_p);
##	print fmt("Status code of ftp connection: %s", c$ftp$reply_code);
##	The username is sent to the server using the USER command, and the password is sent using the PASS command.
	if(cmd == "USER" || cmd == "PASS")
	{
## 	5xx---permanent Negative Completion reply. 530 is code for failed password. This finds all failed password attempts from all addresses in pcap. 
		if(c$ftp$reply_code == 530){
			if([currPort, c$id$orig_h] !in failedAttempts)
			{
				failedAttempts[currPort, c$id$orig_h] = Attempt();
				failedAttempts[currPort, c$id$orig_h]$numAttempts += currTime; 
			}
			else
			{
			failedAttempts[currPort, c$id$orig_h]$numAttempts += currTime;
			}
		}
	}
## 	print out all ip addresses and failures in table
	}
event bro_done(){
	for([i, j] in failedAttempts)
	{
	       local totalTime = failedAttempts[i, j]$numAttempts[|failedAttempts[i, j]$numAttempts| - 1] - failedAttempts[i, j]$numAttempts[0];
 	       print fmt("%s failed password attempts from %s over %s protocol in %s.", |failedAttempts[i, j]$numAttempts|, j, i, totalTime);
 	}
	print "End of bruteforce scan";
	}
