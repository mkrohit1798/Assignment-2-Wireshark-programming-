import dpkt
import struct


def parseBytes(buffer, fmt, pos, size):
    try:
        if len(buffer) > pos:
            return str(struct.unpack(fmt, buffer[pos:pos+size])[0])
    except Exception:
        pass

class PacketStruct:
	isValid = True
	headerSize = ""
	sourceIP = ""
	destIP = ""
	sourcePort = ""
	destPort = ""
	syn = ""
	ack = ""
	windowSize = ""
	seqNumber = ""
	ackNumber = ""
	size = ""
	timeStamp = 0
	maxSegSize = ""

	def parsePacket(self, timestamp, buffer):
		try:
			self.headerSize = parseBytes(buffer, ">B", 46, 1)
			self.sourceIP = parseBytes(buffer, ">B", 26, 1) + "." + parseBytes(buffer, ">B", 27, 1) + \
						"." + parseBytes(buffer, ">B", 28, 1) + "." + parseBytes(buffer, ">B", 29, 1)

			self.destIP = parseBytes(buffer, ">B", 30, 1) + "." + parseBytes(buffer, ">B", 31, 1) + \
       				"." + parseBytes(buffer, ">B", 32, 1) + "." + parseBytes(buffer, ">B", 33, 1)

			self.sourcePort = parseBytes(buffer, ">H", 34, 2)
			self.destPort = parseBytes(buffer, ">H", 36, 2)
			option = "{0:16b}".format(int(parseBytes(buffer, ">H", 46, 2)))
			self.syn = option[14]
			self.ack = option[11]
			self.seqNumber = parseBytes(buffer, ">I", 38, 4)
			self.ackNumber = parseBytes(buffer, ">I", 42, 4)
			self.windowSize = parseBytes(buffer, ">H", 48, 2)
			self.size = len(buffer)
			self.timeStamp = timestamp
			self.maxSegSize = parseBytes(buffer, ">H", 56, 2)
		except:
			self.isValid = False



class Connection:
	sourcePort = ""
	destPort = ""
	packets = []
	def __init__(self, _src, _dest):
		self.sourcePort = _src
		self.destPort = _dest


def TripDupAckRetransmission(pktObj):
	IPAddr1 = "130.245.145.12"
	IPAddr2 = "128.208.2.198"
	seqLookup = {}
	ackLookup = {}
	for pkt in pktObj:
		if pkt.sourceIP == IPAddr1 and pkt.destIP == IPAddr2:
			seqLookup[pkt.seqNumber] = seqLookup.get(pkt.seqNumber,0) + 1
		elif pkt.sourceIP == IPAddr2 and pkt.destIP == IPAddr1:
			ackLookup[pkt.ackNumber] = ackLookup.get(pkt.ackNumber,0) + 1

	loss = 0
	tripleDupAck = 0
	for key, value in seqLookup.items():
		if key in seqLookup:
			loss += seqLookup[key]-1
		if (key in ackLookup) and (ackLookup[key] > 2):
			tripleDupAck += seqLookup[key]-1

	print ("Duplicate packet retransmitted : " + str(loss))
	print ("Triple Duplicate ACKS retransmission: " + str(tripleDupAck))
	print ("Timeout loss : " + str(loss-tripleDupAck))


def ComputeCongestionWindow(pktObj):
	IPAddr1 = "130.245.145.12"
	IPAddr2 = "128.208.2.198"
	cwnd = []
	for pkt in pktObj:
		if pkt.sourceIP == IPAddr1 and pkt.destIP == IPAddr2:
			last_seq = pkt.seqNumber
		elif pkt.sourceIP == IPAddr2 and pkt.destIP == IPAddr1 and int(last_seq)-int(pkt.ackNumber) != -1:
			cwnd.append(str(int(last_seq)-int(pkt.ackNumber)))
			if len(cwnd) == 10:
				break


	for c in cwnd:
		print ("Congestion Window : " + c)


def main():
	pcap = dpkt.pcap.Reader(open('assignment2.pcap', 'rb'))

	
 
	pktObj = []
	for timeStamp, buffer in pcap:
		pkt = PacketStruct()
		pkt.parsePacket(timeStamp, buffer)
		if pkt.isValid:	
			pktObj.append(pkt) 
 
	

	#Number of TCP connections
	TCPConns = 0
	for pkt in pktObj:
		if pkt.syn == "1" and pkt.ack == "1":
			print ("Max Segment Size : " + pkt.maxSegSize + " for connection " + str(TCPConns+1))
			TCPConns += 1
	print ("No of tcp connections : " + str(TCPConns))
	
	connections = []
	count = 0
 
 
	for pkt in pktObj:
		count += 1
		if pkt.syn == "1" and pkt.ack == "1":
			connection = Connection(pkt.sourcePort, pkt.destPort)
			connection.packets = []     
			connections.append(connection)

	for pkt in pktObj:
		for conn in range(0,len(connections)):
			if (((pkt.sourcePort == connections[conn].sourcePort) and (pkt.destPort == connections[conn].destPort)) or \
					((pkt.sourcePort == connections[conn].destPort) and (pkt.destPort == connections[conn].sourcePort))):
				connections[conn].packets.append(pkt)
    
    

	#PART B
	for conn in connections:
		#Retransmissions , Triple Ack Loss
		TripDupAckRetransmission(conn.packets)

		#Congestion Window
		ComputeCongestionWindow(conn.packets)
		print ("---------------------------------------------------------------------------------")

	
    


if __name__ == '__main__':
	main()