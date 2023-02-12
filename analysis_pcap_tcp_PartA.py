import dpkt
import struct


def parseBytes(buffer, format, position, size):
    try:
        if(len(buffer) > position):
            return str(struct.unpack(format, buffer[position:position+size])[0])
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
		


def main():
	pcap = dpkt.pcap.Reader(open('assignment2.pcap', 'rb'))
	IpAddr1 = "130.245.145.12"
	IpAddr2 = "128.208.2.198"
	pktObj = []
	for timestamp, buffer in pcap:
		pkt = PacketStruct()
		pkt.parsePacket(timestamp, buffer)
		if pkt.isValid:	
			pktObj.append(pkt)
   
	
 
	TCPConns = 0			# Number of TCP Connections
	for pkt in pktObj:
		if pkt.syn == "1" and pkt.ack == "1":
			print ("Max Segment Size : ", pkt.maxSegSize + " for connection " + str(TCPConns+1))
			TCPConns += 1
	print ("Number of TCP connections : ", TCPConns)
	

	connections = []
	count = 0
	for pkt in pktObj:
		count += 1
		if pkt.syn == "1" and pkt.ack == "1":
			connection = Connection(pkt.sourcePort, pkt.destPort)
			connection.packets = []     
			connections.append(connection)
	
	for pkt in pktObj:
		# Throughput
		for conn in range(0,len(connections)):
			if (((pkt.sourcePort == connections[conn].sourcePort) and (pkt.destPort == connections[conn].destPort)) or \
					((pkt.sourcePort == connections[conn].destPort) and (pkt.destPort == connections[conn].sourcePort))):
				connections[conn].packets.append(pkt)

	for conn in connections:
		once = True
		PayloadSize = 0
		pkt_1 = 0
		pkt_last = 0
		for pkt in conn.packets:
			if pkt.sourceIP == IpAddr1:
				PayloadSize += int(pkt.size)
				if once:
					pkt_1 = pkt.timeStamp
					once = False

				pkt_last = pkt.timeStamp
			
		print ("Throughput : " + str(PayloadSize/(pkt_last-pkt_1)))

		# Packets lost/received and Loss rate
		seqLookup = {}
		loss = 0
		totalSent = 0
		for pkt in conn.packets:
			if pkt.sourceIP == IpAddr1 and pkt.destIP == IpAddr2:
				seqLookup[pkt.seqNumber] = seqLookup.get(pkt.seqNumber,0) + 1
				totalSent += 1

		for key in seqLookup.items():
			if key in seqLookup:
				loss += seqLookup[key]-1

		print("Source IP: " + str(pkt.sourceIP) + " Destination IP: " + str(pkt.destIP))
		print ("Packets not recieved : ", loss)
		print("Total Packets Sent : ",totalSent)
		print ("Loss Rate : ", (loss*1.0)/totalSent)
		
		# Average Rount Trip Time
		seqLookup = {}
		ackLookup = {}
		for pkt in conn.packets:
			if pkt.sourceIP == IpAddr1 and pkt.destIP == IpAddr2 and pkt.seqNumber not in seqLookup:
				seqLookup[pkt.seqNumber] = pkt.timeStamp
			elif pkt.sourceIP == IpAddr2 and pkt.destIP == IpAddr1 and pkt.ackNumber not in ackLookup:
				ackLookup[pkt.ackNumber] = pkt.timeStamp	

		transactions = 0 
		transactionTime = 0
		avgRTT = 0
		for seqNo, seqTS in seqLookup.items():
			if seqNo in ackLookup:
				transactions += 1
				transactionTime += ackLookup[seqNo] - seqTS
		avgRTT = transactionTime/transactions
		print ("Average Round Trip Time(RTT) : ", avgRTT)

		print ("-------------------------------------------------------------------------------")

if __name__ == '__main__':
	main()