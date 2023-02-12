import struct
import dpkt
import queue


def parseBytes(buffer, format, position, size):
    try:
        if len(buffer) > position:
            if isinstance(struct.unpack(format, buffer[position:position+size])[0], bytes):
                return (struct.unpack(format, buffer[position:position+size])[0]).decode('utf-8')
            return str(struct.unpack(format, buffer[position:position+size])[0])
    except Exception:
        pass
    # try:
    #     if len(buffer) > position:
    #         return str(struct.unpack(format, buffer[position:position+size])[0])
    # except Exception:
    #     pass

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
	request = ""
	response = ""
	data = ""

	def parsetcp(self, timestamp, buffer):
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
		except:
			self.isValid = False

	def parsehttp(self, timestamp, buffer):
		try:
			self.request = str(parseBytes(buffer, ">s", 66, 1)) + str(parseBytes(buffer, ">s", 67, 1)) + str(parseBytes(buffer, ">s", 68, 1))
			self.response = str(parseBytes(buffer, ">s", 66, 1)) + str(parseBytes(buffer, ">s", 67, 1)) + str(parseBytes(buffer, ">s", 68, 1)) + str(parseBytes(buffer, ">s", 69, 1))
		except:
			pass        

def ParsePcapFile(pcap):
	pktObj = []
	for timeStamp, buffer in pcap:
		packet = PacketStruct()
		packet.parsetcp(timeStamp, buffer)
		packet.parsehttp(timeStamp, buffer)
		if packet.isValid:	
			pktObj.append(packet) 
 
	return pktObj

def EvaluateHTTP(pktObj):
	#Count the number of TCP connections in the HTTP packet
	TCPConns = 0
	packetCount = 0
	totalPayload = 0
	for packet in pktObj:
		packetCount += 1
		totalPayload += packet.size
		if packet.syn == "1" and packet.ack == "1":
			TCPConns += 1
	
	print ("Number of tcp connections : " + str(TCPConns))
	print ("Time Taken : " + str(pktObj[len(pktObj)-1].timeStamp-pktObj[0].timeStamp))
	print ("Packet Count : " + str(packetCount))
	print ("Raw data size : " + str(totalPayload))





def main():
    pcapfile = dpkt.pcap.Reader(open('http_1080.pcap', 'rb'))
    pktObj = ParsePcapFile(pcapfile)
    que = queue.Queue()
    HTTPLookup = {}
    
    for pkt in pktObj:
        if pkt.request == "GET":
            que.put(pkt)
        elif pkt.response == "HTTP":
            deq = que.get()
            HTTPLookup[deq] = pkt
    
    for key, val in HTTPLookup.items():
        print("GET request:   " + key.sourceIP + " " + key.destIP + " " + key.seqNumber + " " + key.ackNumber)
        print("HTTP Response: " + val.sourceIP + " " + val.destIP + " " + val.seqNumber + " " + val.ackNumber)
    
	
    files = ['http_1080.pcap','tcp_1081.pcap', 'tcp_1082.pcap']
    print("-----------------------------------------------------------------")
    
    for f in files:
        pcap = dpkt.pcap.Reader(open(f, 'rb'))
        pktObj = ParsePcapFile(pcap)
        
        EvaluateHTTP(pktObj)
        print("------------------------------------------------")


if __name__ == '__main__':
	main()



