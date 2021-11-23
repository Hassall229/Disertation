import sys
import dpkt
import socket
import matplotlib.pyplot as plt
import datetime

def run():

    #Input filename through terminal "python/programme name/pcap file/192.168.56.104
    fileInput = sys.argv[1]
    fileCapture = open(fileInput)

    #IP section of input
    ipInput = sys.argv[2]

    #Read file contents and pass data to printAddress function
    pcap = dpkt.pcap.Reader(fileCapture)
    printAddress(pcap, ipInput)

def inet_str(inet):

    #Convert IP Address to string
    return socket.inet_ntop(socket.AF_INET, inet)

def printAddress(pcap, ipAddress):

    #Declare array to store values
    destinationPort = []
    timeStamp = []

    for ts, buf in pcap:

        #Load ethernet data object
        eth = dpkt.ethernet.Ethernet(buf)

        #Check for instance of IP
        if isinstance(eth.data, dpkt.ip.IP):

            #Set IP data and convert ip.src to string format
            ip = eth.data
            finalIp = inet_str(ip.src)

            #Check for instance of TCP
            if isinstance(ip.data, dpkt.tcp.TCP):

                #Set TCP data
                tcp = ip.data

                #If entered value (ipAddress) matches finalIP (string IP Address) store returned values in array
                if ipAddress == finalIp:

                    destinationPort.append(tcp.dport)
                    timeStamp.append(datetime.datetime.utcfromtimestamp(ts))

    #Plotting graph specifics
    plt.rcParams.update({'font.size': 6})
    plt.title('15112236')
    plt.xlabel('Port Number')
    plt.ylabel('Time elapsed')
    plt.plot(destinationPort, timeStamp, 'ro')
    plt.show()

if __name__ == '__main__':

    run();

