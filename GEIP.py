#!/usr/bin/python
# -*- coding: utf-8 -*-
import scapy.all as scapy
#import cPickel as pickle
import pickle
import operator
#import dpkt
#import socket
import maxminddb as mmdb
import optparse

ipdb = mmdb.open_database(r'GeoLite2-City_20170404\GeoLite2-City.mmdb')

def retKML(tgtIP):
    rec = ipdb.get(tgtIP)
    try:
        longitude = rec['location']['longitude']
        latitude = rec['location']['latitude']
        kml = (
               '<Placemark>\n'
               '<name>%s</name>\n'
               '<Point>\n'
               '<coordinates>%6f,%6f</coordinates>\n'
               '</Point>\n'
               '</Placemark>\n'
               ) %(tgtIP,longitude, latitude)
#        print tgtIP + ' successful...'
        return kml
    except:
        return ''


'''
def plotIPs(pcap):
    kmlPts = ''
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            srcKML = retKML(src)
            dst = socket.inet_ntoa(ip.dst)
            dstKML = retKML(dst)
            kmlPts = kmlPts + srcKML + dstKML
        except:
            pass
    return kmlPts
'''


def plotIPs(pcapFile):
    print 'Reading PCAP file --->>>',pcapFile
    myPcapReader = scapy.PcapReader(pcapFile)
    
    dicIPsrc = {}
    dicIPdst = {}
    
    count = -1
    PacNum = 0
    kmlPts = ''
    
    while count != 0:
        count -= 1
        p = myPcapReader.read_packet()
        if p is None:
            break
        PacNum = PacNum + 1
        if PacNum >= 100000:
            break
        try:
#        if hasattr(p[1], 'src') == True:
            src = p['IP'].src
            if src in dicIPsrc:
                dicIPsrc[src] += 1
            else:
                dicIPsrc[src] = 1
#        if hasattr(p[1], 'dst') == True:
            dst = p['IP'].dst
            if dst in dicIPsrc:
                dicIPdst[dst] += 1
            else:
                dicIPdst[dst] = 1
        except:
            pass
    
    for IP in dicIPsrc:
        srcKML = retKML(IP)
        kmlPts = kmlPts + srcKML
    for IP in dicIPdst:
        dstKML = retKML(IP)
        kmlPts = kmlPts + dstKML
    
    myPcapReader.close()
    
    dicIPsrc = sorted(dicIPsrc.iteritems(), \
                      key=operator.itemgetter(1), reverse=True)
    dicIPdst = sorted(dicIPdst.iteritems(), \
                      key=operator.itemgetter(1), reverse=True)

    '''#--- USING pickle to save DICs ---        
    import pickle
    with open('dicIPsrc.pkl','w') as s:
        pickle.dump(dicIPsrc,s)
    with open('dicIPdst.pkl','w') as d:
        pickle.dump(dicIPdst,d)
    with open(r'dicIPsrc.pkl', 'r') as f:
        dicIPsrc = pickle.load(f)
    with open(r'dicIPdst.pkl', 'r') as f:
        dicIPdst = pickle.load(f)
    '''

    print PacNum,' packets processed.'
    return kmlPts

'''
unnecessary a single Placemark for every IP appearence
need to maintain an IP Dictionary 
'''

def main():
    parser = optparse.OptionParser('usage %prog -p <pcap file>')
    parser.add_option('-p', dest='pcapFile', type='string',\
      help='specify pcap filename')
    (options, args) = parser.parse_args()
    if options.pcapFile == None:
        print parser.usage
        exit(0)
    pcapFile = options.pcapFile
    
#    f = open(pcapFile)

#    pcap = dpkt.pcap.Reader(f)

    kmlheader = '<?xml version="1.0" encoding="UTF-8"?>\
    \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'
    kmlfooter = '</Document>\n</kml>\n'
    
    kmldoc = kmlheader + plotIPs(pcapFile) + kmlfooter
                            
#    print kmldoc
    kmlFile = pcapFile[:-4] + 'kml'
    with open(kmlFile, 'w') as f:
        f.write(kmldoc)

if __name__ == '__main__':
    main()

