#!/usr/bin/env python
#coding:utf-8
#Author:zjun

import re
import sys
import Queue
import threading
import optparse
import requests
from IPy import IP

printLock = threading.Semaphore(1)  #lock Screen print
TimeOut = 5  #request timeout

#User-Agent
header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36','Connection':'close'}
#Port
port = [80, 8080, 81, 8081, 7001, 8000, 8088, 8888, 9090, 8090, 88, 8001, 82, 8082, 8089, 9000, 8443, 9999, 8002,
        89, 999, 8200, 8085, 9001, 9200, 8100, 443, 8087, 8181, 8099, 8899, 9002, 888, 7200, 8020, 7002, 8099, 8800]

class scan():

  def __init__(self,cidr,threads_num):
    self.threads_num = threads_num
    self.cidr = IP(cidr)
	#build ip queue
    self.IPs = Queue.Queue()
    for ip1 in self.cidr:
      for p in port:
        ip = str(ip1)+':'+str(p)
        self.IPs.put(ip)

  def request(self):
    with threading.Lock():
      while self.IPs.qsize() > 0:
        ip = self.IPs.get()
        try:
          r = requests.Session().get('http://'+str(ip),headers=header,timeout=TimeOut)
          status = r.status_code
          title = re.search(r'<title>(.*)</title>', r.text) #get the title
          if title:
            title = title.group(1).strip().strip("\r").strip("\n")[:30]
          else:
            title = "None"
          banner = ''
          try:
            banner += r.headers['Server'][:20] #get the server banner
          except:pass
          printLock.acquire()
          print "|%-21s|%-6s|%-25s|%-35s" % (ip,status,banner,title)
          
        except Exception,e:
          printLock.acquire()
        finally:
          printLock.release()

  #Multi thread
  def run(self):
    for i in range(self.threads_num):
      t = threading.Thread(target=self.request)
      t.start()

if __name__ == "__main__":
  parser = optparse.OptionParser("Usage: %prog [options] target")
  parser.add_option("-t", "--thread", dest = "threads_num",
    default = 100, type = "int",
    help = "[optional]number of  theads,default=100")
  (options, args) = parser.parse_args()
  if len(args) < 1:
    parser.print_help()
    sys.exit(0)

                                    
                                    
  print "  ___   ___    ___    __ _   _ __  "
  print " / __| / __|  / __|  / _` | | '_ \ "
  print "| (__  \__ \ | (__  | (_| | | | | |"
  print " \___| |___/  \___|  \__,_| |_| |_|\n" 
  print "Usage: python2 cscan.py [options]\n" 
  print "Use -h for help\n"
  print "cscan based on httpscan\n"
  print "|IP                   |Status|Server                   |Title                               "

  s = scan(cidr=args[0],threads_num=options.threads_num)
  s.run()
