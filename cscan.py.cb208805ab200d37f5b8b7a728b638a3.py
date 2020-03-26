# cscan based on httpscan
import requests
import re
import IPy
import sys
import argparse
import threading


headers={
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36',
    'Connection':'close'
}

portlist = [
    80, 8080, 81, 8081, 7001, 8000, 8088, 8888, 9090, 8090, 88, 8001, 82, 9080, 8082, 8089, 9000, 8443, 9999, 8002,
    89, 8083, 8200, 90, 8086, 801, 8011, 8085, 9001, 9200, 8100, 8012, 85, 8084, 8070, 8091, 8003, 7777, 8010, 443,
    8028, 8087, 83, 10000, 8181, 8099, 8899, 8360, 8300, 9002, 8053, 1000, 8989, 9060, 888, 8006, 6677, 7200, 8280,
    8161, 8880, 8020, 7070, 889, 1010, 8004, 86, 38501, 41516, 28017, 18080, 7002, 808, 800, 8099, 8800, 8180,
    3505, 7080, 8484, 9003
]

def iplist(ip):
    urllist=[]
    iplist = IPy.IP(ip)
    for ip in iplist[1:-1]:
        for port in portlist:
            urllist.append('http://'+str(ip)+':'+str(port))
    return urllist

def scan(start, end, urllist, lockObj):
    for i in range(int(start), int(end)):
        try:
            r = requests.session().get(url=urllist[i],headers=headers,timeout=5)
            status = r.status_code
            if status != 404 and status != 403 and status != 400 and status != 502:
                title = re.search(r'<title>(.*)</title>', r.content.decode())
                if title:
                    title = title.group(1).strip().strip("\r").strip("\n")
                else:
                    title = 'Null'
                banner = ''
                try:
                    banner += r.headers['Server'][:21]
                except:
                    pass
                lockObj.acquire()
                print ("|%-29s|%-6s|%-24s|%-35s" % (urllist[i],status,banner,title))
                lockObj.release()
        except:
            pass
    
def main():
    print(r'''
  ___ ___  ___ __ _ _ __
 / __/ __|/ __/ _` | '_ \
| (__\__ \ (_| (_| | | | |
 \___|___/\___\__,_|_| |_|
               by:zjun
            www.zjun.info
          ''')
    parser = argparse.ArgumentParser(description='cscan based on httpscan')
    parser.add_argument('-i', '--ip', required=True, help='target ip or ip segment')
    parser.add_argument('-t', '--thread', required=False, default = 100, help='number of threads,default = 100')
    args = parser.parse_args()
    ip = args.ip
    numbers = args.thread
    print ('|IP                           |Status|Server                  |Title')
    url = iplist(ip)
    lock = threading.Lock()
    for i in range(int(numbers)):
        if i == int(numbers) - 1:
            threading.Thread(target=scan, args=(i * len(url) / int(numbers), len(url), url, lock)).start()
        threading.Thread(target=scan, args=(i * len(url) / int(numbers), (i + 1) * len(url) / int(numbers) - 1, url, lock)).start()
        
if __name__ == '__main__':
    main()