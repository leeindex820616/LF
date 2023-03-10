import json
import logging
import os
import sys
import re
import requests
import stdiomask
from time import sleep
from datetime import datetime

def wait_and_exit():
    os.system('pause')
    exit()

def cts():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def initTheLogger():
    rootLogger=logging.getLogger()
    rootLogger.setLevel(logging.DEBUG)
    if os.path.exists('logs') == False:
        os.mkdir('logs')
    loggingHandler = logging.FileHandler(r'logs/'+datetime.now().strftime('[%Y-%m-%d]')+'checkdomain.log', 'a+', 'utf-8')
    rootLogger.addHandler(loggingHandler)

class zabbixProfile(object):
    #init profile for get auth.
    def __init__(self):
        super(zabbixProfile, self).__init__()
        with open('config.json', 'r') as f:
            configJson = json.load(f)
        logging.info('[{}][INFO] Done load config.'.format(cts()))
        #Init config for zabbix auth token
        self.zabbixAPIurl = configJson['ServerIPAddress']+'/api_jsonrpc.php'
        if configJson['Username'] == '':
            self.zabbixUsername=input('Pleas input your username:')
        else:
            self.zabbixUsername=configJson['Username']
        self.header = {'Content-Type': 'application/json-rpc'}
        self.ip_regex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        self.zabbixPassword = ''
        self.zabbixToken = ''
        self.statusCode = 0
        self.requestDomainlist = []
        logging.info('[{}][INFO] Done initialization.'.format(cts()))
        #Get domain list txt
        try:
            for filename in sys.argv[1:]:
                print(filename)
                if re.search('(.txt)$', filename) == None:
                    logging.error('[{}][Error] Please provide txt file extension.'.format(cts()))
                else:
                    with open(filename, 'r') as f:
                        for line in f:
                            self.requestDomainlist.append(line.strip())
                            logging.info('[{}][INFO] Read {} from {} successfully.'.format(cts(), line.strip(), filename))
        except Exception as E:
            logging.error('[{}][INFO] Excepted error: {}'.format(cts(), str(E)))
            print('[{}][INFO] Excepted error: {}'.format(cts(), str(E)))
            wait_and_exit()

    #Error check
    def checkError(self, response):
        try:
            if 'error' in response.keys():
                print('[{}][ERROR] {}.'.format(cts(), response['error']['data']))
                logging.error('[{}][ERROR] {}.'.format(cts(), response['error']['data']))
            else:
                print('[{}][INFO] Success'.format(cts()))
                logging.info('[{}][INFO] Success'.format(cts()))
        except KeyError:
            print('[{}][ERROR] Get an exception about KeyError.'.format(cts()))
            logging.error('[{}][ERROR] Get an exception about KeyError.'.format(cts()))
        else:
            return response

    #Get user password:
    def inputPassword(self):
        while 1:
            self.zabbixPassword = 'lPq^$LCrTZAa'
            if not self.zabbixPassword:
                break
            self.tryGetAuth()
            logging.debug('after get auth')
            if not self.zabbixToken:
                logging.error('[{}][ERROR] Fail to get Auth.'.format(cts()))
                continue
            break

    #Post function
    def postRequest(self, jsonbody):
        try:
            request = requests.post(url=self.zabbixAPIurl, headers=self.header, data=json.dumps(jsonbody), timeout=60)
            logging.info('[{}][INFO] {}.'.format(cts(), request))
            sleep(0.1)
        except requests.ConnectionError:
            logging.error('[{}][ERROR] {}.'.format(cts(), request))
            return None
        else:
            #print(request.json())
            return self.checkError(request.json())

    #Try to get auth from zabbix with username password
    def tryGetAuth(self):
        jsonbody = {
            "jsonrpc":"2.0",
            "method":"user.login",
            "params":{
                "user": self.zabbixUsername,
                "password": self.zabbixPassword
            },
            "id": 1
        }
        logging.info('[{}][INFO] Send a login request to zabbix api.'.format(cts()))
        response_buffer = self.postRequest(jsonbody)
        self.zabbixToken = '' if 'error' in response_buffer else response_buffer['result']

    def tryGetHost(self, domainName):
        jsonbody = {
            "jsonrpc":"2.0",
            "method":"host.get",
            "params":{
                "filter":{
                    "host":[
                        domainName
                    ]
                }
            },
            "auth": self.zabbixToken,
            "id": 1
        }
        logging.info('[{}][INFO] Send a get host({}) request to zabbix api.'.format(cts(), domainName))
        return self.postRequest(jsonbody)

    def try_get_hostid_description(self, domain):
        jsonbody = {
            "jsonrpc": "2.0",
            "method": "host.get",
            "params": {
                "output":[
                    "description"
                ],
                "selectGroups":"extend",
                "filter":{
                    "host":[
                        domain
                    ]
                }
            },
            "auth": self.zabbixToken,
            "id": 1
        }
        return self.postRequest(jsonbody)

    def get_all_groups(self):
        jsonbody={
            "jsonrpc": "2.0",
            "method": "hostgroup.get",
            "params":{
                "output":"extend"
            },
            "auth": self.zabbixToken,
            "id":1
        }
        return self.postRequest(jsonbody)

    def get_all_proxies(self):
        jsonbody={
            "jsonrpc": "2.0",
            "method": "proxy.get",
            "params":{
                "output":"extend",
                "selectInterface":"extend"
            },
            "auth": self.zabbixToken,
            "id":1 
        }
        return self.postRequest(jsonbody)

    def get_all_templates(self):
        jsonbody={
            "jsonrpc": "2.0",
            "method": "template.get",
            "params":{
                "output":"extend"
            },
            "auth": self.zabbixToken,
            "id":1 
        }
        return self.postRequest(jsonbody)

    def create_host(self, domain, groups, templates, port='443', proxy=None, description=None):
        if description == None:
            description=''
        use_ip=1 if re.match(self.ip_regex, domain) else 0
        jsonbody={
            "jsonrpc":"2.0",
            "method":"host.create",
            "params":{
                "host": "{}".format(domain),
                "description":description,
                "interfaces":[
                    {
                        "type": 1,
                        "main": 1,
                        "useip": use_ip,
                        "ip": domain if use_ip == 1 else "",
                        "dns": domain if use_ip == 0 else "",
                        "port": port
                    }
                ],
            },
            "auth": self.zabbixToken,
            "id": 1
        }
        jsonbody['params']['groups']=groups
        jsonbody['params']['templates']=templates
        if proxy != None:
            jsonbody['params']['proxy_hostid']=proxy
        return self.postRequest(jsonbody)

    def china_only_creat_host(self, domain, description=None):
        if description is None:
            description=''
        jsonBody={
            "jsonrpc":"2.0",
            "method":"host.create",
            "params":{
                "host": "{} for HTTP".format(domain),
                "description":description,
                "interfaces":[
                    {
                        "type": 1,
                        "main": 1,
                        "useip": 0,
                        "ip": "",
                        "dns": domain,
                        "port": "80"
                    }
                ],
                "groups":[
                    {
                        "groupid":"15"
                    }
                ],
                "templates":[
                    {
                        "templateid":"16946"
                    }
                ],
                "proxy_hostid":"10268"
            },
            "auth": self.zabbixToken,
            "id": 1
        }
        return self.postRequest(jsonBody)

    def updateHost(self, hostID, host_description, add_description=''):
        jsonBody = {
            "jsonrpc": "2.0",
            "method": "host.update",
            "params": {
                "hostid":hostID,
                "groups":[
                    {
                        "groupid":"15"
                    }
                ],
                "description":host_description+'\r\n'+add_description
            },
            "id": 1,
            "auth": self.zabbixToken    
        }
        return self.postRequest(jsonBody)


    def tryLogoutUser(self):
        jsonbody = {
            "jsonrpc": "2.0",
            "method": "user.logout",
            "params": {},
            "id": 1,
            "auth": self.zabbixToken
        }
        logging.info('[{}][INFO] Send a logout request to zabbix api.'.format(cts()))
        self.postRequest(jsonbody)

    def getDomainList(self):
        return self.requestDomainlist

    def getZabbixToken(self):
        return self.zabbixToken

    def test_password_express(self, password):
        self.zabbixPassword = password

class modifyDomainList(zabbixProfile):
    def modifyTxt(self):
        if not super().getDomainList():
            print('[{}][INFO] No input text file found.'.format(cts()))
            logging.info('[{}][INFO] No input text file found.'.format(cts()))
            return None
        super().inputPassword()
        notExistListFileName = '{}domainlist.txt'.format(datetime.now().strftime('[%Y-%m-%d_%H-%M-%S]'))
        disableFileName = '{}disableList.txt'.format(datetime.now().strftime('[%Y-%m-%d_%H-%M-%S]'))
        notExistList = open(notExistListFileName, 'x')
        logging.info('[{}][INFO] Create {}.'.format(cts(), notExistListFileName))
        disableList = open(disableFileName, 'x')
        logging.info('[{}][INFO] Create {}.'.format(cts(), disableFileName))
        for domain in super(modifyDomainList, self).getDomainList():
            response = super(modifyDomainList, self).tryGetHost(domain)
            if not response['result']:
                notExistList.write('{}\n'.format(domain))
                logging.info('[{}][INFO] Wirte {} to domain list.'.format(cts(), domain))
            elif response['result'][0]['status'] == '1':
                disableList.write('{}\n'.format(domain))
                logging.info('[{}][INFO] Wirte {} to disable list.'.format(cts(), domain))
        notExistList.close()
        disableList.close()
        if not os.path.getsize(notExistListFileName):
            logging.info('[{}][INFO] Delete not exist domain list.'.format(cts()))
            os.remove(notExistListFileName)
        if not os.path.getsize(disableFileName):
            logging.info('[{}][INFO] Delete disable domain list.'.format(cts()))
            os.remove(disableFileName)
        super(modifyDomainList, self).tryLogoutUser()

class chinaOnly(zabbixProfile):
    def chinaOnlyTemplate(self):
        super().inputPassword()
        domain_input=[]
        print('Paste the domain list(:q for quit):')
        while 1:
            input_buffer=input('').strip()
            if input_buffer == '':
                continue
            elif input_buffer == ':q':
                break
            domain_input.append(input_buffer)
        description=input('Description:')
        for domain in domain_input:
            domain=domain.strip()
            if re.match('^(www\.)?[a-zA-Z0-9]?[a-zA-Z0-9\-]{0,62}[a-zA-Z0-9]?(\.[a-zA-Z]{2,62})$', domain):
                re.sub('^(www\.)', '',domain)
                print('[{date}][INFOR] Try to create new host \"{domain}\" for HTTP with description {des}'.format(date=cts(), domain=domain, des=description))
                super().china_only_creat_host(domain, description=description)
                print('[{date}][INFOR] Try to create new host \"{domain}\" for HTTP with description {des}'.format(date=cts(), domain='www.'+domain, des=description))
                super().china_only_creat_host('www.'+domain, description=description)
                print('[{date}][INFOR] Try to update host \"{domain}\" with Group CH Web Site, description {des}'.format(date=cts(), domain=domain, des=description))
                response_hostid_des = super().try_get_hostid_description(domain)['result']
                super().updateHost(response_hostid_des[0]['hostid'],response_hostid_des[0]['description'],description)
                print('[{date}][INFOR] Try to update host \"{domain}\" with Group CH Web Site, description {des}'.format(date=cts(), domain='www.'+domain, des=description))
                response_hostid_des = super().try_get_hostid_description('www.'+domain)['result']
                super().updateHost(response_hostid_des[0]['hostid'],response_hostid_des[0]['description'],description)

class batch_create_ssl_host(zabbixProfile):
    def __init__(self):
        super().__init__()
        super().inputPassword()
        logging.info('[{date}][INFO] Trying to get group list.'.format(date=cts()))
        print('[{date}][INFO] Trying to get group list.'.format(date=cts()))
        self.all_group_list = {x['name']:x['groupid'] for x in super().get_all_groups()['result']}
        logging.info('[{date}][INFO] Trying to get proxy list.'.format(date=cts()))
        print('[{date}][INFO] Trying to get proxy list.'.format(date=cts()))
        self.all_proxy_list = {x['host']:x['proxyid'] for x in super().get_all_proxies()['result']}
        logging.info('[{date}][INFO] Trying to get template list.'.format(date=cts()))
        print('[{date}][INFO] Trying to get template list.'.format(date=cts()))
        self.all_template_list = {x['name']:x['templateid'] for x in super().get_all_templates()['result']}
        print('--------Group list id--------')
        for x in self.all_group_list.keys():
            print('{} {}'.format(x, self.all_group_list[x]))
        print('--------Proxy list id--------')    
        for x in self.all_proxy_list.keys():
            print('{} {}'.format(x, self.all_proxy_list[x]))    
        print('--------Template list id--------')
        for x in self.all_template_list.keys():
            print('{} {}'.format(x, self.all_template_list[x]))
        with open('templates.json', 'r') as j:
            self.templates_json = json.load(j)
    
    def templates_menu(self):
        for index, item in enumerate(self.templates_json['profile']):
            print('{index}. {profile_name}'.format(index=index+1, profile_name=item['profile_name']))

    def check_item_exist(self, selected_template):
        if selected_template['template']['groups'] in self.all_group_list.values() or selected_template['template']['templates'] in self.all_template_list.values() or (selected_template['template']['proxy'] != '' and not selected_template['template']['proxy'] in self.all_proxy_list.values()):
            logging.error('[{date}][ERROR] Template is invalid.'.format(date=cts()))
            print('[{date}][ERROR] Template is invalid.'.format(date=cts()))
            wait_and_exit()

    def add_ssl_host(self):
        self.templates_menu()
        get_profile_number = input('Type number for which template you want to apply:')
        try:
            selected_template=self.templates_json['profile'][int(get_profile_number)-1]
        except ValueError:
            logging.error('[{date}][INFO] Input is not template number.'.format(date=cts()))
            print('[{date}][INFO] Input is not template number.'.format(date=cts()))
            wait_and_exit()
        else:
            logging.info('[{date}][INFO] Load template: {profile_name}..'.format(date=cts(), profile_name=selected_template['profile_name']))
            print('[{date}][INFO]Load template: {profile_name}..'.format(date=cts(), profile_name=selected_template['profile_name']))
        self.check_item_exist(selected_template)
        domain_input=[]
        template_name=selected_template['profile_name']
        print('Paste the domain list(:q for quit):')
        while 1:
            input_buffer=input('').strip()
            if input_buffer == '':
                continue
            elif input_buffer == ':q':
                break
            domain_input.append(input_buffer)
        description = input('Description:')
        for item in domain_input:
            domain=item.split(':')
            logging.info('[{date}][INFO] Create host for \'{domain_name}\' with {template_name}..'.format(date=cts(), domain_name=item, template_name=template_name))
            print('[{date}][INFO] Create host for \'{domain_name}\' with {template_name}..'.format(date=cts(), domain_name=item, template_name=template_name))
            super().create_host(domain[0], 
                                [{'groupid':x} for x in selected_template['template']['groups']], 
                                [{'templateid':x} for x in selected_template['template']['templates']],
                                '443' if len(domain)==1 else domain[1],
                                None if selected_template['template']['proxy']=='' else selected_template['template']['proxy'],
                                description=description)

class test_API_module(zabbixProfile):
    def testResponse(self):
        super().test_password_express('Password123')
        super().tryGetAuth()
        group_list = super().get_all_groups()
        proxy_list = super().get_all_proxies()
        template_list = super().get_all_templates()
        for item in group_list['result']:
            print(item)
        for item in proxy_list['result']:
            print(item['host']+'//'+item['proxyid'])
        for item in template_list['result']:
            print(item['name']+'//'+item['templateid'])

if __name__ == '__main__':
    initTheLogger()
    
    print('Please input the number to select function.')
    print('[1] Check host is it on Zabbix by text.')
    print('[2] Create China only host by text.')
    print('[3] Batches add SSL monitor with template.')
    print('[Input another string to leave.]')

    inputValue = input('\nInput:')
    if inputValue == '1':
        zabbix = modifyDomainList()
        if zabbix.modifyTxt() == None:
            pass
    elif inputValue == '2':
        zabbix = chinaOnly()
        zabbix.chinaOnlyTemplate()
    elif inputValue == '3':
        zabbix = batch_create_ssl_host()
        zabbix.add_ssl_host()
    else:
        exit()
    


    #test

    os.system('pause')