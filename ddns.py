#!/usr/bin/env python
#-*- coding:utf-8 -*-

from dnspod.apicn import *
import sys
import time
import getpass
import os

def __getip():
    sock = socket.create_connection(('ns1.dnspod.net', 6666))
    ip = sock.recv(16)
    sock.close()
    return ip

import traceback
def exception_msg(error_only=False):
    if error_only:
        (e1,e2,e3) = sys.exc_info()
        d = str(e2)
    else:
        d = traceback.format_exc()
    return d

def logmsg(msg,toerr=True):
    import os
    logfile = "/tmp/.ddns.log"
    t = time.strftime("%F,%a %T",time.localtime())
    w=None
    try:
        w = open(logfile,"a")
        txt = "[%d]%s:%s\n" % (os.getpid(),t,msg)
        w.write(txt)
        if toerr:
            sys.stderr.write(txt)
    except:pass
    finally:
        if w:w.close() 

def testInternetConnection():
    res=False
    address_array=[("www.baidu.com",80),('www.google.com',80)]
    for addr in address_array:
        try:
            sock = socket.create_connection(addr)
            sock.close()
            res = True
        except:
            logmsg(exception_msg())
        if res:break
    return res


def cmd_output(cmd):
    import subprocess
    p = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE)
    p.wait()
    return p.stdout.read().strip()

class DDNS(object):

    def __init__(self,domain,sub_domain='@'):
        self._email = ""
        self._password = ""
        self._domain = domain
        self._sub_domain = sub_domain
        self._domain_id=0
        self._record_id=0
        self._ddns_ip = '0.0.0.0'

    @property
    def email(self):
        return self._email

    @property
    def password(self):
        return self._password

    def set_email(self,email):
        self._email = email

    def set_password(self,password):
        self._password = password

    def config_from_file(self,cfg="~/.config/ddns.conf"):
        r=None
        try:
            r = open(os.path.expanduser(cfg))
            jsn = json.load(r)
            if jsn.has_key('email'):
                self.set_email(jsn.get('email'))
            if jsn.has_key('password'):
                self.set_password(jsn.get('password'))
            if jsn.has_key('domain'):
                self._domain = jsn.get('domain')
            if jsn.has_key('sub_domain'):
                self._sub_domain = jsn.get('sub_domain')
        finally:
            if r:r.close()
        return (self.email and self.password and len(self.email) > 0 and len(self.password) > 0 and self.check_login())
 
    def check_login(self):
        ret = True
        try:
            api = InfoVersion(email=self.email, password=self.password)
            ret = api()
        except:
            ret = False

        if ret:
            logmsg("Login test OK")
        else:
            logmsg("Login test failed")

        return ret


    def ddns_init(self):
        api=ApiCn(self.email,self.password,domain=self._domain)
        try:
            api.path='/Domain.Info'
            ret = api()
        except:
            logmsg("Create domain:"+self._domain)
            api=DomainCreate(self._domain,email=self.email,password=self.password)
            ret = api()
            logmsg("Domain("+self._domain + ") created")

        self._domain_id = ret.get("domain", {}).get("id")

        try:
            api=RecordList(self._domain_id,sub_domain=self._sub_domain,email=self.email,password=self.password)
            ret=api().get("records")[0]
            self._ddns_ip = ret.get("value")
        except:
            logmsg("Create sub domain(%s) for domain(%s)" %(self._sub_domain,self._domain))
            api=RecordCreate(self._sub_domain, "A", u'默认'.encode("utf8"), self._ddns_ip, 600, domain_id=self._domain_id,email=self.email,password=self.password)
            ret =api().get('record')
            logmsg("Sub domain(%s) for domain(%s) created" %(self._sub_domain,self._domain))

        self._record_id = ret.get("id")

    def record_ddns(self):
        new_ip = getip()
        if new_ip != self._ddns_ip:
            old_ip = self._ddns_ip
            api=RecordDdns(self._record_id,self._sub_domain,u'默认'.encode("utf8"),domain_id=self._domain_id,email=self.email,password=self.password)
            try:
                self._ddns_ip = api().get("record",{}).get("value")
            except:
                logmsg(exception_msg())
                raise
            logmsg("DDNS IP:"+ old_ip + "->"+self._ddns_ip)
        else:
            logmsg("DDNS IP:"+ self._ddns_ip +" unchanged")

    def email_and_password_from_stdin(self):
        login_ok = False
        while not login_ok:
            new_email=""
            prompt="Please enter your email:"
            if self.email and len(self.email) > 0:
                prompt="Please enter your email[%s]:" % self.email
            while len(new_email) == 0:
                new_email = raw_input(prompt).strip()
                if len(new_email) == 0 and self.email and len(self.email) > 0:
                    break;
                if new_email and len(new_email) > 0:
                    self.set_email(new_email)
                    break;

            new_password = ""
            while len(new_password) == 0:
                new_password = getpass.getpass('Please enter your passowrd:').strip()
                if new_password and len(new_password) > 0:
                    break;
            self.set_password(new_password)
            login_ok = self.check_login()
            if login_ok:
                break
            else:
                retry = raw_input("Failed to login ! Retry? Yes/No ")
                if len(retry) == 0 or retry.lower() == 'yes' or retry.lower() == 'y':
                    pass
                else:
                    break

        return login_ok


if __name__ == '__main__':
    dns = DDNS('test.net',sub_domain='ddns')
    time_out = 60

    while not testInternetConnection():time.sleep(time_out)

    if dns.config_from_file() or dns.email_and_password_from_stdin():
        dns.ddns_init()
        while True:
            try:
                dns.record_ddns()
                time_out = 60
            except:time_out = 10*60
            time.sleep(time_out)
    else:
        logmsg("Give it up!")
