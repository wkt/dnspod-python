#!/usr/bin/env python
#-*- coding:utf-8 -*-

from dnspod.apicn import *
import sys
import time
import getpass

def getip():
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
##        except:pass
    finally:
        if w:w.close() 

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

    def check_login(self):
        ret = True
        try:
            api = InfoVersion(email=self.email, password=self.password)
            ret = api()
        except:
            ret = False
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
                logmsg("Login test OK")
                break
            else:
                logmsg("Login test failed")
                retry = raw_input("Failed to login ! Retry? Yes/No ")
                if len(retry) == 0 or retry.lower() == 'yes' or retry.lower() == 'y':
                    pass
                else:
                    break

        return login_ok


if __name__ == '__main__':
    dns = DDNS('xx51.net',sub_domain='ddns')
    dns.set_email("wkt55555@163.com")

    if dns.email_and_password_from_stdin():
        dns.ddns_init()
        while True:
            dns.record_ddns()
            time.sleep(60)
    else:
        logmsg("Give it up!")