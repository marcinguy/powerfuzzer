#!/usr/bin/env python

# Powerfuzzer
# Copyright (C) 2008 Marcin Kozlowski
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import lswww,urllib,urllib2,urlparse,socket
import sys,re,getopt,os

import  wx
import  wx.lib.newevent
import wx.richtext as rt

import threading
import time

from wx.lib.wordwrap import wordwrap

import wx.lib.filebrowsebutton as filebrowse

import reportframe



try:
	import cookielib
except ImportError:
	cookielibhere=0
else:
	cookielibhere=1

ID_ABOUT = 101
ID_EXIT  = 102
version = "v1 BETA"




licenseText = "This program is free software; you can redistribute it and/or modify\nit under the terms of the GNU General Public License as published by\nthe Free Software Foundation; either version 2 of the License, or\n(at your option) any later version.\n\nThis program is distributed in the hope that it will be useful,\nbut WITHOUT ANY WARRANTY; without even the implied warranty of\nMERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\nGNU General Public License for more details.\n\nYou should have received a copy of the GNU General Public License\nalong with this program; if not, write to the Free Software\nFoundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA\n\n"



class worker(threading.Thread):

        root=""
        myls=""
        urls=[]
        forms=[]
        attackedGET=[]
        attackedPOST=[]
        server=""
        proxy={}
        cookie=""
        auth_basic=[]
        color=0
        bad_params=[]
        verbose=2
        doGET=1
        doPOST=1
        doExec=1
        doFileHandling=1
        doInjection=1
        doXSS=1
        doCRLF=1
        timeout=6
	type=""

        box="";
	window=""

        def __init__(self, threadNum, window,URL,type,user,password,cookie,proxy,timeout,verbose,ex_url1,ex_url2,ex_url3,ex_url4):
		#print "worker init"
		#print URL
		#print proxy
                threading.Thread.__init__(self)
                self.threadNum = threadNum
                self.window = window
                self.timeToQuit = threading.Event()
                self.timeToQuit.clear()
                self.root=window.URL
                self.rooturl=window.URL
                self.box=window.rtc
		self.verbose=verbose
		self.timeout=timeout
		self.type=type
		self.window=window

		if len(user):
		  if len(password):
		    self.auth_basic=[user,password]


                if len(cookie):
		  self.cookie=cookie

		if len(proxy):
		  self.proxy=proxy

                

	
		if (ex_url1.find("http://",0)==0) or (ex_url1.find("https://",0)==0):
		  self.addExcludedURL(ex_url1)
                
		if (ex_url2.find("http://",0)==0) or (ex_url2.find("https://",0)==0):
                  self.addExcludedURL(ex_url2)

		if (ex_url3.find("http://",0)==0) or (ex_url3.find("https://",0)==0):
	          self.addExcludedURL(ex_url3)


	        if (ex_url4.find("http://",0)==0) or (ex_url4.find("https://",0)==0):
	          self.addExcludedURL(ex_url4)








                
        def stop(self):
                self.timeToQuit.set()
        def run(self):
		#print "self.rooturl"+self.rooturl
                self.server=urlparse.urlparse(self.rooturl)[1]
                self.myls=lswww.lswww(self.rooturl,self.box,self.timeToQuit)
                self.myls.verbosity(self.verbose)
                socket.setdefaulttimeout(self.timeout)
		self.myls.setTimeOut(self.timeout)

                if len(self.cookie):
                  self.setCookieFile(self.cookie)
                
		if len(self.proxy):	
		  prox={'http':self.proxy}
                  self.setProxy(prox)



                self.myls.setAuthCredentials(self.auth_basic)
                
		if self.type=="GET_XSS":
                  self.setGlobal()
                  self.setGET()
                  self.setXSS()
                elif self.type=="POST_XSS":
                  self.setGlobal()
                  self.setPOST()
                  self.setXSS()
                elif self.type=="GET_ALL":
                  self.setPOST(0)

	         

                if not self.timeToQuit.isSet():
        	  self.browse()
                
		if not self.timeToQuit.isSet():
        	  self.attack()

		wx.CallAfter(self.window.update_status, "Done.")

                wx.CallAfter(self.window.show_rep)

		




	
	def browse(self):
	
               # director = urllib2.OpenerDirector()

               # director.add_handler(urllib2.HTTPHandler())
               # director.add_handler(urllib2.HTTPSHandler())

                if self.cookie!="" and cookielibhere==1:
                        cj = cookielib.LWPCookieJar()
                        if os.path.isfile(self.cookie):
                                cj.load(self.cookie,ignore_discard=True)
                                #director.add_handler(urllib2.HTTPCookieProcessor(cj))
				opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))

                if len(self.proxy):
                        #director.add_handler(urllib2.ProxyHandler(self.proxy))
			opener = urllib2.build_opener(urllib2.ProxyHandler(self.proxy))

		if self.auth_basic!=[]:
			passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
			#print self.root+" "+self.auth_basic[0]+" "+self.auth_basic[1]
			passman.add_password(None, self.root, self.auth_basic[0], self.auth_basic[1])
			#director.add_handler(urllib2.HTTPBasicAuthHandler(passman))
			opener = urllib2.build_opener(urllib2.HTTPBasicAuthHandler(passman))

                #urllib2.install_opener(director)
		try:
			if opener:
                		urllib2.install_opener(opener)
			pass
		except NameError:
			pass
		
		self.myls.go()
		if self.timeToQuit.isSet():
		  return 0
	        self.urls=self.myls.getLinks()
                if self.timeToQuit.isSet():
		  return 0
		self.forms=self.myls.getForms()


	def attack(self):
		if self.urls==[]:
		  #print "Problem scanning website !"
		  #self.box.AppendText("Problem scanning website !")
		  wx.CallAfter(self.window.write_to_box,"Problem scanning website !")


 
		  #sys.exit(1)
		  return
		if self.doGET==1:
		  #print "\nAttacking urls (GET)..."
		  #print  "-----------------------"
                  #self.box.AppendText("\nAttacking urls (GET)...\n")
		  #wx.CallAfter(self.window.write_to_box,"Attacking urls (GET)...")
		  for url in self.urls:
		    if self.timeToQuit.isSet():
		      break
		    if url.find("?")!=-1:
		      self.attackGET(url)
		if self.doPOST==1:
		  #print "\nAttacking forms (POST)..."
		  #print "-------------------------"
		  #self.box.AppendText("\nAttacking forms (POST)...\n")
		  #wx.CallAfter(self.window.write_to_box,"Attacking forms (POST)...");

		  for form in self.forms:
		    if self.timeToQuit.isSet():
		      break
		    if form[1]!={}:
		      self.attackPOST(form)
		if self.doXSS==1:
		  #print "\nLooking for permanent XSS"
		  #print "-------------------------"
		  #self.box.AppendText("\nLooking for permanent XSS\n")
		  wx.CallAfter(self.window.write_to_box,"Looking for permanent XSS")

		  for url in self.urls:
		    if self.timeToQuit.isSet():
		      break
		    self.permanentXSS(url)
		if self.myls.getUploads()!=[]:
			#print "\nUpload scripts found :"
			#print "----------------------"
			#self.box.AppendText("\nUpload scripts found:\n")
			wx.CallAfter(self.window.write_to_box,"Upload scripts found:")
			for url in self.myls.getUploads():
			        if self.timeToQuit.isSet():
				  break
				#print url
				#self.box.AppendText(url+"\n")
				wx.CallAfter(self.window.write_to_box,url+"\n")


	def setTimeOut(self,timeout=6):
		self.timeout=timeout
		self.myls.setTimeOut(self.timeout)

	def setProxy(self,proxy={}):
		self.proxy=proxy
		self.myls.setProxy(proxy)

	def addStartURL(self,url):
		self.myls.addStartURL(url)

	def addExcludedURL(self,url):
		self.myls.addExcludedURL(url)

	def setCookieFile(self,cookie):
	 	self.cookie=cookie
		self.myls.setCookieFile(cookie)

	def setAuthCredentials(self,auth_basic):
		self.auth_basic=auth_basic
		self.myls.setAuthCredentials(auth_basic)

	def addBadParam(self,bad_param):
		self.myls.addBadParam(bad_param)

	def setColor(self):
		self.color=1

	def verbosity(self,vb):
		self.verbose=vb
		self.myls.verbosity(vb)

# following set* functions can be used to create scan modes
	def setGlobal(self,var=0):
	  	"""Activate or desactivate (default) all attacks"""
		self.doGET=var
		self.doPOST=var
		self.doFileHandling=var
		self.doExec=var
		self.doInjection=var
		self.doXSS=var
		self.doCRLF=var

	def setGET(self,get=1):
		self.doGET=get

	def setPOST(self,post=1):
		self.doPOST=post

	def setFileHandling(self,fh=1):
		self.doFileHandling=fh

	def setExec(self,cmds=1):
		self.doExec=cmds

	def setInjection(self,inject=1):
		self.doInjection=inject

	def setXSS(self,xss=1):
		self.doXSS=xss

	def setCRLF(self,crlf=1):
		self.doCRLF=crlf

	def attackGET(self,url):
                wx.CallAfter(self.window.write_to_box,"Attacking urls (GET)...")
		page=url.split('?')[0]
		query=url.split('?')[1]
		params=query.split('&')
		dict={}
		if self.verbose==1:
		  #print "+ attackGET "+url
		  #print "  ",params
		  wx.CallAfter(self.window.write_to_box,"GET attacking "+url+" "+params)

		if query.find("=")>=0:
		  for param in params:
		    dict[param.split('=')[0]]=param.split('=')[1]
		if self.doFileHandling==1: self.attackFileHandling(page,dict)
		if self.doExec==1: self.attackExec(page,dict)
		if self.doInjection==1: self.attackInjection(page,dict)
		if self.doXSS==1: self.attackXSS(page,dict)
		if self.doCRLF==1: self.attackCRLF(page,dict)

	def attackPOST(self,form):
		wx.CallAfter(self.window.write_to_box,"Attacking forms (POST)...")
	  	if self.verbose==1:
		  #print "+ attackPOST "+form[0]
		  #print "  ",form[1]
	          wx.CallAfter(self.window.write_to_box,"POST attacking "+str(form[0])+" "+str(form[1]))
		if self.doFileHandling==1: self.attackFileHandling_POST(form)
		if self.doExec==1: self.attackExec_POST(form)
		if self.doInjection==1: self.attackInjection_POST(form)
		if self.doXSS==1: self.attackXSS_POST(form)

	def attackInjection(self,page,dict):
		payload="\xbf'\"("
		if dict=={}:
		  err=""
		  url=page+"?"+payload
		  if url not in self.attackedGET:
		    if self.verbose==2:
		      #print "+ "+url
                      wx.CallAfter(self.window.write_to_box,"+ "+url)
		    try:
		      req = urllib2.Request(url)
		      u = urllib2.urlopen(req)
		      data=u.read()
		    except (urllib2.URLError,socket.timeout),e:
		      if hasattr(e,'code'):
			data=""
			u = e
		      else:
			return
		    if data.find("You have an error in your SQL syntax")>=0:
		      err="MySQL Injection"
		    if data.find("supplied argument is not a valid MySQL")>0:
		      err="MySQL Injection"
		    if data.find("[Microsoft][ODBC Microsoft Access Driver]")>=0:
		      err="MSSQL Injection"
		    if data.find("java.sql.SQLException: Syntax error or access violation")>=0:
		      err="Java.SQL Injection"
		    if data.find("XPathException")>=0:
		      err="XPath Injection"
	            if data.find("supplied argument is not a valid ldap")>=0 or data.find("javax.naming.NameNotFoundException")>=0:
		      err="LDAP Injection"
		    if err!="":
		      #print err,"(QUERY_STRING) in",page
		      #print "\tEvil url:",url
		      wx.CallAfter(self.window.write_to_box_vuln,err+" (QUERY_STRING) in "+page+" Vulnerable URL:"+url)
		      self.window.findings.append(err+" (QUERY_STRING) in "+page+" Vulnerable URL:"+url)

	            else:
		      if u.code==500:
		        #print "500 HTTP Error code with"
		        #print "\tEvil url:",url
			wx.CallAfter(self.window.write_to_box_vuln,"500 HTTP Error code with Vulnerable URL: "+url)
			self.window.findings.append("500 HTTP Error code with Vulnerable URL: "+url)
		    self.attackedGET.append(url)
		else:
		  for k in dict.keys():
		    if self.timeToQuit.isSet():
		      break

		    err=""
		    tmp=dict.copy()
		    tmp[k]=payload
		    url=page+"?"+urllib.urlencode(tmp)
		    if url not in self.attackedGET:
		      if self.timeToQuit.isSet():
		        break

		      if self.verbose==2:
			#print "+ "+url
			wx.CallAfter(self.window.write_to_box,"+ "+url)
		      try:
			req = urllib2.Request(url)
			u = urllib2.urlopen(req)
			data=u.read()
		      except (urllib2.URLError,socket.timeout),e:
			if hasattr(e,'code'):
			  data=""
			  u = e
			else:
			  continue
		      if data.find("You have an error in your SQL syntax")>=0:
			err="MySQL Injection"
		      if data.find("supplied argument is not a valid MySQL")>0:
			err="MySQL Injection"
		      if data.find("[Microsoft][ODBC Microsoft Access Driver]")>=0:
			err="MSSQL Injection"
		      if data.find("java.sql.SQLException: Syntax error or access violation")>=0:
			err="Java.SQL Injection"
		      if data.find("XPathException")>=0:
		        err="XPath Injection"
		      if data.find("supplied argument is not a valid ldap")>=0 or data.find("javax.naming.NameNotFoundException")>=0:
			err="LDAP Injection"
		      if err!="":
		        if self.color==0:
		          #print err,"("+k+") in",page
		          #print "\tEvil url:",url
			  wx.CallAfter(self.window.write_to_box_vuln,err+" ("+k+") in "+page)
			  wx.CallAfter(self.window.write_to_box_vuln," Vulnerable URL: "+url)
			  self.window.findings.append(err+" ("+k+") in "+page)
			  self.window.findings.append("Vulnerable URL: "+url)
		        else:
		          print err,":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
		      else:
			if u.code==500:
			  #print "500 HTTP Error code with"
			  #print "\tEvil url:",url
		          wx.CallAfter(self.window.write_to_box_vuln,"500 HTTP Error code with Vulnerable URL"+url)
			  self.window.findings.append("500 HTTP Error code with Vulnerable URL: "+url)
		      self.attackedGET.append(url)

	def attackFileHandling(self,page,dict):
		payloads=["http://www.google.com/",
		          "/etc/passwd", "/etc/passwd\0", "c:\\\\boot.ini", "c:\\\\boot.ini\0",
		          "../../../../../../../../../../etc/passwd", # /.. is similar to / so one such payload is enough :)
		          "../../../../../../../../../../etc/passwd\0", # same with null byte
		          "../../../../../../../../../../boot.ini",
		          "../../../../../../../../../../boot.ini\0"]
		if dict=={}:
		  warn=0
		  inc=0
		  err500=0
		  for payload in payloads:
		    err=""
		    url=page+"?"+urllib.quote(payload)
		    if url not in self.attackedGET:
		      if self.timeToQuit.isSet():
		        break

		      if self.verbose==2:
			#print "+ "+url
			wx.CallAfter(self.window.write_to_box,"+ "+url)
		      self.attackedGET.append(url)
		      if inc==1: continue
		      try:
			req = urllib2.Request(url)
			u = urllib2.urlopen(req)
			data=u.read()
		      except (urllib2.URLError,socket.timeout),e:
			if hasattr(e,'code'):
			  data=""
			  u = e
			else:
			  continue
		      if data.find("root:x:0:0")>=0:
			err="Unix include/fread"
		        inc=1
		      if data.find("[boot loader]")>=0:
		        err="Windows include/fread"
		        inc=1
		      if data.find("<title>Google</title>")>0:
		        err="Remote include"
		        inc=1
		      if data.find("java.io.FileNotFoundException:")>=0 and warn==0:
		        err="Warning Java include/open"
		        warn=1
		      if data.find("fread(): supplied argument is not")>0 and warn==0:
		        err="Warning fread"
		        warn=1
		      if data.find("for inclusion (include_path=")>0 and warn==0:
		        err="Warning include"
		        warn=1
                      if data.find("Failed opening required")>=0 and warn==0:
                        err="Warning require"
                        warn=1
		      if data.find("<b>Warning</b>:  file(")>=0 and warn==0:
			err="Warning file()"
			warn=1
		      if data.find("<b>Warning</b>:  file_get_contents(")>=0:
			err="Warning file_get_contents()"
			warn=1
		      if err!="":
			#print err,"(QUERY_STRING) in",page
			#print "\tEvil url:",url
			wx.CallAfter(self.window.write_to_box_vuln,err+" (QUERY_STRING) in "+page)
			wx.CallAfter(self.window.write_to_box_vuln,"Vulnerable URL: "+url)
			self.window.findings.append(err+" (QUERY_STRING) in "+page)
			self.window.findings.append("Vulnerable URL: "+url)
		      else:
			if u.code==500 and err500==0:
			  err500=1
			  #print "500 HTTP Error code with"
			  #print "\tEvil url:",url
			  wx.CallAfter(self.window.write_to_box_vuln,"500 HTTP Error code with Vulnerable URL: "+url)
			  self.window.findings.append("500 HTTP Error code with Vulnerable URL: "+url)
		for k in dict.keys():
		  warn=0
		  inc=0
		  err500=0
		  for payload in payloads:
		    err=""
		    tmp=dict.copy()
		    tmp[k]=payload
		    url=page+"?"+urllib.urlencode(tmp)
		    if url not in self.attackedGET:
		      if self.timeToQuit.isSet():
		        break

		      if self.verbose==2:
			#print "+ "+url
			wx.CallAfter(self.window.write_to_box,"+ "+url)
		      self.attackedGET.append(url)
		      if inc==1: continue
		      try:
			req = urllib2.Request(url)
			u = urllib2.urlopen(req)
			data=u.read()
		      except (urllib2.URLError,socket.timeout),e:
			if hasattr(e,'code'):
			  data=""
			  u = e
			else:
			  continue
		      if data.find("root:x:0:0")>=0:
			err="Unix include/fread"
		        inc=1
		      if data.find("[boot loader]")>=0:
		        err="Windows include/fread"
		        inc=1
		      if data.find("<title>Google</title>")>0:
		        err="Remote include"
		        inc=1
		      if data.find("java.io.FileNotFoundException:")>=0 and warn==0:
		        err="Warning Java include/open"
		        warn=1
		      if data.find("fread(): supplied argument is not")>0 and warn==0:
		        err="Warning fread"
		        warn=1
		      if data.find("for inclusion (include_path=")>0 and warn==0:
		        err="Warning include"
		        warn=1
                      if data.find("Failed opening required")>=0 and warn==0:
                        err="Warning require"
                        warn=1
		      if data.find("<b>Warning</b>:  file(")>=0 and warn==0:
			err="Warning file()"
			warn=1
		      if data.find("<b>Warning</b>:  file_get_contents(")>=0:
			err="Warning file_get_contents()"
			warn=1
		      if err!="":
		        if self.color==0:
		          #print err,"("+k+") in",page
		          #print "\tEvil url:",url
			  wx.CallAfter(self.window.write_to_box_vuln,err+" ("+k+") in "+page)
			  wx.CallAfter(self.window.write_to_box_vuln,"Vulnerable URL: "+url)
			  self.window.findings.append(err+" ("+k+") in "+page)
			  self.window.findings.append("Vulnerable URL: "+url)
		        else:
		          print err,":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
		      else:
			if u.code==500 and err500==0:
			  err500=1
			  #print "500 HTTP Error code with"
			  #print "\tEvil url:",url
			  wx.CallAfter(self.window.write_to_box_vuln,"500 HTTP Error code with Vulnerable URL: "+url)
			  self.window.findings.append("500 HTTP Error code with Vulnerable URL: "+url)

	def attackXSS(self,page,dict):
		if dict=={}:
		  err=""
		  payload="<script>var pf_"
		  payload+=page.encode("hex_codec")
		  payload+="_"
		  payload+="QUERYSTRING".encode("hex_codec")
		  payload+="=new Boolean();</script>"
		  url=page+"?"+payload
		  if url not in self.attackedGET:
		    try:
		      if self.verbose==2:
			#print "+ "+url
			wx.CallAfter(self.window.write_to_box,"+ "+url)
		      req = urllib2.Request(url)
		      u = urllib2.urlopen(req)
		      data=u.read()
		    except (urllib2.URLError,socket.timeout),e:
		      if hasattr(e,'code'):
			data=""
			u = e
		      else:
			return
		    if data.find(payload)>=0:
		      #print "XSS (QUERY_STRING) in",page
		      #print "\tEvil url:",url
		      wx.CallAfter(self.window.write_to_box_vuln,"XSS (QUERY_STRING) in "+page+" Evil url: "+url)
		      self.window.findings.append("XSS (QUERY_STRING) in "+page+" Evil url: "+url)
	            else:
		      if u.code==500:
			#print "500 HTTP Error code with"
			#print "\tEvil url:",url
			wx.CallAfter(self.window.write_to_box_vuln,"500 HTTP Error code with Vulnerable URL: "+url)
			self.window.findings.append("500 HTTP Error code with Vulnerable URL: "+url)

		    self.attackedGET.append(url)
		for k in dict.keys():
		  if self.timeToQuit.isSet():
		    break

		  err=""
		  tmp=dict.copy()
		  payload="<script>var pf_"
		  payload+=page.encode("hex_codec")
		  payload+="_"
		  payload+=k.encode("hex_codec")
		  payload+="=new Boolean();</script>"
		  tmp[k]=payload
		  url=page+"?"+urllib.unquote(urllib.urlencode(tmp))
		  if url not in self.attackedGET:
		    if self.verbose==2:
		      #print "+ "+url
		      wx.CallAfter(self.window.write_to_box,"+ "+url)
		    try:
		      req = urllib2.Request(url)
		      u = urllib2.urlopen(req)
		      data=u.read()
		    except (urllib2.URLError,socket.timeout),e:
		      if hasattr(e,'code'):
			data=""
			u = e
		      else:
			continue
		    if data.find(payload)>=0:
		      if self.color==0:
		        #print "XSS ("+k+") in",page
		        #print "\tEvil url:",url
			wx.CallAfter(self.window.write_to_box_vuln,"XSS ("+k+") in "+page)
			wx.CallAfter(self.window.write_to_box_vuln,"Vulnerable URL: "+url)
			self.window.findings.append("XSS ("+k+") in "+page)
			self.window.findings.append("Vulnerable URL: "+url)
		      else:
		        print "XSS",":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
	            else:
		      if u.code==500:
			#print "500 HTTP Error code with"
			#print "\tEvil url:",url
			wx.CallAfter(self.window.write_to_box_vuln,"500 HTTP Error code with Vulnerable URL: "+url)
			self.window.findings.append("500 HTTP Error code with Vulnerable URL: "+url)

		    self.attackedGET.append(url)

	def attackExec(self,page,dict):
		payloads=["a;env",
		          "a);env",
			  "/e\0"]
		if dict=={}:
		  warn=0
		  cmd=0
		  err500=0
		  for payload in payloads:
		    err=""
		    url=page+"?"+urllib.quote(payload)
		    if url not in self.attackedGET:
		      if self.verbose==2:
			#print "+ "+url
			wx.CallAfter(self.window.write_to_box,"+ "+url)
		      self.attackedGET.append(url)
		      if cmd==1: continue
		      try:
			req = urllib2.Request(url)
			u = urllib2.urlopen(req)
			data=u.read()
		      except (urllib2.URLError,socket.timeout),e:
			if hasattr(e,'code'):
			  data=""
			  u = e
			else:
			  return
		      if data.find("eval()'d code</b> on line <b>")>=0 and warn==0:
			err="Warning eval()"
		        warn=1
		      if data.find("PATH=")>=0 and data.find("PWD=")>=0:
		        err="Command execution"
		        cmd=1
		      if data.find("Cannot execute a blank command in")>=0 and warn==0:
		        err="Warning exec"
		        warn=1
		      if data.find("Fatal error</b>:  preg_replace")>=0 and warn==0:
			err="preg_replace injection"
			warn=1
		      if err!="":
			#print err,"(QUERY_STRING) in",page
			#print "\tEvil url:",url
			wx.CallAfter(self.window.write_to_box_vuln,err+" (QUERY_STRING) in "+page)
			wx.CallAfter(self.window.write_to_box_vuln,"Vulnerable URL: "+url)
			self.window.findings.append(err+" (QUERY_STRING) in "+page)
			self.window.findings.append("Vulnerable URL: "+url)
		      else:
			if u.code==500 and err500==0:
			  err500=1
			  #print "500 HTTP Error code with"
			  #print "\tEvil url:",url
			  wx.CallAfter(self.window.write_to_box_vuln,"500 HTTP Error code with Vulnerable URL: "+url)
			  self.window.findings.append("500 HTTP Error code with Vulnerable URL: "+url)


		for k in dict.keys():
		  if self.timeToQuit.isSet():
		    break

		  warn=0
		  cmd=0
		  err500=0
		  for payload in payloads:
		    err=""
		    tmp=dict.copy()
		    tmp[k]=payload
		    url=page+"?"+urllib.urlencode(tmp)
		    if url not in self.attackedGET:
		      if self.verbose==2:
			#print "+ "+url
			wx.CallAfter(self.window.write_to_box,"+ "+url)
		      self.attackedGET.append(url)
		      if cmd==1: continue
		      try:
			req = urllib2.Request(url)
			u = urllib2.urlopen(req)
			data=u.read()
		      except (urllib2.URLError,socket.timeout),e:
			if hasattr(e,'code'):
			  data=""
			  u = e
			else:
			  continue
		      if data.find("eval()'d code</b> on line <b>")>=0 and warn==0:
			err="Warning eval()"
		        warn=1
		      if data.find("PATH=")>=0 and data.find("PWD=")>=0:
		        err="Command execution"
		        cmd=1
		      if data.find("Cannot execute a blank command in")>0 and warn==0:
		        err="Warning exec"
		        warn=1
		      if data.find("Fatal error</b>:  preg_replace")>=0 and warn==0:
			err="preg_replace injection"
			warn=1
		      if err!="":
		        if self.color==0:
		          #print err,"("+k+") in",page
		          #print "\tEvil url:",url
			  wx.CallAfter(self.window.write_to_box_vuln,err+" ("+k+") in "+page)
			  wx.CallAfter(self.window.write_to_box_vuln,"Vulnerable URL: "+url)
			  self.window.findings.append(err+" ("+k+") in "+page)
			  self.window.findins.append("Vulnerable URL: "+url)
		        else:
		          print err,":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
		      else:
			if u.code==500 and err500==0:
			  err500=1
			  #print "500 HTTP Error code with"
			  #print "\tEvil url:",url
			  wx.CallAfter(self.window.write_to_box_vuln,"500 HTTP Error code with Vulnerable URL"+url)
			  self.window.findings.append("500 HTTP Error code with Vulnerable URL"+url)
			   

	# Won't work with PHP >= 4.4.2
	def attackCRLF(self,page,dict):
		payload="http://www.google.com\r\nPowerfuzzer: "+version
		if dict=={}:
		  err=""
		  url=page+"?"+payload
		  if url not in self.attackedGET:
		    if self.verbose==2:
		      #print "+ "+url
		      wx.CallAfter(self.window.write_to_box,"+ "+url)
		    try:
		      req = urllib2.Request(url)
		      u = urllib2.urlopen(req)
		      if u.info().has_key('Powerfuzzer'):
			err="CRLF Injection"
		    except (urllib2.URLError,socket.timeout):
		      err=""
		    if err!="":
		      #print err,"(QUERY_STRING) in",page
		      #print "\tEvil url:",url
		      wx.CallAfter(self.window.write_to_box_vuln,err+ "(QUERY_STRING) in "+page)
		      wx.CallAfter(self.window.write_to_box_vuln,"Vulnerable URL: "+url)
		      self.window.findings.append(err+ "(QUERY_STRING) in "+page)
		      self.window.findings.append("Vulnerable URL: "+url)
		    self.attackedGET.append(url)
		else:
		  for k in dict.keys():
		    if self.timeToQuit.isSet():
		      break

		    err=""
		    tmp=dict.copy()
		    tmp[k]=payload
		    url=page+"?"+urllib.urlencode(tmp)
		    if url not in self.attackedGET:
		      if self.verbose==2:
			#print "+ "+url
			wx.CallAfter(self.window.write_to_box,"+ "+url)

		      try:
			req = urllib2.Request(url)
			u = urllib2.urlopen(req)
			if u.info().has_key('Powerfuzzer'):
			  err="CRLF Injection"
		      except (urllib2.URLError,socket.timeout):
			err=""
		      if err!="":
		        if self.color==0:
		          #print err,"("+k+") in",page
		          #print "\tEvil url:",url
			  wx.CallAfter(self.window.write_to_box_vuln,err+" ("+k+") i "+page)
			  wx.CallAfter(self.window.write_to_box_vuln,"Vulnerable URL :"+url)
			  self.window.findings.append(err+" ("+k+") i "+page)
			  self.window.findings.append("Vulnerable URL :"+url)
		        else:
		          print err,":",url.replace(k+"=","\033[0;31m"+k+"\033[0;0m=")
		      self.attackedGET.append(url)

	def attackInjection_POST(self,form):
		payload="\xbf'\"("
		page=form[0]
		dict=form[1]
		err=""
		for k in dict.keys():
		  if self.timeToQuit.isSet():
		    break

		  tmp=dict.copy()
		  tmp[k]=payload
		  if (page,tmp) not in self.attackedPOST:
		    headers={"Accept": "text/plain"}
		    if self.verbose==2:
		      #print "+ "+page
		      #print "  ",tmp
		      wx.CallAfter(self.window.write_to_box,"+ "+page)
		      wx.CallAfter(self.window.write_dic_to_box,tmp)
		    try:
		      req = urllib2.Request(page,urllib.urlencode(tmp),headers)
		      u = urllib2.urlopen(req)
		      data=u.read()
		    except (urllib2.URLError,socket.timeout),e:
		      if hasattr(e,'code'):
			data=""
			u = e
		      else:
			continue
		    if data.find("You have an error in your SQL syntax")>=0:
		      err="MySQL Injection"
		    if data.find("supplied argument is not a valid MySQL")>0:
		      err="MySQL Injection"
		    if data.find("[Microsoft][ODBC Microsoft Access Driver]")>=0:
		      err="MSSQL Injection"
		    if data.find("java.sql.SQLException: Syntax error or access violation")>=0:
		      err="SQL Injection"
		    if data.find("XPathException")>=0:
		      err="XPath Injection"
		    if data.find("supplied argument is not a valid ldap")>=0 or data.find("javax.naming.NameNotFoundException")>=0:
		      err="LDAP Injection"
		    if err!="":
		      #print err,"in",page
		      #print "  with params =",urllib.urlencode(tmp)
		      #print "  coming from",form[2]
		      wx.CallAfter(self.window.write_to_box_vuln,err+" in "+page)
		      wx.CallAfter(self.window.write_to_box_vuln," with params ="+urllib.urlencode(tmp))
		      wx.CallAfter(self.window.write_to_box_vuln," coming from"+form[2])
                      self.window.findings.append(err+" in "+page)
		      self.window.findings.append(" with params ="+urllib.urlencode(tmp))
		      self.window.findings.append(" coming from"+form[2])
	            else:
		      if u.code==500:
			#print "500 HTTP Error code in",page
			#print "  with params =",urllib.urlencode(tmp)
			#print "  coming from",form[2]
			wx.CallAfter(self.window.write_to_box_vuln,"500 HTTP Error code in "+page)
			wx.CallAfter(self.window.write_to_box_vuln,"  with params ="+urllib.urlencode(tmp))
			wx.CallAfter(self.window.write_to_box_vuln," coming from"+form[2])
			self.window.findings.append("500 HTTP Error code in "+page)
			self.window.findings.append("  with params ="+urllib.urlencode(tmp))
			self.window.findings.append(" coming from"+form[2])

	def attackFileHandling_POST(self,form):
		payloads=["http://www.google.com/",
		          "/etc/passwd", "/etc/passwd\0", "c:\\\\boot.ini", "c:\\\\boot.ini\0",
		          "../../../../../../../../../../etc/passwd", # /.. is similar to / so one such payload is enough :)
		          "../../../../../../../../../../etc/passwd\0", # same with null byte
		          "../../../../../../../../../../boot.ini",
		          "../../../../../../../../../../boot.ini\0"]
		page=form[0]
		dict=form[1]
		err=""
		for payload in payloads:
                  warn=0
                  inc=0
		  err500=0
		  for k in dict.keys():
		    if self.timeToQuit.isSet():
		      break

		    tmp=dict.copy()
		    tmp[k]=payload
		    if (page,tmp) not in self.attackedPOST:
		      self.attackedPOST.append((page,tmp))
		      if inc==1: continue
		      headers={"Accept": "text/plain"}
		      if self.verbose==2:
			#print "+ "+page
			#print "  ",tmp
			wx.CallAfter(self.window.write_to_box,"+ "+page)
			wx.CallAfter(self.window.write_dic_to_box,tmp)
			
		      try:
			req = urllib2.Request(page,urllib.urlencode(tmp),headers)
			u = urllib2.urlopen(req)
			data=u.read()
		      except (urllib2.URLError,socket.timeout),e:
			if hasattr(e,'code'):
			  data=""
			  u = e
			else:
			  continue
		      if data.find("root:x:0:0")>=0:
			err="Unix include/fread"
		        inc=1
		      if data.find("[boot loader]")>=0:
		        err="Windows include/fread"
		        inc=1
		      if data.find("<title>Google</title>")>0:
		        err="Remote include"
		        inc=1
		      if data.find("java.io.FileNotFoundException:")>=0 and warn==0:
		        err="Warning Java include/open"
		        warn=1
		      if data.find("fread(): supplied argument is not")>0 and warn==0:
		        err="Warning fread"
		        warn=1
		      if data.find("for inclusion (include_path=")>0 and warn==0:
		        err="Warning include"
		        warn=1
                      if data.find("Failed opening required")>=0 and warn==0:
                        err="Warning require"
                        warn=1
		      if data.find("<b>Warning</b>:  file(")>=0 and warn==0:
			err="Warning file()"
			warn=1
		      if data.find("<b>Warning</b>:  file_get_contents(")>=0:
			err="Warning file_get_contents()"
			warn=1
		      if err!="":
			#print err,"in",page
			#print "  with params =",urllib.urlencode(tmp)
			#print "  coming from",form[2]
			wx.CallAfter(self.window.write_to_box_vuln,err+" in "+page)
			wx.CallAfter(self.window.write_to_box_vuln,"  with params ="+urllib.urlencode(tmp))
			wx.CallAfter(self.window.write_to_box_vuln,"  coming from"+form[2])
			self.window.findings.append(err+" in "+page)
			self.window.findings.append("  with params ="+urllib.urlencode(tmp))
			self.window.findings.append("  coming from"+form[2])
		      else:
			if u.code==500 and err500==0:
			  err500=1
			  #print "500 HTTP Error code in",page
			  #print "  with params =",urllib.urlencode(tmp)
			  #print "  coming from",form[2]
			  wx.CallAfter(self.window.write_to_box_vuln,"500 HTTP Error code in"+page)
			  wx.CallAfter(self.window.write_to_box_vuln," with params ="+urllib.urlencode(tmp))
			  wx.CallAfter(self.window.write_to_box_vuln,"  coming from"+form[2])
			  self.window.findings.append("500 HTTP Error code in"+page)
			  self.window.findings.append(" with params ="+urllib.urlencode(tmp))
			  self.window.findings.append("  coming from "+form[2])

	def attackXSS_POST(self,form):
		page=form[0]
		dict=form[1]
		for k in dict.keys():
		  if self.timeToQuit.isSet():
		    break

		  tmp=dict.copy()
		  payload="<script>var pf_"
		  payload+=page.encode("hex_codec")
		  payload+="_"
		  payload+=k.encode("hex_codec")
		  payload+="=new Boolean();</script>"
		  tmp[k]=payload
		  if (page,tmp) not in self.attackedPOST:
		    headers={"Accept": "text/plain"}
		    if self.verbose==2:
		      #print "+ "+page
		      #print "  ",tmp
		      wx.CallAfter(self.window.write_to_box,"+ "+page)
		      wx.CallAfter(self.window.write_dic_to_box,tmp)
		    try:
		      req = urllib2.Request(page,urllib.unquote(urllib.urlencode(tmp)),headers)
		      u = urllib2.urlopen(req)
		      data=u.read()
		    except (urllib2.URLError,socket.timeout),e:
		      if hasattr(e,'code'):
			data=""
			u = e
		      else:
			continue
		    if data.find(payload)>=0:
		      #print "XSS in",page
		      #print "  with params =",urllib.urlencode(tmp)
		      #print "  coming from",form[2]
		      wx.CallAfter(self.window.write_to_box_vuln,"XSS in "+page)
		      wx.CallAfter(self.window.write_to_box_vuln,"  with params ="+urllib.urlencode(tmp))
		      wx.CallAfter(self.window.write_to_box_vuln,"  coming from "+form[2])
		      self.window.findings.append("XSS in "+page)
		      self.window.findings.append("  with params ="+urllib.urlencode(tmp))
		      self.window.findings.append("  coming from"+form[2])
	            else:
		      if u.code==500:
			#print "500 HTTP Error code in",page
			#print "  with params =",urllib.urlencode(tmp)
			#print "  coming from",form[2]
			wx.CallAfter(self.window.write_to_box_vuln,"500 HTTP Error code in "+page)
			wx.CallAfter(self.window.write_to_box_vuln,"  with params ="+urllib.urlencode(tmp))
			wx.CallAfter(self.window.write_to_box_vuln,"  coming from "+form[2])
			self.window.findings.append("500 HTTP Error code in "+page)
			self.window.findings.append("  with params ="+urllib.urlencode(tmp))
			self.window.findings.append("  coming from "+form[2])
		    self.attackedPOST.append((page,tmp))

	def attackExec_POST(self,form):
		payloads=["a;env",
		          "a);env",
			  "/e\0"]
		page=form[0]
		dict=form[1]
		err=""
		for payload in payloads:
                  warn=0
                  cmd=0
		  err500=0
		  for k in dict.keys():
		    if self.timeToQuit.isSet():
		      break

		    tmp=dict.copy()
		    tmp[k]=payload
		    if (page,tmp) not in self.attackedPOST:
		      self.attackedPOST.append((page,tmp))
		      if cmd==1: continue
		      headers={"Accept": "text/plain"}
		      if self.verbose==2:
			#print "+ "+page
			#print "  ",tmp
			wx.CallAfter(self.window.write_to_box,"+ "+page)
			wx.CallAfter(self.window.write_dic_to_box,tmp)
		      try:
			req = urllib2.Request(page,urllib.urlencode(tmp),headers)
			u = urllib2.urlopen(req)
			data=u.read()
		      except (urllib2.URLError,socket.timeout),e:
			if hasattr(e,'code'):
			  data=""
			  u = e
			else:
			  continue
		      if data.find("eval()'d code</b> on line <b>")>=0 and warn==0:
			err="Warning eval()"
		        warn=1
		      if data.find("PATH=")>=0 and data.find("PWD=")>=0:
		        err="Command execution"
		        cmd=1
		      if data.find("Cannot execute a blank command in")>0 and warn==0:
		        err="Warning exec"
		        warn=1
		      if data.find("Fatal error</b>:  preg_replace")>=0 and warn==0:
			err="preg_replace injection"
			warn=1
		      if err!="":
			#print err,"in",page
			#print "  with params =",urllib.urlencode(tmp)
			#print "  coming from",form[2]
			wx.CallAfter(self.window.write_to_box_vuln,err+" in "+page);
			wx.CallAfter(self.window.write_to_box_vuln,"  with params ="+urllib.urlencode(tmp))
			wx.CallAfter(self.window.write_to_box_vuln,"  coming from "+form[2])
			self.window.findings.append(err+" in "+page)
			self.window.findings.append("  with params ="+urllib.urlencode(tmp))
			self.window.findings.append("  coming from "+form[2])
		      else:
			if u.code==500 and err500==0:
			  err500=1
			  #print "500 HTTP Error code in",page
			  #print "  with params =",urllib.urlencode(tmp)
			  #print "  coming from",form[2]
			  wx.CallAfter(self.window.write_to_box_vuln,"500 HTTP Error code in "+page)
			  wx.CallAfter(self.window.write_to_box_vuln,"  with params ="+urllib.urlencode(tmp))
			  wx.CallAfter(self.window.write_to_box_vuln,"  coming from "+form[2])
			  self.window.findings.append("500 HTTP Error code in "+page)
			  self.window.findings.append("  with params ="+urllib.urlencode(tmp))
			  self.window.findings.append("  coming from "+form[2])

	def permanentXSS(self,url):
		try:
		  req = urllib2.Request(url)
		  u = urllib2.urlopen(req)
		  data=u.read()
		except (urllib2.URLError,socket.timeout):
		  data=""
		p=re.compile("<script>var pf_[0-9a-h]+_[0-9a-h]+=new Boolean\(\);</script>")
		for s in p.findall(data):
		  if self.timeToQuit.isSet():
		    break

		  s=s.split("=")[0].split('_')[1:]
		  #print "Found permanent XSS in",url
		  #print "  attacked by",s[0].decode("hex_codec"),"with field",s[1].decode("hex_codec")
		  wx.CallAfter(self.window.write_to_box_vuln,"Found permanent XSS in "+url)
		  wx.CallAfter(self.window.write_to_box_vuln,"  attacked by "+s[0].decode("hex_codec")+" with field "+s[1].decode("hex_codec"))
		  self.window.findings.append("Found permanent XSS in "+url)
		  self.window.findings.append("  attacked by "+s[0].decode("hex_codec")+" with field "+s[1].decode("hex_codec"))



class MyFrame(wx.Frame):
    def __init__(self, *args, **kwds):

	self.AddRTCHandlers()

        self.go_on=1
        self.threads = []
        self.count = 0

        self.group1_ctrls = []
        self.group2_ctrls = []
        self.URL=""


        self.c1=""
        self.c2=""
        self.c3=""

        self.user=""
        self.password=""

        self.cookie=""

        self.proxy=""

        self.timeout=6

        self.verbose=2
        self.type=""



        self.ex_url1=""
        self.ex_url2=""
        self.ex_url3=""
        self.ex_url4=""

	self.findings=[]


        # begin wxGlade: MyFrame.__init__
        kwds["style"] = wx.DEFAULT_FRAME_STYLE
        wx.Frame.__init__(self, *args, **kwds)

        # Menu Bar
        self.frame_1_menubar = wx.MenuBar()
        wxglade_tmp_menu = wx.Menu()
        wxglade_tmp_menu.Append(ID_ABOUT, "&About")
        wxglade_tmp_menu.Append(ID_EXIT,"E&xit")
	self.frame_1_menubar.Append(wxglade_tmp_menu, "&File")
        self.SetMenuBar(self.frame_1_menubar)


        # Menu Bar end
        self.frame_1_statusbar = self.CreateStatusBar(1, 0)

        # Tool Bar
        self.frame_1_toolbar = wx.ToolBar(self, -1)
        self.SetToolBar(self.frame_1_toolbar)
        # Tool Bar end
        #self.text_ctrl_2 = wx.TextCtrl(self, -1, "", style=wx.TE_PROCESS_ENTER|wx.TE_PROCESS_TAB|wx.TE_MULTILINE|wx.HSCROLL)
        self.rtc = rt.RichTextCtrl(self, style=wx.VSCROLL|wx.HSCROLL);
        wx.CallAfter(self.rtc.SetFocus)




        self.label_2 = wx.StaticText(self, -1, "Credentials")
        self.label_4 = wx.StaticText(self, -1, "User")
        self.text_ctrl_3 = wx.TextCtrl(self, -1, "")
        self.label_5 = wx.StaticText(self, -1, "Password")
        self.text_ctrl_4 = wx.TextCtrl(self, -1, "")
        #self.label_3 = wx.StaticText(self, -1, "Only Perform checks")

        #self.radio_btn_4 = wx.RadioButton(self, -1, "GET", style = wx.RB_GROUP)
        #self.radio_btn_5 = wx.RadioButton(self, -1, "GET XSS")
        #self.radio_btn_6 = wx.RadioButton(self, -1, "POST XSS")
        #self.group2_ctrls.append((self.radio_btn_4))
        #self.group2_ctrls.append((self.radio_btn_5))
        #self.group2_ctrls.append((self.radio_btn_6))
        self.label_6 = wx.StaticText(self, -1, "Verbosity")
        self.radio_btn_1 = wx.RadioButton(self, -1, "Low",  style = wx.RB_GROUP)
        self.radio_btn_2 = wx.RadioButton(self, -1, "Medium")
        self.radio_btn_3 = wx.RadioButton(self, -1, "High")
        self.group1_ctrls.append((self.radio_btn_1))
        self.group1_ctrls.append((self.radio_btn_2))
        self.group1_ctrls.append((self.radio_btn_3))

        #self.label_1 = wx.StaticText(self, -1, "Cookie")
        #self.text_ctrl_1 = wx.TextCtrl(self, -1, "")
	self.fbb = filebrowse.FileBrowseButton(self, -1, labelText='',buttonText='Cookie')
        self.label_10 = wx.StaticText(self, -1, "Target URL")
        self.label_8 = wx.StaticText(self, -1, "Proxy")
        self.text_ctrl_9 = wx.TextCtrl(self, -1, "")
        self.text_ctrl_10 = wx.TextCtrl(self, -1, "")
        self.label_9 = wx.StaticText(self, -1, "Timeout")
        self.spin_ctrl_1 = wx.SpinCtrl(self, -1, "5", min=0, max=100)
        self.button_1 = wx.Button(self, -1, "Scan")
        self.button_2 = wx.Button(self, -1, "Stop")

        self.label_7 = wx.StaticText(self, -1, "Exclude URL(s) or dir", style=wx.ALIGN_CENTRE)
        self.text_ctrl_5 = wx.TextCtrl(self, -1, "")
        self.text_ctrl_6 = wx.TextCtrl(self, -1, "")
        self.text_ctrl_7 = wx.TextCtrl(self, -1, "")
        self.text_ctrl_8 = wx.TextCtrl(self, -1, "")

        self.Bind(wx.EVT_BUTTON, self.do_Scan, self.button_1)
        self.Bind(wx.EVT_BUTTON, self.do_Stop, self.button_2)
	self.Bind(wx.EVT_MENU, self.MenuExit, id=ID_EXIT)
	self.Bind(wx.EVT_MENU, self.MenuAbout, id=ID_ABOUT)


        for radio in self.group1_ctrls:
            self.Bind(wx.EVT_RADIOBUTTON, self.OnGroup1Select, radio )
            radio.SetValue(0)
        #for radio in self.group2_ctrls:
        #    self.Bind(wx.EVT_RADIOBUTTON, self.OnGroup2Select, radio )
        #    radio.SetValue(0)
          
         
        self.radio_btn_3.SetValue(1)
       
        self.__set_properties()
        self.__do_layout()
        # end wxGlade


    def __set_properties(self):
        # begin wxGlade: MyFrame.__set_properties
        self.SetTitle("Powerfuzzer "+version)
        self.SetSize((800, 700))
        self.SetBackgroundColour(wx.SystemSettings_GetColour(wx.SYS_COLOUR_3DFACE))
        self.SetFont(wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "MS Shell Dlg 2"))
        self.frame_1_statusbar.SetStatusWidths([-1])
        # statusbar fields
        frame_1_statusbar_fields = ["Ready"]
        for i in range(len(frame_1_statusbar_fields)):
            self.frame_1_statusbar.SetStatusText(frame_1_statusbar_fields[i], i)
        self.frame_1_toolbar.Realize()
        #self.text_ctrl_2.SetMinSize((800, 150))
        self.rtc.SetMinSize((800,300))
        self.text_ctrl_10.SetMinSize((200, 21))
        self.text_ctrl_5.SetMinSize((200, 21))
        self.text_ctrl_6.SetMinSize((200, 21))
        self.text_ctrl_7.SetMinSize((200, 21))
        self.text_ctrl_8.SetMinSize((200, 21))
        # end wxGlade

    def __do_layout(self):
        # begin wxGlade: MyFrame.__do_layout
        sizer_1 = wx.BoxSizer(wx.VERTICAL)
        sizer_3 = wx.BoxSizer(wx.VERTICAL)
        grid_sizer_7 = wx.GridSizer(3, 3, 0, 0)
        grid_sizer_6 = wx.GridSizer(3, 3, 0, 0)
        grid_sizer_1 = wx.GridSizer(3, 3, 0, 0)
        grid_sizer_9 = wx.GridSizer(3, 3, 0, 0)
        grid_sizer_8 = wx.GridSizer(3, 3, 0, 0)
        grid_sizer_2 = wx.GridSizer(3, 3, 0, 0)
        grid_sizer_5 = wx.GridSizer(3, 3, 0, 0)
        grid_sizer_4 = wx.GridSizer(3, 3, 0, 0)
        sizer_2 = wx.BoxSizer(wx.HORIZONTAL)
        grid_sizer_3 = wx.GridSizer(3, 3, 0, 0)
        sizer_1.Add(self.rtc, 0, wx.EXPAND, 0)
        grid_sizer_3.Add(self.label_2, 0, 0, 0)
        grid_sizer_3.Add((20, 20), 0, 0, 0)
        grid_sizer_3.Add((20, 20), 0, 0, 0)
        grid_sizer_3.Add(self.label_4, 0, 0, 0)
        grid_sizer_3.Add(self.text_ctrl_3, 0, 0, 0)
        grid_sizer_3.Add((20, 20), 0, 0, 0)
        grid_sizer_3.Add(self.label_5, 0, 0, 0)
        grid_sizer_3.Add(self.text_ctrl_4, 0, 0, 0)
        grid_sizer_3.Add((20, 20), 0, 0, 0)
        sizer_2.Add(grid_sizer_3, 1, wx.EXPAND, 0)
        grid_sizer_1.Add(sizer_2, 1, wx.EXPAND, 0)
        #grid_sizer_4.Add(self.label_3, 0, 0, 0)
        grid_sizer_4.Add((20, 20), 0, 0, 0)
        grid_sizer_4.Add((20, 20), 0, 0, 0)
        #grid_sizer_4.Add(self.radio_btn_4, 0, 0, 0)
        #grid_sizer_4.Add(self.radio_btn_5, 0, 0, 0)
        #grid_sizer_4.Add(self.radio_btn_6, 0, 0, 0)
        grid_sizer_4.Add((20, 20), 0, 0, 0)
        grid_sizer_4.Add((20, 20), 0, 0, 0)
        grid_sizer_4.Add((20, 20), 0, 0, 0)
        grid_sizer_1.Add(grid_sizer_4, 1, wx.EXPAND, 0)
        grid_sizer_5.Add(self.label_6, 0, 0, 0)
        grid_sizer_5.Add((20, 20), 0, 0, 0)
        grid_sizer_5.Add((20, 20), 0, 0, 0)
        grid_sizer_5.Add(self.radio_btn_1, 0, 0, 0)
        grid_sizer_5.Add(self.radio_btn_2, 0, 0, 0)
        grid_sizer_5.Add(self.radio_btn_3, 0, 0, 0)
        grid_sizer_5.Add((20, 20), 0, 0, 0)
        grid_sizer_5.Add((20, 20), 0, 0, 0)
        grid_sizer_5.Add((20, 20), 0, 0, 0)
        grid_sizer_1.Add(grid_sizer_5, 1, wx.EXPAND, 0)
        #grid_sizer_2.Add(self.label_1, 0, 0, 0)
        grid_sizer_2.Add(self.fbb, 0, 0, 0)
        grid_sizer_2.Add((20, 20), 0, 0, 0)
        grid_sizer_2.Add((20, 20), 0, 0, 0)
        grid_sizer_2.Add((20, 20), 0, 0, 0)
        grid_sizer_2.Add((20, 20), 0, 0, 0)
        grid_sizer_2.Add((20, 20), 0, 0, 0)
        grid_sizer_2.Add((20, 20), 0, 0, 0)
        grid_sizer_2.Add(self.label_10, 0, 0, 0)
        grid_sizer_1.Add(grid_sizer_2, 1, wx.EXPAND, 0)
        grid_sizer_8.Add(self.label_8, 0, 0, 0)
        grid_sizer_8.Add(self.text_ctrl_9, 0, 0, 0)
        grid_sizer_8.Add((20, 20), 0, 0, 0)
        grid_sizer_8.Add((20, 20), 0, 0, 0)
        grid_sizer_8.Add((20, 20), 0, 0, 0)
        grid_sizer_8.Add((20, 20), 0, 0, 0)
        grid_sizer_8.Add((20, 20), 0, 0, 0)
        grid_sizer_8.Add(self.text_ctrl_10, 0, 0, 0)
        grid_sizer_8.Add((20, 20), 0, 0, 0)
        grid_sizer_1.Add(grid_sizer_8, 1, wx.EXPAND, 0)
        grid_sizer_9.Add(self.label_9, 0, 0, 0)
        grid_sizer_9.Add(self.spin_ctrl_1, 0, 0, 0)
        grid_sizer_9.Add((20, 20), 0, 0, 0)
        grid_sizer_9.Add((20, 20), 0, 0, 0)
        grid_sizer_9.Add((20, 20), 0, 0, 0)
        grid_sizer_9.Add((20, 20), 0, 0, 0)
        grid_sizer_9.Add((20, 20), 0, 0, 0)
        grid_sizer_9.Add(self.button_1, 0, 0, 0)
        grid_sizer_9.Add(self.button_2, 0, 0, 0)
        #grid_sizer_9.Add((20, 20), 0, 0, 0)
        grid_sizer_1.Add(grid_sizer_9, 1, wx.EXPAND, 0)
        sizer_1.Add(grid_sizer_1, 1, wx.EXPAND, 0)
        grid_sizer_6.Add((20, 20), 0, 0, 0)
        grid_sizer_6.Add((20, 20), 0, 0, 0)
        grid_sizer_6.Add((20, 20), 0, 0, 0)
        grid_sizer_6.Add(self.label_7, 0, wx.ALIGN_CENTER_HORIZONTAL, 0)
        grid_sizer_6.Add(self.text_ctrl_5, 0, wx.ALIGN_RIGHT, 0)
        grid_sizer_6.Add((20, 20), 0, 0, 0)
        grid_sizer_6.Add((20, 20), 0, 0, 0)
        grid_sizer_6.Add(self.text_ctrl_6, 0, wx.ALIGN_RIGHT, 0)
        grid_sizer_6.Add((20, 20), 0, 0, 0)
        sizer_3.Add(grid_sizer_6, 1, wx.EXPAND, 0)
        grid_sizer_7.Add((20, 20), 0, 0, 0)
        grid_sizer_7.Add(self.text_ctrl_7, 0, wx.ALIGN_RIGHT, 0)
        grid_sizer_7.Add((20, 20), 0, 0, 0)
        grid_sizer_7.Add((20, 20), 0, 0, 0)
        grid_sizer_7.Add(self.text_ctrl_8, 0, wx.ALIGN_RIGHT, 0)
        grid_sizer_7.Add((20, 20), 0, 0, 0)
        grid_sizer_7.Add((20, 20), 0, 0, 0)
        grid_sizer_7.Add((20, 20), 0, 0, 0)
        grid_sizer_7.Add((20, 20), 0, 0, 0)
        sizer_3.Add(grid_sizer_7, 1, wx.EXPAND, 0)
        sizer_1.Add(sizer_3, 1, wx.EXPAND, 0)
        self.SetSizer(sizer_1)
        self.Layout()
        # end wxGlade


    def write_to_box(self,msg):
                #print msg+"\n"
                #wx.Yield()
                self.rtc.Freeze()
                self.rtc.BeginSuppressUndo()

                self.rtc.BeginTextColour((0, 0, 255))
                self.rtc.WriteText(msg)
                self.rtc.EndTextColour()

                self.rtc.Newline()

                self.rtc.EndSuppressUndo()
                self.rtc.Thaw()
                #wx.Yield()

    def write_to_box_vuln(self,msg):
                #print msg+"\n"
                #wx.Yield()
                self.rtc.Freeze()
                self.rtc.BeginSuppressUndo()

                self.rtc.BeginTextColour((255, 0, 0))
                self.rtc.WriteText(msg)
                self.rtc.EndTextColour()

                self.rtc.Newline()

                self.rtc.EndSuppressUndo()
		self.rtc.MoveEnd()
                self.rtc.Thaw()
                #wx.Yield()


    def write_dic_to_box(self,dic):
                self.rtc.Freeze()
                self.rtc.BeginSuppressUndo()

                self.rtc.BeginTextColour((0, 255, 0))
                for x in dic.keys():
                        self.rtc.WriteText("'"+x+"' => '"+dic[x]+"' ")
			self.rtc.Newline()

                self.rtc.EndTextColour()

                self.rtc.Newline()

                self.rtc.EndSuppressUndo()
		self.rtc.MoveEnd()
                self.rtc.Thaw()
	

    def update_status(self,msg):
                self.frame_1_statusbar.SetStatusText(msg)




    def OnGroup1Select( self, event ):
        radio_selected = event.GetEventObject()

        if self.radio_btn_1 is radio_selected:
          self.verbose = 0

        elif self.radio_btn_2 is radio_selected:
          self.verbose = 1

        elif self.radio_btn_3 is radio_selected:
          self.verbose = 2
        else:
          self.verbose = 2

    def OnGroup2Select( self, event ):
        radio_selected = event.GetEventObject()

        if self.radio_btn_4 is radio_selected:
          self.type = "GET_ALL"

        elif self.radio_btn_5 is radio_selected:
          self.type = "GET_XSS"

        elif self.radio_btn_6 is radio_selected:
          self.type = "POST_XSS"
        else:
          print "none"


    def do_Scan(self, event): # wxGlade: MyFrame.<event_handler>
        #print "Event handler `do_Scan' not implemented"


        self.URL = self.text_ctrl_10.GetValue()
	if not len(self.URL):
          wx.MessageBox("Please specify an URL","Missing URL")  
	  return



        self.user = self.text_ctrl_3.GetValue()
        self.password = self.text_ctrl_4.GetValue()

        self.cookie = self.fbb.GetValue()

        self.proxy = self.text_ctrl_9.GetValue()

        self.timeout = int(self.spin_ctrl_1.GetValue())



        self.ex_url1 = self.text_ctrl_5.GetValue()
        self.ex_url2 = self.text_ctrl_6.GetValue()
        self.ex_url3 = self.text_ctrl_7.GetValue()
        self.ex_url4 = self.text_ctrl_8.GetValue()



        self.frame_1_statusbar.SetStatusText("Scanning")
        
        self.count += 1
        thread = worker(self.count, self, self.URL,self.type,self.user,self.password,self.cookie,self.proxy,self.timeout,self.verbose,self.ex_url1,self.ex_url2,self.ex_url3,self.ex_url4)
        self.threads.append(thread)
        thread.start()

    def show_rep(self):

	win = reportframe.ReportFrame(self, -1, "Scan Report",
                            size=(700, 500),
                            style = wx.DEFAULT_FRAME_STYLE)

	win.addFindings(self.findings)
       	win.Show(True)

	


    def do_Stop(self, event): # wxGlade: MyFrame.<event_handler>
        self.StopThreads()

    def MenuExit(self, event):
        self.Destroy()

    def MenuAbout(self, event):

        info = wx.AboutDialogInfo()
        info.Name = "Powerfuzzer"
        info.Version = version
        info.Copyright = "GPL"
        info.Description = wordwrap("Powerfuzzer is a web application vulnerability scanner ",
            350, wx.ClientDC(self))
	info.WebSite = ("http://powerfuzzer.sourceforge.net", "Powerfuzzer homepage")
	info.Developers = [ "Marcin Kozlowski marcinguy (at) yahoo.com"]

        info.License = wordwrap(licenseText, 500, wx.ClientDC(self))

        # Then we call wx.AboutBox giving it that info object
        wx.AboutBox(info)


    def StopThreads(self):
        while self.threads:
          thread = self.threads[0]
          thread.stop()
          self.threads.remove(thread)




    def OnCloseWindow(self, evt):
        self.Destroy()

    
    def AddRTCHandlers(self):
        # make sure we haven't already added them.
        if rt.RichTextBuffer.FindHandlerByType(rt.RICHTEXT_TYPE_HTML) is not None:
            return
        
        # This would normally go in your app's OnInit method.  I'm
        # not sure why these file handlers are not loaded by
        # default by the C++ richtext code, I guess it's so you
        # can change the name or extension if you wanted...
        rt.RichTextBuffer.AddHandler(rt.RichTextHTMLHandler())
        rt.RichTextBuffer.AddHandler(rt.RichTextXMLHandler())

        # ...like this
        rt.RichTextBuffer.AddHandler(rt.RichTextXMLHandler(name="Other XML",
                                                           ext="ox",
                                                           type=99))

        # This is needed for the view as HTML option since we tell it
        # to store the images in the memory file system.
        wx.FileSystem.AddHandler(wx.MemoryFSHandler())


# end of class MyFrame



class MyApp(wx.App):
    def OnInit(self):
        wx.InitAllImageHandlers()
        frame_1 = MyFrame(None, -1, "")
        self.SetTopWindow(frame_1)
        frame_1.Show()
        return 1

# end of class MyApp

if __name__ == "__main__":
    #th = ScanThread("test")
    app = MyApp(0)
    app.MainLoop()
  	
