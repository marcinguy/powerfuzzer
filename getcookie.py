#!/usr/bin/env python

# Powerfuzzer
# Copyright (C) 2008 Marcin Kozlowski
# Parts taken from get_cookie.py from Wapiti by Nicolas Surribas

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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  US

import urllib, urllib2, urlparse, cookielib
import sys, socket, lswww, HTMLParser
try:
  import tidy
except ImportError:
  tidyhere = 0
else:
  tidyhere = 1

if len(sys.argv)!=3:
  sys.stderr.write("Usage: python getcookie.py <cookie_file> <url_with_form>\n")
  sys.exit(1)

COOKIEFILE = sys.argv[1]
url=sys.argv[2]

# Some websites/webapps like Webmin send a first cookie to see if the browser support them
# so we must collect these test-cookies durring authentification.
cj = cookielib.LWPCookieJar()

opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
urllib2.install_opener(opener)

current=url.split("#")[0]
current=current.split("?")[0]
currentdir="/".join(current.split("/")[:-1])+"/"
proto=url.split("://")[0]
agent =  {'User-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}

req=urllib2.Request(url)
socket.setdefaulttimeout(6)
try:
  fd=urllib2.urlopen(req)
except IOError:
  print("Error getting url")
  sys.exit(1)
try:
  htmlSource=fd.read()
except socket.timeout:
  print("Error fetching page")
  sys.exit(1)
p=lswww.linkParser()
try:
  p.feed(htmlSource)
except err:
  if tidyhere==1:
    options = dict(output_xhtml=1, add_xml_decl=1, indent=1, tidy_mark=0)
    htmlSource=str(tidy.parseString(htmlSource,**options))
    try:
      p.reset()
      p.feed(htmlSource)
    except err:
      pass

if len(p.forms)==0:
  print("No forms found in this page !")
  sys.exit(1)

myls=lswww.lswww(url,box=0,timeToQuit=0)
i=0
nchoice=0
if len(p.forms)>1:
  print("Choose the form you want to use :")
  for form in p.forms:
    print
    print("%d) %s" % (i,myls.correctlink(form[0],current,currentdir,proto)))
    for field,value in form[1].items():
      print("\t"+field+" ("+value+")")
    i=i+1
  ok=False
  while ok==False:
    choice=raw_input("Enter a number : ")
    if choice.isdigit():
      nchoice=int(choice)
      if nchoice<i and nchoice>=0:
        ok=True

form=p.forms[nchoice]
print("Please enter values for the folling form :")
print("url = "+myls.correctlink(form[0],current,currentdir,proto))

d={}
for field,value in form[1].items():
  str=raw_input(field+" ("+value+") : ")
  d[field]=str

form[1].update(d)
url=myls.correctlink(form[0],current,currentdir,proto)

server=urlparse.urlparse(url)[1]
script=urlparse.urlparse(url)[2]
if urlparse.urlparse(url)[4]!="":
  script+="?"+urlparse.urlparse(url)[4]
params=urllib.urlencode(form[1])


txheaders =  {'User-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
              'Referer' : sys.argv[2]}

try:
    req = urllib2.Request(url, params, txheaders)
    handle = urllib2.urlopen(req)
except e:
    print("Error getting URL:",url)
    sys.exit(1)

for index, cookie in enumerate(cj):
    print(index,':',cookie)
cj.save(COOKIEFILE,ignore_discard=True)
