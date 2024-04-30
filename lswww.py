#!/usr/bin/env python3

# Powerfuzzer
# Copyright (C) 2008 Marcin Kozlowski
# Using lswww component by:
# lswww v2.1.5 - A web spider library
# Copyright (C) 2006 Nicolas Surribas
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

import sys
import re
import socket
import getopt
import os
import html.parser
import urllib.request, urllib.parse, urllib.error
import time

import wx
import wx.richtext as rt

try:
    import http.cookiejar as cookielib
except ImportError:
    cookielibhere = 0
else:
    cookielibhere = 1

try:
    import tidylib as tidy
except ImportError:
    print("lswww will be far less effective without tidy")
    print("please install libtidy ( http://tidy.sourceforge.net/ ),")
    print("ctypes ( http://starship.python.net/crew/theller/ctypes/ )")
    print("and uTidylib ( http://utidylib.berlios.de/ )")
    tidyhere = 0
else:
    tidyhere = 1

try:
    import bs4 as BeautifulSoup
except ImportError:
    BeautifulSouphere = 0
else:
    BeautifulSouphere = 1

class lswww:
    """
    lswww explore a website and extract links and forms fields.

    Usage: python lswww.py http://server.com/base/url/ [options]

    Supported options are:
    -s <url>
    --start <url>
        To specify an url to start with

    -x <url>
    --exclude <url>
        To exclude an url from the scan (for example logout scripts)
        You can also use a wildcard (*)
        Exemple : -x "http://server/base/?page=*&module=test"
        or -x http://server/base/admin/* to exclude a directory

    -p <url_proxy>
    --proxy <url_proxy>
        To specify a proxy
        Exemple: -p http://proxy:port/

    -c <cookie_file>
    --cookie <cookie_file>
        To use a cookie

    -a <login%password>
    --auth <login%password>
        Set credentials for HTTP authentication
        Doesn't work with Python 2.4

    -r <parameter_name>
    --remove <parameter_name>
        Remove a parameter from URLs

    -v <level>
    --verbose <level>
        Set verbosity level
        0: only print results
        1: print a dot for each url found (default)
        2: print each url

    -t <timeout>
    --timeout <timeout>
        Set the timeout (in seconds)

    -h
    --help
        To print this usage message
    """

    root = ""
    server = ""
    tobrowse = []
    browsed = []
    proxy = {}
    excluded = []
    forms = []
    uploads = []
    allowed = ['php', 'html', 'htm', 'xml', 'xhtml', 'xht', 'xhtm',
               'asp', 'aspx', 'php3', 'php4', 'php5', 'txt', 'shtm',
               'shtml', 'phtm', 'phtml', 'jhtml', 'pl', 'jsp', 'cfm', 'cfml']
    verbose = 2
    cookie = ""
    auth_basic = []
    bad_params = []
    timeout = 6
    box = ""

    def __init__(self, rooturl, box, timeToQuit):
        self.root = rooturl
        self.box = box
        self.timeToQuit = timeToQuit
        if self.root[-1] != "/":
            self.root += "/"
        if self.checklink(self.root):
            self.write_to_box("Invalid URI: " + self.root)
            self.timeToQuit.set()
            return

        self.server = (self.root.split("://")[1]).split("/")[0]
        self.tobrowse.append(self.root)

    def write_to_box(self, msg):
        self.box.Freeze()
        self.box.BeginSuppressUndo()
        self.box.BeginTextColour((0, 0, 255))
        self.box.WriteText(msg)
        self.box.EndTextColour()
        self.box.Newline()
        self.box.EndSuppressUndo()
        self.box.Thaw()

    def write_to_box_no_nl(self, msg):
        self.box.Freeze()
        self.box.BeginSuppressUndo()
        self.box.BeginTextColour((0, 0, 255))
        self.box.WriteText(msg)
        self.box.EndTextColour()
        self.box.EndSuppressUndo()
        self.box.Thaw()

    def clear(self):
        self.box.Clear()

    def setTimeOut(self, timeout=6):
        """Set the timeout in seconds to wait for a page"""
        self.timeout = timeout

    def setProxy(self, proxy={}):
        """Set proxy preferences"""
        self.proxy = proxy

    def addStartURL(self, url):
        if self.checklink(url):
            self.write_to_box("Invalid link argument:" + url)
            return
        if self.inzone(url) == 0:
            self.tobrowse.append(url)

    def addExcludedURL(self, url):
        """Add an url to the list of forbidden urls"""
        self.excluded.append(url)

    def setCookieFile(self, cookie):
        """Set the file to read the cookie from"""
        self.cookie = cookie

    def setAuthCredentials(self, auth_basic):
        self.auth_basic = auth_basic

    def addBadParam(self, bad_param):
        self.bad_params.append(bad_param)

    def browse(self, url):
        """Extract urls from a webpage and add them to the list of urls to browse if they aren't in the exclusion list"""
        current = url.split("#")[0]
        current = current.split("?")[0]
        currentdir = "/".join(current.split("/")[:-1]) + "/"

        socket.setdefaulttimeout(self.timeout)
        try:
            req = urllib.request.Request(url)
            u = urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            self.write_to_box(url + ":" + str(e))
            self.excluded.append(url)
            return 0
        except urllib.error.URLError as e:
            self.write_to_box(url + ":" + str(e))
            self.excluded.append(url)
            return 0

        proto = url.split("://")[0]
        if proto == "http" or proto == "https":
            if not u.info().get_content_type():
                if (current.split(".")[-1] not in self.allowed) and current[-1] != "/":
                    return 1
            elif u.info().get_content_type().find("text") == -1:
                return 1

        if u.headers.get("location"):
            redir = self.correctlink(u.headers.get("location"), current, currentdir, proto)
            if redir != None:
                if self.inzone(redir) == 0:
                    if redir not in self.browsed and redir not in self.tobrowse and not self.isExcluded(redir):
                        self.tobrowse.append(redir)

        try:
            htmlSource = u.read()
        except socket.timeout:
            htmlSource = ""
        p = linkParser()
        try:
            p.feed(htmlSource.decode('utf-8'))
        except html.parser.HTMLParseError as err:
            if tidyhere == 1:
                options = dict(output_xhtml=1, add_xml_decl=1, indent=1, tidy_mark=0)
                htmlSource = str(tidy.parseString(htmlSource, **options))
                try:
                    p.reset()
                    p.feed(htmlSource)
                except html.parser.HTMLParseError as err:
                    pass
            elif BeautifulSouphere == 1:
                htmlSource = BeautifulSoup.BeautifulSoup(htmlSource).prettify()
                try:
                    p.reset()
                    p.feed(htmlSource)
                except html.parser.HTMLParseError as err:
                    pass
            else:
                p.liens = re.findall('href="(.*?)"', htmlSource.decode('utf-8'))

        for lien in p.uploads:
            self.uploads.append(self.correctlink(lien, current, currentdir, proto))
        for lien in p.liens:
            lien = self.correctlink(lien, current, currentdir, proto)
            if lien != None:
                if self.inzone(lien) == 0:
                    if lien not in self.browsed and lien not in self.tobrowse and not self.isExcluded(lien):
                        self.tobrowse.append(lien)
        for form in p.forms:
            action = self.correctlink(form[0], current, currentdir, proto)
            if action == None:
                action = current
            form = (action, form[1], url)
            if form not in self.forms:
                self.forms.append(form)
        if u.code == 404:
            self.excluded.append(url)
            return 0
        return 1

    def correctlink(self, lien, current, currentdir, proto):
        """Transform relatives urls in absolutes ones"""
        lien = lien.strip()
        if (lien.find("http://", 0) == 0) or (lien.find("https://", 0) == 0):
            pass
        else:
            if lien[0] == '/':
                lien = proto + "://" + self.server + lien
            else:
                if lien[0] == '?':
                    lien = current + lien
                else:
                    lien = currentdir + lien
        if lien.find("#") != -1:
            lien = lien.split("#")[0]
        if lien.find("?") != -1:
            args = lien.split("?")[1]
            if args.find("&") != -1:
                args = args.split("&")
                args.sort()
                args = [i for i in args if i != "" and i.find("=") >= 0]
                for i in self.bad_params:
                    for j in args:
                        if j.startswith(i + "="):
                            args.remove(j)
                args = "&".join(args)
            if args in ["C=D;O=A", "C=D;O=D", "C=M;O=A", "C=M;O=D", "C=N;O=A", "C=N;O=D", "C=S;O=A", "C=S;O=D"]:
                lien = lien.split("?")[0]
            else:
                lien = lien.split("?")[0] + "?" + args
        if lien[-1:] == "?":
            lien = lien[:-1]
        if lien.find("?") != -1:
            file = lien.split("?")[0]
            file = re.sub("[^:]//+", "/", file)
            lien = file + "?" + lien.split("?")[1]
        while re.search("/([~:!,;a-zA-Z0-9\.\-+_]+)/\.\./", lien) != None:
            lien = re.sub("/([~:!,;a-zA-Z0-9\.\-+_]+)/\.\./", "/", lien)
        lien = re.sub("/\./", "/", lien)
        return lien

    def checklink(self, url):
        """Verify the protocol"""
        if (url.find("http://", 0) == 0) or (url.find("https://", 0) == 0):
            return 0
        else:
            return 1

    def inzone(self, url):
        """Make sure the url is under the root url"""
        temp = self.root
        if isinstance(temp, str):
            temp = temp.encode("iso8859-15")
        if url.find(temp, 0) == 0:
            return 0
        else:
            return 1

    def isExcluded(self, url):
        """Return True if the url is not allowed to be scan"""
        match = False
        for regexp in self.excluded:
            if self.reWildcard(regexp, url):
                match = True
        return match

    def reWildcard(self, regexp, string):
        """Wildcard-based regular expression system"""
        regexp = re.sub("\*+", "*", regexp)
        match = True
        if regexp.count("*") == 0:
            if regexp == string:
                return True
            else:
                return False
        blocks = regexp.split("*")
        start = ""
        end = ""
        if not regexp.startswith("*"):
            start = blocks[0]
        if not regexp.endswith("*"):
            end = blocks[-1]
        if start != "":
            if string.startswith(start):
                blocks = blocks[1:]
            else:
                return False
        if end != "":
            if string.endswith(end):
                blocks = blocks[:-1]
            else:
                return False
        blocks = [block for block in blocks if block != ""]
        if blocks == []:
            return match
        for block in blocks:
            i = string.find(block)
            if i == -1:
                return False
            string = string[i + len(block):]
        return match

    def go(self):
        wx.CallAfter(self.clear)
        while len(self.tobrowse) > 0:
            if self.timeToQuit.isSet():
                del self.tobrowse[0:]
                break
            lien = self.tobrowse.pop(0)
            if lien not in self.browsed:
                if self.browse(lien):
                    self.browsed.append(lien)
                    if self.verbose == 1:
                        wx.CallAfter(self.write_to_box_no_nl, ".")
                    elif self.verbose == 2:
                        wx.CallAfter(self.write_to_box, lien)
        del self.tobrowse[0:]

    def verbosity(self, vb):
        """Set verbosity level"""
        self.verbose = vb

    def printLinks(self):
        """Print found URLs on standard output"""
        self.browsed.sort()
        sys.stderr.write("\n+ URLs :\n")
        for lien in self.browsed:
            print(lien)

    def printForms(self):
        """Print found forms on standard output"""
        if self.forms != []:
            sys.stderr.write("\n+ Forms Info :\n")
            for form in self.forms:
                print("From:", form[2])
                print("To:", form[0])
                for k, v in form[1].items():
                    print("\t" + k, ":", v)
                print

    def printUploads(self):
        """Print urls accepting uploads"""
        if self.uploads != []:
            sys.stderr.write("\n+ Upload Scripts :\n")
            for up in self.uploads:
                print(up)

    def getLinks(self):
        self.browsed.sort()
        return self.browsed

    def getForms(self):
        return self.forms

    def getUploads(self):
        self.uploads.sort()
        return self.uploads


class linkParser(html.parser.HTMLParser):
    """Extract urls in 'a' href HTML tags"""

    def __init__(self):
        html.parser.HTMLParser.__init__(self)
        self.liens = []
        self.forms = []
        self.form_values = {}
        self.inform = 0
        self.current_form_url = ""
        self.uploads = []
        self.current_form_method = "get"

    def handle_starttag(self, tag, attrs):
        tmpdict = {}
        val = None
        for k, v in dict(attrs).items():
            tmpdict[k.lower()] = v
        if tag.lower() == 'a':
            if "href" in tmpdict.keys():
                self.liens.append(tmpdict['href'])

        if tag.lower() == 'form':
            self.inform = 1
            self.form_values = {}
            if "action" in tmpdict.keys():
                self.liens.append(tmpdict['action'])
                self.current_form_url = tmpdict['action']

            # Forms use GET method by default
            self.current_form_method = "get"
            if "method" in tmpdict.keys():
                if tmpdict["method"].lower() == "post":
                    self.current_form_method = "post"

        if tag.lower() == 'input':
            if self.inform == 1:
                if "type" not in tmpdict.keys():
                    tmpdict["type"] = "text"
                if "name" in tmpdict.keys():
                    if tmpdict['type'].lower() in ['text', 'password', 'radio', 'checkbox', 'hidden', 'submit',
                                                   'search']:
                        # use default value if present or set it to 'on'
                        if "value" in tmpdict.keys():
                            if tmpdict["value"] != "":
                                val = tmpdict["value"]
                            else:
                                val = "on"
                        else:
                            val = "on"
                        self.form_values.update(dict([(tmpdict['name'], val)]))
                    if tmpdict['type'].lower() == "file":
                        self.uploads.append(self.current_form_url)

        if tag.lower() in ["textarea", "select"]:
            if self.inform == 1:
                if "name" in tmpdict.keys():
                    self.form_values.update(dict([(tmpdict['name'], 'on')]))

        if tag.lower() in ["frame", "iframe"]:
            if "src" in tmpdict.keys():
                self.liens.append(tmpdict['src'])

    def handle_endtag(self, tag):
        if tag.lower() == 'form':
            self.inform = 0
            if self.current_form_method == "post":
                self.forms.append((self.current_form_url, self.form_values))
            else:
                l = ["=".join([k, v]) for k, v in self.form_values.items()]
                l.sort()
                self.liens.append(self.current_form_url.split("?")[0] + "?" + "&".join(l))


if __name__ == "__main__":
    try:
        prox = {}
        auth = []
        if len(sys.argv) < 2:
            print(lswww.__doc__)
            sys.exit(0)
        if '-h' in sys.argv or '--help' in sys.argv:
            print(lswww.__doc__)
            sys.exit(0)
        myls = lswww(sys.argv[1])
        myls.verbosity(1)
        try:
            opts, args = getopt.getopt(sys.argv[2:], "hp:s:x:c:a:r:v:t:",
                                       ["help", "proxy=", "start=", "exclude=", "cookie=", "auth=", "remove=",
                                        "verbose=", "timeout="])
        except getopt.GetoptError as e:
            print(e)
            sys.exit(2)
        for o, a in opts:
            if o in ("-h", "--help"):
                print(lswww.__doc__)
                sys.exit(0)
            if o in ("-s", "--start"):
                if (a.find("http://", 0) == 0) or (a.find("https://", 0) == 0):
                    myls.addStartURL(a)
            if o in ("-x", "--exclude"):
                if (a.find("http://", 0) == 0) or (a.find("https://", 0) == 0):
                    myls.addExcludedURL(a)
            if o in ("-p", "--proxy"):
                if (a.find("http://", 0) == 0) or (a.find("https://", 0) == 0):
                    prox = {'http': a}
                    myls.setProxy(prox)
            if o in ("-c", "--cookie"):
                myls.setCookieFile(a)
            if o in ("-r", "--remove"):
                myls.addBadParam(a)
            if o in ("-a", "--auth"):
                if a.find("%") >= 0:
                    auth = [a.split("%")[0], a.split("%")[1]]
                    myls.setAuthCredentials(auth)
            if o in ("-v", "--verbose"):
                if str.isdigit(a):
                    myls.verbosity(int(a))
            if o in ("-t", "--timeout"):
                if str.isdigit(a):
                    myls.setTimeOut(int(a))
        myls.go()
        myls.printLinks()
        myls.printForms()
        myls.printUploads()
    except SystemExit:
        pass

