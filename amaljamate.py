#!/usr/bin/python
from __future__ import with_statement
import datetime, grp, hashlib, httplib, operator, os, re, sys, tempfile, threading, time, urllib2, xml.dom.minidom, yaml

# amaljamate - Simple multiplexer to get around the lack of RSS for LJ's friends page
#
# This software is copyright (c) 2008-2010 Chris Boyle.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Example config:

livejournal.com:
  username: joebloggs
  password: letmein
  output: ~/www/somewhere_that_your_webserver_protects/livejournal.xml
  exclude: [some_crossposter, foo, joebloggs]
dreamwidth.org:
  username: joe
  password: cloud9
  output: ~/www/need_auth_to_get_here/dreamwidth.feed
"""
CONFIG_PATH = os.path.join('~','.amaljamate.yml')
CACHE_PATH = os.path.join('~','.amaljamate-cache')
ONE_SITE_AT_A_TIME = False
OUTPUT_CHMOD = 0660
OUTPUT_CHGRP = 'nogroup'
DELAY_SCALE = 1.8
INITIAL_DELAY = 6
MAX_DELAY = 100
MAX_TRIES = 10
CACHE_TIME = 3500
USER_AGENT = 'amaljamate/0.1; chris@boyle.name; http://chris.boyle.name/projects/amaljamate'
VERBOSE = '--verbose' in sys.argv

def log(m):
	if VERBOSE: sys.stderr.write('%s\n' % m)

"""Create a temp file in the same dir, which will be renamed onto the filename, or deleted if an exception occurred."""
class FileWithTemp:
	def __init__(self, path):
		self.path = path

	def __enter__(self):
		d, p = os.path.split(self.path)
		self.fd, self.temppath = tempfile.mkstemp(dir=d, prefix='.%s.part.' % p)
		self.f = os.fdopen(self.fd, 'w')
		return self.f.__enter__()

	def __exit__(self, exc_type, exc_value, traceback):
		r = self.f.__exit__(exc_type, exc_value, traceback)
		if exc_type is None:
			try:
				os.rename(self.temppath, self.path)
				if OUTPUT_CHMOD: os.chmod(self.path, OUTPUT_CHMOD)
				if OUTPUT_CHGRP:
					gid = grp.getgrnam(OUTPUT_CHGRP).gr_gid
					os.chown(self.path, -1, gid)
				return r
			except:
				log(e)
				pass
		try: os.unlink(self.temppath)
		except: pass
		return r

class ConstantPasswordMgr:
	def __init__( self, user, password ): self.user, self.password = user, password
	def add_password(self, realm, uri, user, passwd): pass
	def find_user_password(self, realm, authuri): return self.user, self.password

"""mostly from http://developer.yahoo.com/python/python-caching.html"""
class DiskCacheFetcher:
	def __init__(self, cache_dir=None):
		self.cache_dir = cache_dir or os.path.expanduser(CACHE_PATH)
		# alternative: os.path.join(tempfile.gettempdir(),'amaljamate-%s' % getpass.getuser())
		if not os.path.isdir(self.cache_dir): os.makedirs(self.cache_dir, 0700)
		self.delay = INITIAL_DELAY

	def fetch(self, url, max_age=0, headers={}, username=None, password=None):
		for tryNum in range(0, MAX_TRIES):
			log('Try %d/%d: %s' % (tryNum, MAX_TRIES, url))
			try:
				return self._fetch(url, max_age, headers, username, password)
			except (httplib.HTTPException, urllib2.HTTPError, urllib2.URLError, httplib.BadStatusLine), e:
				log(e)
			# Sleep a bit longer and have another try
			self.delay = min(self.delay*DELAY_SCALE, MAX_DELAY)
		sys.stderr.write('Tried to fetch %s' % url)
		try:
			raise
		except Exception, e:
			sys.stderr.write(str(e))
			if hasattr(e,'read'): sys.stderr.write(str(e.read()))
		return ''

	def _fetch(self, url, max_age=0, headers={}, username=None, password=None):
		# Use MD5 hash of the URL as the filename
		filename = hashlib.md5(url).hexdigest()
		filepath = os.path.join(self.cache_dir, filename)
		if os.path.exists(filepath) and int(time.time()) - os.path.getmtime(filepath) < max_age:
			log('cached')
			return open(filepath).read()
		time.sleep(self.delay)  # Don't annoy the server (we don't have a client waiting)
		# Retrieve over HTTP and cache, using rename to avoid collisions
		headers.update({ 'User-Agent': USER_AGENT })
		# set these up freshly every time because of http://bugs.python.org/issue4683
		auth_handler = urllib2.HTTPDigestAuthHandler( ConstantPasswordMgr( username, password ) )
		opener = urllib2.build_opener( auth_handler )
		data = opener.open( urllib2.Request( url, headers=headers ) ).read()
		with FileWithTemp(filepath) as f: f.write(data)
		return data

class FeedMaker( threading.Thread ):
	def __init__(self, **kwargs):
		self.__dict__.update(**kwargs)
		if not hasattr(self,'site'):     raise 'Need a site name'
		if not hasattr(self,'output'):   raise '%s: Need an output'  % self.site
		if not hasattr(self,'username'): raise '%s: Need a username' % self.site
		if not hasattr(self,'password'): raise '%s: Need a password' % self.site
		self.fetcher = DiskCacheFetcher()
		self.url_to_friend_cache = {}
		threading.Thread.__init__(self)

	def _get_friends(self):
		url = 'http://www.%s/tools/opml.bml?user=%s' % (self.site,self.username)
		fdata = self.fetcher.fetch( url, CACHE_TIME )
		if len(fdata) <= 0: return []
		try: dom = xml.dom.minidom.parseString( fdata )
		except Exception,e:
			sys.stderr.write("Invalid output from %s, exception:\n%s\noutput:\n%s" % (url,str(e),fdata))
			return []
		friends = filter(None, map( lambda o: o.getAttribute('xmlURL') or o.getAttribute('xmlUrl'), dom.getElementsByTagName('outline')))
		dom.unlink()
		return friends

	def _entry_date(self, i):
		date = i.getElementsByTagName("published")[0].childNodes[0].data
		date = re.sub(r'[+-]\d\d:\d\d',r'Z',date)  # strptime can't cope, and this is only for sorting
		try: return datetime.datetime.strptime(date,"%Y-%m-%dT%H:%M:%SZ")
		except: return datetime.datetime.now()

	def url_to_friend(self, url):
		try: return self.url_to_friend_cache[url]
		except KeyError:
			if not re.match(r'http://[^/]+\.'+re.escape(self.site), url):
				f = None  # off-site URL of a syndicated feed: exclude
			elif url.startswith('http://users.') or url.startswith('http://community.'):
				f = re.sub(r'^http://[^/]+/([^/]+).*',r'\1',url).replace('-','_')
			else:
				f = re.sub(r'^http://([^\.]+)\..*',r'\1',url).replace('-','_')
			self.url_to_friend_cache[url] = f
			return f

	def _should_fetch(self, url):
		# status' DNS points to a non-LJ server (no feed), ext- users aren't real (OpenID)
		bad_starts = ['http://status.','http://ext-','http://syndicated.','http://feeds.']
		f = self.url_to_friend(url)
		return not any(map(url.startswith, bad_starts)) and f is not None and not any(map(f.__eq__, self.__dict__.get('exclude',[])))

	def _retitle(self, e, friend):
		tag = e.getElementsByTagName( "title" )[0]
		t = tag.childNodes[0].data
		posters = e.getElementsByTagName( "lj:poster" )
		if posters:
			u = posters[0].getAttribute('user')
			if t.startswith(friend): t = u+': '+t
			else: t = friend+'/'+u+': '+t
		elif not t.startswith(friend+' '): t = friend+': '+t
		tag.childNodes[0].replaceWholeText(t)

	def _get_dates_and_entries(self, friend):
		entries = []
		url = re.sub(r'rss$','atom',friend) + '?auth=digest'
		friend = self.url_to_friend(friend)
		data = self.fetcher.fetch( url, CACHE_TIME, username=self.username, password=self.password )
		if len(data) <= 0: return []
		dom = xml.dom.minidom.parseString( data )
		for e in dom.getElementsByTagName('entry'):
			self._retitle(e, friend)
			entries.append((self._entry_date(e), e.toxml('UTF-8')))
		dom.unlink()
		return entries

	def run(self):
		friends = filter(self._should_fetch, self._get_friends())
		dated_entries = reduce(operator.add, map(self._get_dates_and_entries, friends), [])
		entries = [e[1] for e in sorted(dated_entries, lambda a,b: cmp( b[0], a[0] ))]  # newest first
		with FileWithTemp(os.path.expanduser(self.output)) as f:
			f.write( """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:lj="http://www.livejournal.com">
<title>%s friends</title>""" % self.site )
			map(f.write, entries[:100])
			f.write( "</feed>" )

if __name__ == "__main__":
	CONFIG = yaml.load(open(os.path.expanduser(CONFIG_PATH)).read())
	for site in CONFIG:
		kwargs = CONFIG[site]
		kwargs['site'] = site
		f = FeedMaker(**kwargs)
		if ONE_SITE_AT_A_TIME: f.run()
		else: f.start()
