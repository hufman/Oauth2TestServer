#!/usr/bin/env python

import os.path
from bottle import abort
import random
import string
import urllib
from .virtualdict import VirtualDict
import json

def load_clients(filename):
	try:
		with open(filename, 'r') as list:
			clients = dict([line.split(':',1) for line in list])
	except:
		clients = {}
	return clients
def reload_clients():
	global filename
	global file_clients
	file_clients = load_clients(filename)

def get_token():
	choices = string.ascii_letters + string.digits
	return ''.join([random.choice(choices) for i in xrange(16)])

file_clients = {}
post_clients = {}
clients = VirtualDict(post_clients, file_clients)
client_auth = {}	# client_id -> auth token
client_refresh = {}	# client_id -> refresh token
client_access = {}	# client_id -> access token

filename = os.path.join(os.path.dirname(__file__), 'clients.txt')
reload_clients()

def clear():
	global post_clients
	global client_auth
	global client_refresh
	global client_access
	post_clients.clear()
	client_auth.clear()
	client_refresh.clear()
	client_access.clear()

def create_client():
	global post_clients
	client_id = "client%s"%(len(post_clients),)
	client_secret = get_token()
	add_client(client_id, client_secret)
	response = {'client_id':client_id, 'client_secret':client_secret}
	return urllib.urlencode(response)

def add_client(client_id, client_secret):
	global post_clients
	post_clients[client_id] = client_secret
	return "Successfully added %s"%(client_id,)

def del_client(client_id, client_secret):
	global post_clients
	if client_id in post_clients and \
	   post_clients[client_id] == client_secret:
		del post_clients[client_id]
		return "Successfully deleted %s"%(client_id,)
	else:
		return "Invalid client_secret for client_id: %s"%(client_id,)

def auth(query):
	""" Authenticates a request, given a dict with query params
	    Required params:
	       response_type
	       client_id
	       redirect_uri
	       scope
	    Optional params:
	       access_type
	       approval_prompt
	       state
	    Returns a url to redirect to
	"""
	required = ['response_type', 'client_id', 'redirect_uri', 'scope']
	q = query
	missing = set(required) - set(q.keys())
	if len(missing) > 0:
		abort(400, "Missing parameters: %s"%(', '.join(missing),))
	if q['response_type'] != 'code':
		abort(400, "Invalid response_type: %s"%(q['response_type'],))
	if '?' in q['redirect_uri']:
		abort(400, "Invalid redirect_uri: %s"%(q['redirect_uri'],))

	reload_clients()
	if q['client_id'] == '' or q['client_id'] not in clients:
		abort(401, "Invalid client_id: %s"%(q['client_id'],))

	if q.get('access_type') == 'offline' and \
	   (q.get('approval_prompt') == 'force' or \
	    q['client_id'] not in client_refresh):
		client_refresh[q['client_id']] = ''

	url = q['redirect_uri']
	params = {}
	auth_code = get_token()
	client_auth[q['client_id']] = auth_code
	params['code'] = auth_code
	if 'state' in q:
		params['state'] = q['state']
	return url + "?" + urllib.urlencode(params)

def token(form):
	""" Trades in an auth code, given a dict with form params
	    Required params:
	       client_id
	       code
	    Returns a urlencoded Oauth2 token response
	"""
	f = form
	required = ['client_id', 'client_secret', 'grant_type']
	missing = set(required) - set(f.keys())
	if len(missing) > 0:
		abort(400, "Missing parameters: %s"%(', '.join(missing),))
	if not (f['client_id'] in clients and \
	        clients[f['client_id']] == f['client_secret']):
		abort(401, "Invalid client id or secret")

	if f['grant_type'] == 'authorization_code':
		if not (f['client_id'] in client_auth and \
			client_auth[f['client_id']] == f.get('code')):
			abort(401, "Invalid auth code")
		del client_auth[f['client_id']]
	elif f['grant_type'] == 'refresh_token':
		if not (f['client_id'] in client_refresh and \
			client_refresh[f['client_id']] == f.get('refresh_token')):
			abort(401, "Invalid refresh token")
	else:
		abort(401, "Invalid grant_type")

	params = {}
	access_token = get_token()
	client_access[f['client_id']] = access_token
	params['access_token'] = access_token
	params['expires_in'] = 86400
	params['token_type'] = 'Bearer'
	if f['client_id'] in client_refresh and \
	   client_refresh[f['client_id']] == '':	# need new refresh
		refresh_token = get_token()
		client_refresh[f['client_id']] = refresh_token
		params['refresh_token'] = refresh_token
	return json.dumps(params)

def validate_access_token(access_token):
	global client_access
	if access_token in client_access.values():
		return ""
	else:
		abort(401, "Invalid access token")
