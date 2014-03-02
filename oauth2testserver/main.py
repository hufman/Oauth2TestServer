#!/usr/bin/env python

from . import oauth2
from bottle import delete, get, post, put, request, abort, redirect, run

@post('/client')
def create_client():
	return oauth2.create_client()

@put('/client')
def add_client():
	form = request.forms
	required = ['client_id', 'client_secret']
	missing = set(required) - set(form.keys())
	if len(missing) > 0:
		abort(400, "Missing parameters: %s"%(', '.join(missing),))

	return oauth2.add_client(form.client_id, form.client_secret)

@delete('/client')
def del_client():
	form = request.forms
	required = ['client_id', 'client_secret']
	missing = set(required) - set(form.keys())
	if len(missing) > 0:
		abort(400, "Missing parameters: %s"%(', '.join(missing),))

	return oauth2.del_client(form.client_id, form.client_secret)

@get('/auth')
def auth():
	return redirect(oauth2.auth(request.query))
@delete('/auth')
def unauth():
	if 'client_id' not in request.forms.keys():
		abort(400, 'Missing parameters: client_id')
	oauth2.unauth(request.forms['client_id'])
@post('/token')
def token():
	return oauth2.token(request.forms)

@delete('/token')
def del_token():
	if 'client_id' not in request.forms.keys():
		abort(400, 'Missing parameters: client_id')
	oauth2.del_access_token(request.forms['client_id'])
	oauth2.del_refresh_token(request.forms['client_id'])
@delete('/accesstoken')
def del_access_token():
	if 'client_id' not in request.forms.keys():
		abort(400, 'Missing parameters: client_id')
	oauth2.del_access_token(request.forms['client_id'])
@delete('/refreshtoken')
def del_refresh_token():
	if 'client_id' not in request.forms.keys():
		abort(400, 'Missing parameters: client_id')
	oauth2.del_refresh_token(request.forms['client_id'])

@get('/validate')
def validate():
	return oauth2.validate_access_token(request.query.token)

if __name__ == '__main__':
	run(host='0.0.0.0', port=9873, debug=True)
