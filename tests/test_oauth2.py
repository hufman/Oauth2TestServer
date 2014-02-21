from nose.tools import *
from oauth2testserver import oauth2
from urlparse import parse_qs, urlparse
import json

class TestClients:
	def setup(self):
		oauth2.clear()
	def test_create(self):
		result = oauth2.create_client()
		data = json.loads(result)
		assert_in('client_id', data)
		assert_in('client_secret', data)
		client_id = data['client_id']
		client_secret = data['client_secret']
		assert_true(len(client_id) > 5, "id too short: %s"%(client_id,))
		assert_true(len(client_secret) > 10, "secret too short: %s"%(client_secret,))
		assert_in(client_id, oauth2.clients)
		assert_equal(oauth2.clients[client_id], client_secret)
	def test_add(self):
		oauth2.add_client('hi','password')
		assert_in('hi', oauth2.clients)
		assert_equal(oauth2.clients['hi'], 'password')
	def test_delete(self):
		oauth2.add_client('hi','password')
		assert_in('hi', oauth2.clients)
		assert_equal(oauth2.clients['hi'], 'password')
		oauth2.del_client('hi','wrong')
		assert_in('hi', oauth2.clients)
		assert_equal(oauth2.clients['hi'], 'password')
		oauth2.del_client('hi','password')
		assert_not_in('hi', oauth2.clients)

class TestAuthTokens:
	def setup(self):
		oauth2.clear()
	def test_create(self):
		oauth2.add_client('hi','password')
		auth_request = {'client_id':'hi', 'response_type':'code',
		                'scope':'test', 'redirect_uri':'http://me'}
		url = oauth2.auth(auth_request)
		parsed_url = urlparse(url)
		assert_equal('http', parsed_url.scheme)
		assert_equal('me', parsed_url.netloc)
		data = parse_qs(parsed_url.query)
		data = dict([(k,d[0]) for k,d in data.items()])
		assert_in('code', data)
		assert_not_in('state', data)

		assert_in('hi', oauth2.client_auth)
		assert_not_in('hi', oauth2.client_refresh)
		assert_not_in('hi', oauth2.client_access)

	def test_create_offline(self):
		oauth2.add_client('hi','password')
		auth_request = {'client_id':'hi', 'response_type':'code',
		                'scope':'test', 'redirect_uri':'http://me',
		                'access_type':'offline'}
		url = oauth2.auth(auth_request)
		parsed_url = urlparse(url)
		assert_equal('http', parsed_url.scheme)
		assert_equal('me', parsed_url.netloc)
		data = parse_qs(parsed_url.query)
		data = dict([(k,d[0]) for k,d in data.items()])
		assert_in('code', data)
		assert_not_in('state', data)

		assert_in('hi', oauth2.client_auth)
		assert_in('hi', oauth2.client_refresh)
		assert_not_in('hi', oauth2.client_access)

	def test_create_state(self):
		oauth2.add_client('hi','password')
		auth_request = {'client_id':'hi', 'response_type':'code',
		                'scope':'test', 'redirect_uri':'http://me',
		                'state':'preserveit'}
		url = oauth2.auth(auth_request)
		parsed_url = urlparse(url)
		assert_equal('http', parsed_url.scheme)
		assert_equal('me', parsed_url.netloc)
		data = parse_qs(parsed_url.query)
		data = dict([(k,d[0]) for k,d in data.items()])
		assert_in('code', data)
		assert_in('state', data)
		assert_equal('preserveit', data['state'])

		assert_in('hi', oauth2.client_auth)
		assert_not_in('hi', oauth2.client_refresh)
		assert_not_in('hi', oauth2.client_access)

class TestAccessTokens:
	def setup(self):
		oauth2.clear()

	def get_code(self, client_id, **kwargs):
		auth_request = {'client_id':client_id, 'response_type':'code',
		                'scope':'test', 'redirect_uri':'http://me'}
		auth_request.update(kwargs)
		url = oauth2.auth(auth_request)
		parsed_url = urlparse(url)
		data = parse_qs(parsed_url.query)
		data = dict([(k,d[0]) for k,d in data.items()])
		code = data['code']
		return code

	def test_bad_grant(self):
		oauth2.add_client('hi','password')

		code = self.get_code('hi')

		token_request = {'client_id':'hi', 'client_secret':'password',
		                 'grant_type':'custom_code', 'code':code}
		try:
			resp = oauth2.token(token_request)
			fail()
		except:
			pass

	def test_create(self):
		oauth2.add_client('hi','password')

		code = self.get_code('hi')

		token_request = {'client_id':'hi', 'client_secret':'password',
		                 'grant_type':'authorization_code', 'code':code}
		resp = oauth2.token(token_request)
		token_data = json.loads(resp)
		assert_in('access_token', token_data)
		assert_in('expires_in', token_data)
		assert_in('token_type', token_data)
		assert_not_in('refresh_token', token_data)
		# throws an exception if invalid
		works = oauth2.validate_access_token(token_data['access_token'])

		# auth_token should not be valid a second time
		try:
			resp = oauth2.token(token_request)
			fail()
		except:
			pass

	def test_create_random(self):
		result = oauth2.create_client()
		data = json.loads(result)
		client_id = data['client_id']
		client_secret = data['client_secret']

		code = self.get_code(client_id)

		token_request = {'client_id':client_id, 'client_secret':client_secret,
		                 'grant_type':'authorization_code', 'code':code}
		resp = oauth2.token(token_request)
		token_data = json.loads(resp)
		assert_in('access_token', token_data)
		assert_in('expires_in', token_data)
		assert_in('token_type', token_data)
		assert_not_in('refresh_token', token_data)
		# throws an exception if invalid
		works = oauth2.validate_access_token(token_data['access_token'])

		# auth_token should not be valid a second time
		try:
			resp = oauth2.token(token_request)
			fail()
		except:
			pass

	def test_create_and_revoke(self):
		oauth2.add_client('hi','password')

		code = self.get_code('hi')

		token_request = {'client_id':'hi', 'client_secret':'password',
		                 'grant_type':'authorization_code', 'code':code}
		resp = oauth2.token(token_request)
		token_data = json.loads(resp)
		assert_in('access_token', token_data)
		assert_in('expires_in', token_data)
		assert_in('token_type', token_data)
		assert_not_in('refresh_token', token_data)
		# throws an exception if invalid
		works = oauth2.validate_access_token(token_data['access_token'])
		# revoke
		oauth2.del_client('hi','password')
		try:
			works = oauth2.validate_access_token(token_data['access_token'])
			fail()
		except:
			pass

	def test_create_offline(self):
		oauth2.add_client('hi','password')

		code = self.get_code('hi', access_type='offline')

		# get auth token
		token_request = {'client_id':'hi', 'client_secret':'password',
		                 'grant_type':'authorization_code', 'code':code}
		resp = oauth2.token(token_request)
		token_data = json.loads(resp)
		assert_in('access_token', token_data)
		assert_in('expires_in', token_data)
		assert_in('token_type', token_data)
		assert_in('refresh_token', token_data)
		# throws an exception if invalid
		works = oauth2.validate_access_token(token_data['access_token'])

		# auth_token should not be valid a second time
		try:
			resp = oauth2.token(token_request)
			fail()
		except:
			pass

	def test_create_offline_omit(self):
		oauth2.add_client('hi','password')

		code = self.get_code('hi', access_type='offline')

		# get auth token
		token_request = {'client_id':'hi', 'client_secret':'password',
		                 'grant_type':'authorization_code', 'code':code}
		resp = oauth2.token(token_request)
		token_data = json.loads(resp)
		assert_in('access_token', token_data)
		assert_in('expires_in', token_data)
		assert_in('token_type', token_data)
		assert_in('refresh_token', token_data)
		# throws an exception if invalid
		works = oauth2.validate_access_token(token_data['access_token'])

		# should not get another refresh
		code = self.get_code('hi', access_type='offline')
		token_request['code'] = code
		resp = oauth2.token(token_request)
		token_data = json.loads(resp)
		assert_in('access_token', token_data)
		assert_in('expires_in', token_data)
		assert_in('token_type', token_data)
		assert_not_in('refresh_token', token_data)
		# throws an exception if invalid
		works = oauth2.validate_access_token(token_data['access_token'])

	def test_create_offline_force(self):
		oauth2.add_client('hi','password')

		code = self.get_code('hi', access_type='offline',
		                           approval_prompt='force')

		# get auth token
		token_request = {'client_id':'hi', 'client_secret':'password',
		                 'grant_type':'authorization_code', 'code':code}
		resp = oauth2.token(token_request)
		token_data = json.loads(resp)
		assert_in('access_token', token_data)
		assert_in('expires_in', token_data)
		assert_in('token_type', token_data)
		assert_in('refresh_token', token_data)
		# throws an exception if invalid
		works = oauth2.validate_access_token(token_data['access_token'])

		# should not get another refresh
		code = self.get_code('hi', access_type='offline',
		                           approval_prompt='force')
		token_request['code'] = code
		resp = oauth2.token(token_request)
		token_data = json.loads(resp)
		assert_in('access_token', token_data)
		assert_in('expires_in', token_data)
		assert_in('token_type', token_data)
		assert_in('refresh_token', token_data)
		# throws an exception if invalid

	def test_create_offline_use(self):
		oauth2.add_client('hi','password')

		code = self.get_code('hi', access_type='offline')

		# get auth token
		token_request = {'client_id':'hi', 'client_secret':'password',
		                 'grant_type':'authorization_code', 'code':code}
		resp = oauth2.token(token_request)
		token_data = json.loads(resp)
		assert_in('access_token', token_data)
		assert_in('expires_in', token_data)
		assert_in('token_type', token_data)
		assert_in('refresh_token', token_data)
		# throws an exception if invalid
		works = oauth2.validate_access_token(token_data['access_token'])
		refresh_token = token_data['refresh_token']

		# expire the access token
		del oauth2.client_access['hi']
		try:
			works = oauth2.validate_access_token(token_data['access_token'])
			fail()
		except:
			pass

		# get a new token with refresh
		token_request = {'client_id':'hi', 'client_secret':'password',
		                 'grant_type':'refresh_token', 'refresh_token':refresh_token}
		resp = oauth2.token(token_request)
		token_data = json.loads(resp)
		assert_in('access_token', token_data)
		assert_in('expires_in', token_data)
		assert_in('token_type', token_data)
		assert_not_in('refresh_token', token_data)
		# throws an exception if invalid
		works = oauth2.validate_access_token(token_data['access_token'])
