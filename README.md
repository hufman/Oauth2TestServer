Oauth2TestServer
================

This is a simple program that implements an Oauth2 server. It replicates the behavior of the [Google Oauth2 server](https://developers.google.com/accounts/docs/OAuth2WebServer). It also has a REST interface to manage the client\_id and client\_secret parts.

Client Management
-----------------

POST to /client to receive a urlencoded data blob with client\_id and client\_secret keys.

PUT to /client by sending a urlencoded client\_id and client\_secret.

DELETE to /client by sending a urlencoded client\_id and client\_secret.

Oauth2 Functionality
--------------------

GET /auth with the normal Oauth2 parameters (client\_id, redirect\_uri, scope) to receive a redirect with the auth\_code.

POST /token with code={auth\_code}, along with client\_id, client\_secret, and the grant\_type=authorization\_code, to get an access\_token. If the /auth endpoint received an access\_type=offline, this will also send a refresh\_token.

POST /token with refresh\_token={refresh\_token}, along with client\_id, client\_secret, and the grant\_type=refresh\_code, to get an access\_token.

GET /validate?token={access\_token\}, which will return 200 if valid and 401 if not.
