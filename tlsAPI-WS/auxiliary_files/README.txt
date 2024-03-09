client-ca.*
Those are the files that we used to sign the USER's cert

serverCA.*
This is the ROOT CA used to sign the SERVER's SSL Cert (must be installed on test machine so it trusts the SSL of the server)

user.*
This is the key and cert that must be used by the user so the server agrees to server it contents (currently only HELLO WELCOME TO NGINX over HTTP)

