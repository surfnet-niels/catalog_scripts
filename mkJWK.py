#!/usr/bin/env python3 
#-*- coding: utf-8 -*-

from jwcrypto import jwk, jwt
import json

def pj(the_json):
    print(json.dumps(the_json, indent=4, sort_keys=True))

def mkJWK(entityHash): 
   return jwk.JWK.generate(kty='EC', crv='P-256', use='sig', kid=entityHash)
   #return jwk.JWK.generate(kty=keytype, size=keysize, use='sig', kid=entityHash)

#print(json.dumps(mkJWK('07c8274a353aa691772bbc6827e889f563e5bee5'), indent=4, sort_keys=True))
#key = mkJWK('a67c0b12cf2ae510e7ddcf54341b3fc165d01e2f')
#entityHash='a67c0b12cf2ae510e7ddcf54341b3fc165d01e2f'
#key = jwk.JWK(generate='oct', kty='RSA', size=2048, alg='RSA-OAEP-256', use='sig', kid=entityHash)
#key = jwk.JWK.generate(generate='oct', kty='RSA', size=2048, alg='RSA-OAEP-256', use='sig', kid=entityHash)
#key = jwk.JWK.generate(kty='EC', crv='P-256')

key = mkJWK('a67c0b12cf2ae510e7ddcf54341b3fc165d01e2f')
#key = jwk.JWK.generate(kty='RSA', size=2048, use='sig', kid=entityHash)
#key = jwk.JWK.generate(kty='EC', crv='P-256', use='sig', kid=entityHash)

pj("Private Key: " + key.export(private_key=False))
pj("Public Key: " + key.export(private_key=True))

t = jwt.JWT(header={"alg": "ES256"},
            claims={"info": "I'm a signed token"})

#print(type(key))
#t.make_signed_token(key)
#pj(t.serialize())       #doctest: +ELLIPSIS
