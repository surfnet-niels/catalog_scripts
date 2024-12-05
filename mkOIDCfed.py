#!/usr/bin/env python3 
#-*- coding: utf-8 -*-

import xml.etree.cElementTree as ET
from operator import itemgetter
from collections import OrderedDict

import os
import datetime
import sys, getopt
import json
import hashlib
import time
import urllib.request
from pathlib import Path
from jwcrypto import jwk, jwt

LOGDEBUG = True

##################################################################################################################################
#
# Config and logs handling functions
#
##################################################################################################################################
def loadJSONconfig(json_file):
   with open(json_file) as json_file:
     return json.load(json_file)

def p(message, writetolog=True):
   if writetolog:
      write_log(message)
   else:
      print(message)
    
def pj(the_json, writetolog=True):
    p(json.dumps(the_json, indent=4, sort_keys=False), writetolog)

def write_log(message):
   datestamp = (datetime.datetime.now()).strftime("%Y-%m-%d")
   timestamp = (datetime.datetime.now()).strftime("%Y-%m-%d %X")
   f = open("./logs/" + datestamp + "_apistatus.log", "a")
   f.write(timestamp +" "+ message+"\n")
   f.close()

def write_file(contents, filepath, mkpath=True, overwrite=False):
   if mkpath:
      Path(filepath).mkdir(parents=True, exist_ok=overwrite)

   f = open(filepath, "a")
   f.write(contents+"\n")
   f.close()

##################################################################################################################################
#
# Metadata url/file handling functions
#
##################################################################################################################################

def is_file_older_than_x_days(file, days=1): 
    file_time = os.path.getmtime(file) 
    # Check against 24 hours 
    if (time.time() - file_time) / 3600 > 24*days: 
        return True
    else: 
        return False

def fetchXML(url, file_path):
  try:
    urllib.request.urlretrieve(url, file_path)
    return True
  except:
    p("ERROR: Could not download URL: " + url, LOGDEBUG)
    return False

def parseMetadataXML(file_path):
    try:
      with open(file_path) as fd:
          ent = xmltodict.parse(fd.read())
          return ent

    except:
      print("ERROR: Could not parse " +file_path)
      return {}    

def fetchMetadata(md_urls, raname, input_path):

    metadataSet = []

    for i in range(len(md_urls)):
       md_url = md_urls[i]
      
       file_path = input_path + raname.replace(" ", "_") + '_' + str(i) + '.xml'
    
       if os.path.isfile(file_path) and not (is_file_older_than_x_days(file_path, 1)):
           p("INFO: " + raname + " metadata still up to date, skipping download", LOGDEBUG)
       else:
           p("INFO: " + raname + " metadata out of date, downloading from " + md_url, LOGDEBUG)

           if (fetchXML(md_url, file_path)):
             p("INFO: Downloaded metadata: " + md_url + " to file location: " + file_path, LOGDEBUG)
           else:
             p("ERROR: Could not download metadata: " + md_url, LOGDEBUG)
             return {} 
             
       metadataSet.append(file_path)
       
       
    if len(md_urls) == 0:
      p("ERROR: No metadata URL provided for RA " + raname, LOGDEBUG)

    return metadataSet

def setRAdata(raconf, input_path, edugain_ra_uri):
  # Read RA config and loads RA metadata 
  RAs={}

  for ra in raconf.keys():
     RAs[ra] = {} 
      
     RAs[ra]["md_url"] = raconf[ra]["md_url"]
     RAs[ra]["ra_name"] = raconf[ra]["name"]
     RAs[ra]["ra_hash"] = hashSHA1(ra)
     RAs[ra]["country_code"] = raconf[ra]["country_code"]
     RAs[ra]["filepath"] = []
     RAs[ra]["ta_url"] = raconf[ra]["ta_url"]

  return RAs

##################################################################################################################################
#
# SAML Metadata processing functions
#
##################################################################################################################################

# Get entityID
def getEntityID(EntityDescriptor, namespaces):
    return EntityDescriptor.get('entityID')

# Get hased EntityID
def hashSHA1(aString):    
    return hashlib.sha1(aString.encode('utf-8')).hexdigest()

# Get MDUI Descriptions
def getDescriptions(EntityDescriptor,namespaces,entType='idp',lang='en'):

    description_list = list()
    if (entType.lower() == 'idp'):
       entityType = "./md:IDPSSODescriptor"
    if (entType.lower() == 'sp'):
       entityType = "./md:SPSSODescriptor"

    descriptions = EntityDescriptor.findall("%s/md:Extensions/mdui:UIInfo/mdui:Description" % entityType, namespaces)

    if (len(descriptions) != 0):
       for desc in descriptions:
           descriptions_dict = dict()
           descriptions_dict['value'] = desc.text
           descriptions_dict['lang'] = desc.get("{http://www.w3.org/XML/1998/namespace}lang")
           description_list.append(descriptions_dict)
    
    return description_list


# Get MDUI Logo BIG
def getLogoBig(EntityDescriptor,namespaces,entType='idp'):

    entityType = ""
    if (entType.lower() == 'idp'):
       entityType = "./md:IDPSSODescriptor"
    if (entType.lower() == 'sp'):
       entityType = "./md:SPSSODescriptor"
    
    logoUrl = ""
    logos = EntityDescriptor.findall("%s/md:Extensions/mdui:UIInfo/mdui:Logo[@xml:lang='it']" % entityType,namespaces)
    if (len(logos) != 0):
       for logo in logos:
           logoHeight = logo.get("height")
           logoWidth = logo.get("width")
           if (logoHeight != logoWidth):
              # Avoid "embedded" logos
              if ("data:image" in logo.text):
                 logoUrl = "embeddedLogo"
                 return logoUrl
              else:
                 logoUrl = logo.text
                 return logoUrl
    else:
       logos = EntityDescriptor.findall("%s/md:Extensions/mdui:UIInfo/mdui:Logo[@xml:lang='en']" % entityType,namespaces)
       if (len(logos) != 0):
          for logo in logos:
              logoHeight = logo.get("height")
              logoWidth = logo.get("width")
              if (logoHeight != logoWidth):
                 # Avoid "embedded" logos
                 if ("data:image" in logo.text):
                    logoUrl = "embeddedLogo"
                    return logoUrl
                 else:
                    logoUrl = logo.text
                    return logoUrl
       else:
           logos = EntityDescriptor.findall("%s/md:Extensions/mdui:UIInfo/mdui:Logo" % entityType,namespaces)
           if (len(logos) != 0):
              for logo in logos:
                  logoHeight = logo.get("height")
                  logoWidth = logo.get("width")
                  if (logoHeight != logoWidth):
                     # Avoid "embedded" logos
                     if ("data:image" in logo.text):
                        logoUrl = "embeddedLogo"
                        return logoUrl
                     else:
                        logoUrl = logo.text
                        return logoUrl
           else:
              return ""


# Get MDUI Logo SMALL
def getLogoSmall(EntityDescriptor,namespaces,entType='idp',format="html"):
    entityType = ""
    if (entType.lower() == 'idp'):
       entityType = "./md:IDPSSODescriptor"
    if (entType.lower() == 'sp'):
       entityType = "./md:SPSSODescriptor"
    
    logoUrl = ""
    logos = EntityDescriptor.findall("%s/md:Extensions/mdui:UIInfo/mdui:Logo[@xml:lang='it']" % entityType,namespaces)
    if (len(logos) != 0):
       for logo in logos:
           logoHeight = logo.get("height")
           logoWidth = logo.get("width")
           if (logoHeight == logoWidth):
              # Avoid "embedded" logos
              if ("data:image" in logo.text):
                 logoUrl = "embeddedLogo"
                 return logoUrl
              else:
                 logoUrl = logo.text
                 return logoUrl
    else:
       logos = EntityDescriptor.findall("%s/md:Extensions/mdui:UIInfo/mdui:Logo[@xml:lang='en']" % entityType,namespaces)
       if (len(logos) != 0):
          for logo in logos:
              logoHeight = logo.get("height")
              logoWidth = logo.get("width")
              if (logoHeight == logoWidth):
                 # Avoid "embedded" logos
                 if ("data:image" in logo.text):
                    logoUrl = "embeddedLogo"
                    return logoUrl
                 else:
                    logoUrl = logo.text
                    return logoUrl
       else:
           logos = EntityDescriptor.findall("%s/md:Extensions/mdui:UIInfo/mdui:Logo" % entityType,namespaces)
           if (len(logos) != 0):
              for logo in logos:
                  logoHeight = logo.get("height")
                  logoWidth = logo.get("width")
                  if (logoHeight == logoWidth):
                     # Avoid "embedded" logos
                     if ("data:image" in logo.text):
                        logoUrl = "embeddedLogo"
                        return logoUrl
                     else:
                        logoUrl = logo.text
                        return logoUrl
           else:
              return ""


# Get ServiceName
def getServiceName(EntityDescriptor,namespaces,lang='en'):
    serviceName = EntityDescriptor.find("./md:SPSSODescriptor/md:AttributeConsumingService/md:ServiceName[@xml:lang='it']", namespaces)
    if (serviceName != None):
       return serviceName.text
    else:
       serviceName = EntityDescriptor.find("./md:SPSSODescriptor/md:AttributeConsumingService/md:ServiceName[@xml:lang='en']", namespaces)
       if (serviceName != None):
          return serviceName.text
       else:
          return ""


# Get Organization Name
def getOrganizationName(EntityDescriptor, namespaces,lang='en'):
    orgName = EntityDescriptor.find("./md:Organization/md:OrganizationName[@xml:lang='%s']" % lang,namespaces)

    if (orgName != None):
       return orgName.text
    else:
       return ""


# Get DisplayName
def getDisplayName(EntityDescriptor, namespaces, entType='idp',lang='en'):
   entityType = ""
   if (entType.lower() == 'idp'):
      entityType = "./md:IDPSSODescriptor"
   if (entType.lower() == 'sp'):
      entityType = "./md:SPSSODescriptor"

   displayName = EntityDescriptor.find("%s/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang='en']" % entityType,namespaces)
   #langs = EntityDescriptor.find("%s/md:Extensions/mdui:DisplayName/@xml:lang" % entityType,namespaces)
   #pj(langs)

   #displayName = EntityDescriptor.find("%s/md:Extensions/mdui:DisplayName" % entityType,namespaces)

   if (displayName != None):
      #p(displayName.text)
      return displayName.text
   else:
      displayName = EntityDescriptor.find("%s/md:Extensions/mdui:DisplayName[@xml:lang='en']" % entityType,namespaces)
      if (displayName != None):
         return displayName.text
      else:
         if (entType == 'sp'):
            displayName = getServiceName(EntityDescriptor,namespaces)
            if (displayName != None):
               return displayName
            else:
               return ""
         else:
            displayName = getOrganizationName(EntityDescriptor,namespaces)
            return displayName
         
 
# Get MDUI InformationURLs
def getInformationURLs(EntityDescriptor,namespaces,entType='idp',lang='en'):
    entityType = ""
    if (entType.lower() == 'idp'):
       entityType = "./md:IDPSSODescriptor"
    if (entType.lower() == 'sp'):
       entityType = "./md:SPSSODescriptor"

    info_pages = EntityDescriptor.findall("%s/md:Extensions/mdui:UIInfo/mdui:InformationURL" % entityType, namespaces)

    info_dict = dict()
    for infop in info_pages:
        lang = infop.get("{http://www.w3.org/XML/1998/namespace}lang")
        info_dict[lang] = infop.text

    return info_dict


# Get MDUI PrivacyStatementURLs
def getPrivacyStatementURLs(EntityDescriptor,namespaces,entType='idp',lang='en'):
    entityType = ""
    if (entType.lower() == 'idp'):
       entityType = "./md:IDPSSODescriptor"
    if (entType.lower() == 'sp'):
       entityType = "./md:SPSSODescriptor"

    privacy_pages = EntityDescriptor.findall("%s/md:Extensions/mdui:UIInfo/mdui:PrivacyStatementURL" % entityType, namespaces)

    privacy_dict = dict()
    for pp in privacy_pages:
        lang = pp.get("{http://www.w3.org/XML/1998/namespace}lang")
        privacy_dict[lang] = pp.text

    return privacy_dict


# Get OrganizationURL
def getOrganizationURL(EntityDescriptor,namespaces,lang='en'):
    orgUrl = EntityDescriptor.find("./md:Organization/md:OrganizationURL[@xml:lang='%s']" % lang,namespaces)

    if (orgUrl != None):
       return orgUrl.text
    else:
       return ""


# Get RequestedAttribute
def getRequestedAttribute(EntityDescriptor,namespaces):
    reqAttr = EntityDescriptor.findall("./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute", namespaces)

    requireList = list()
    requestedList = list()
    requestedAttributes = dict()

    if (len(reqAttr) != 0):
       for ra in reqAttr:
           if (ra.get('isRequired') == "true"):
              requireList.append(ra.get('FriendlyName'))
           else:
              requestedList.append(ra.get('FriendlyName'))

    requestedAttributes['required'] = requireList
    requestedAttributes['requested'] = requestedList

    return requestedAttributes


# Get Contacts
def getContacts(EntityDescriptor,namespaces,contactType='technical', format="html"):
   #ToDo: add a more strict scan for securtiy as 'other may also be used in another way'

   name=''
   mail=''
   contactsList = list()
   contactsDict = {}
   
   contacts = EntityDescriptor.findall("./md:ContactPerson[@contactType='"+contactType.lower()+"']/md:EmailAddress", namespaces)
   contactsGivenName = EntityDescriptor.findall("./md:ContactPerson[@contactType='"+contactType.lower()+"']/md:GivenName", namespaces)
   contactsSurName = EntityDescriptor.findall("./md:ContactPerson[@contactType='"+contactType.lower()+"']/md:SurName", namespaces)

   cname = "" 
   if (len(contactsGivenName) != 0):
      for cgn in contactsGivenName:
         cname = cgn.text

   if (len(contactsSurName) != 0):
      for csn in contactsSurName:
         cname = cname + " " + csn.text

   if (len(cname) != 0):
      name = cname.strip()              

   if (len(contacts) != 0):
      for ctc in contacts:
         if ctc.text.startswith("mailto:"):
            mail = ctc.text.replace("mailto:", "")
         else:
            mail = contactsList.append(ctc.text)

   if format=="html":
      contactsList.append(name) 
      contactsList.append(mail)
      return '<br/>'.join(contactsList)
   else:
      contactsDict['name']=name
      contactsDict['email']=mail
      return contactsDict

def formatInfo(infoDict, format="html", lang="en"):
   
   match format:
      case "html":
         info = "<ul>"
         for lng in infoDict:
            flag = lng
            
            if lng == "en":
               flag = "gb"
            
            info = info + "<li><a href='"+infoDict[lng]+ "' target='_blank'><img src='https://flagcdn.com/24x18/"+flag+".png' alt='Info "+lng.upper()+"' height='18' width='24' /></a></li>"
         info = info + "</ul>"
      case "json":
         info = infoDict
   
   return info

def formatPrivacy(privacyDict, format="html", lang="en"):
   #ToDO: propper language processing in case of HTML
   privacy = {}

   if len(privacyDict)!=0:
      match format:
         case "html":
            privacy = "<ul>"
            for lang in privacyDict:
               flag = lang
               if lang == "en":
                  flag = "gb"
            privacy = privacy + "<li><a href='"+privacyDict[lang]+ "' target='_blank'><img src='https://flagcdn.com/24x18/"+flag+".png' alt='Info "+lang.upper()+"' height='18' width='24' /></a></li>"
            privacy = privacy + "</ul>"      
         case "json":
            privacy = privacyDict
   
   return privacy

def formatOrg(orgName, orgUrl, format="html", lang="en"):
   org={}
   
   match format:
      case "html":
         org = "<a href='%s' target='_blank'>%s</a>" % (orgUrl,orgName)
      case "json":
         org["name"]={}
         org["name"]["en"] = orgName
         org["url"]={}
         org["url"]["en"] = orgUrl
   
   return org

##################################################################################################################################
#
# OIDCfed stuff
#
##################################################################################################################################

def mkJWK(entityHash): 

   kid= hashSHA1(entityHash + str(datetime.datetime.now()))

   return jwk.JWK.generate(kty='EC', crv='P-256', use='sig', kid=kid)

def exportKey(keys, type="public"):
   if type=="private":
      return keys.export(private_key=True)
   else:
      return keys.export(private_key=False)

def updateOIDCfedMetadata(leaf, element, elementValue, action="append"):
  
   match element:
      case 'authority_hints':
         if action == "append":
            leaf["metadata"]['authority_hints'].append(elementValue)

def mkOIDCfedMetadata(leaf_dict, baseURL):

   if leaf_dict['type'] == 'op':
      openid_provider = '''{
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "claims_parameter_supported": true,
            "request_parameter_supported": true,
            "request_uri_parameter_supported": true,
            "require_request_uri_registration": false,
            "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"],
            "jwks_uri": "'''+baseURL + '''leafs/''' + leaf_dict['id']+'''/OIDC/jwks",
            "scopes_supported": ["openid", "profile", "email", "eduperson_assurance", "eduperson_entitlement", "eduperson_orcid", "eduperson_principal_name", "eduperson_scoped_affiliation", "voperson_external_affiliation", "voperson_external_id", "voperson_id", "aarc", "ssh_public_key", "orcid", "schac_home_organization", "schac_personal_unique_code"],
            "response_types_supported": ["code", "id_token token"],
            "response_modes_supported": ["query", "fragment", "form_post"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "HS256", "HS384", "HS512"],
            "userinfo_signing_alg_values_supported": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "HS256", "HS384", "HS512"],
            "request_object_signing_alg_values_supported": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "HS256", "HS384", "HS512"],
            "claim_types_supported": ["normal"],
            "claims_supported": ["sub", "eduperson_targeted_id", "eduperson_unique_id", "eduperson_orcid", "eaahash", "uid", "name", "given_name", "email", "name", "family_name", "eduperson_scoped_affiliation", "eduperson_affiliation", "eduperson_principal_name", "eduperson_entitlement", "eduperson_assurance", "schac_personal_unique_code", "schac_home_organization", "eidas_person_identifier", "ssh_public_key", "voperson_external_affiliation", "voperson_external_id", "voperson_id", "voperson_application_uid", "voperson_scoped_affiliation", "voperson_sor_id", "voperson_policy_agreement", "voperson_status", "eduid_cz_loa"],
            "code_challenge_methods_supported": ["S256"],
            "issuer": "'''+baseURL + '''leafs/''' + leaf_dict['id']+'''",
            "authorization_endpoint": "'''+baseURL + '''leafs/''' + leaf_dict['id']+'''/saml2sp/OIDC/authorization",
            "token_endpoint": "'''+baseURL + '''leafs/''' + leaf_dict['id']+'''/OIDC/token",
            "userinfo_endpoint": "'''+baseURL + '''leafs/''' + leaf_dict['id']+'''/OIDC/userinfo",
            "introspection_endpoint": "'''+baseURL + '''leafs/''' + leaf_dict['id']+'''/OIDC/introspect",
            "revocation_endpoint": "'''+baseURL + '''leafs/''' + leaf_dict['id']+'''/OIDC/revoke"
        }'''
   
      p(openid_provider)
      metadata=OrderedDict([
         ("openid_provider", json.loads(openid_provider)),
      ]) 
   
   if leaf_dict['type'] == 'rp':
      openid_relying_party=OrderedDict([
      ('client_name', leaf_dict['resourceName']),
      ('contacts',leaf_dict['resourceContacts']),
      ('application_type', "web"),
      ('client_registration_types', ["automatic"]),
      ('grant_types',["refresh_token", "authorization_code"]),
      ('redirect_uris',[baseURL + "leafs/" + leaf_dict['id'] +"/oidc/rp/redirect"]),
      ('response_types', ["code"]),
      ('logo_uri', leaf_dict['logo']),
      ('client_uri', leaf_dict['id']),
      ('logo_uri', leaf_dict['logo']),
      ('subject_type', "pairwise"),
      ('tos_uri', baseURL + "leafs/" + leaf_dict['id'] +"/tos"),
      ('policy_uri', leaf_dict['privacy']),
      ('jwks',exportKey(leaf_dict['keys'], "public"))
      ]) 

      metadata=OrderedDict([
         ("openid_relying_party", openid_relying_party),
      ]) 

   now = datetime.datetime.now()
   iat = datetime.datetime.timestamp(now) # Today
   exp = datetime.datetime.timestamp(now + datetime.timedelta(days=3650)) # Set exp to 10 years

   # Build OIDCfed metadata
   leafMetadata = OrderedDict([
   ("iss", baseURL + "leafs/" + leaf_dict['id'] +"/"),
   ("sub", baseURL + "leafs/" + leaf_dict['id'] +"/"),
   ("iat", iat), 
   ("exp", exp), 
   ('jwks',exportKey(leaf_dict['keys'], "public")),
   ('metadata', metadata),
   ("trust_marks", []),
   ('authority_hints', [leaf_dict['taURL']]) # Lookup RA/TA dynamically
   ]) 

   return(leafMetadata)

def mkSignedOIDCfedMetadata(leafMetadata, key):
   encoded_data = jwt.JWT(header={"alg": "ES256"},
                     claims=leafMetadata)
   encoded_data.make_signed_token(key)
   encoded_data.serialize()  
   return encoded_data

##################################################################################################################################
#
# testbed
#
##################################################################################################################################
def uploadMetadata(taUrl, sub):
   message =dict(entity_type="openid_relying_party", sub=sub)
   taUrl = taUrl + "/enroll"

   #p("curl -v -X POST -H 'Content-Type: application/json' -d '"+message+"' "+taUrl)

   message = urllib.parse.urlencode(message).encode("utf-8")
   req = urllib.request.Request(taUrl, message)
   resp = urllib.request.urlopen(req).read().decode('utf-8')
   print(resp)

##################################################################################################################################
#
# Output files
#
##################################################################################################################################
def writeFile(contents, fileid, outputpath, filetype='json', mkParents=True, overwrite=True):
   
   match filetype:
      case 'json':
         leafsPath = outputpath + "leafs/" + fileid + "/"

         # Write the json to the leaf url
         Path(leafsPath).mkdir(parents=mkParents, exist_ok=overwrite)
         contentFile = open(leafsPath+".json", "w",encoding=None)
         contentFile.write(json.dumps(contents,sort_keys=False, indent=4, ensure_ascii=False,separators=(',', ':')))
      case 'jwk':
         keysPath = outputpath + "keys/"
         
         # Write the jwk to the keys path outside of the public html url
         Path(keysPath).mkdir(parents=mkParents, exist_ok=overwrite)
         contentFile = open(keysPath+fileid+".jwk", "w",encoding=None)
         contentFile.write(json.dumps(contents,sort_keys=False, indent=4, ensure_ascii=False,separators=(',', ':')))
      case 'jwt':
         fedMetaPath = outputpath + "leafs/" + fileid + "/.well-known/"
         # Write the jwt diorectly to the metadata endpoint
         Path(fedMetaPath).mkdir(parents=mkParents, exist_ok=overwrite)
         contentFile = open(fedMetaPath+"openid-federation", "w",encoding=None)
         contentFile.write(str(contents))  
      
   contentFile.close()

def parseLeaf(ra, raList, entityList, inputfile, outputpath, namespaces, format="html", baseURL = "https://example.org/"):
   #p("Working on: " + inputfile) 
    
   # JSON/HTML SP Output per entity
   # [
   #   {
   #     "id": #_sha1-hash-over-entityID_#,
   #     "resourceName": "#_resource-display-name_#",
   #     "resourceProvider": "#_organization-name-linked_#",
   #     "resourceAttributes": {
   #        "required": [
   #                      "eduPersonPrincipalName",
   #                      "email",
   #                      "givenName",
   #                      "surname"
   #                    ],
   #        "requested": []
   #     },
   #     "entityID": "#_entityID-resource_#",
   #     "resourceContacts": {
   #        "technical": [
   #                       "#_email-address-list_#"
   #                     ],
   #        "support": [],
   #        "administrative": []
   #     },
   #     "info": "<a href='#_info-url-it_#'>IT</a>, <a href='#_info-url-en_#'>EN</a>",
   #     "privacy": "<a href='#_privacy-url-it_#'>IT</a>, <a href='#_privacy-url-en_#'>EN</a>"
   #   }
   # ]

   tree = ET.parse(inputfile)
   root = tree.getroot()
   sp = root.findall("./md:EntityDescriptor[md:SPSSODescriptor]", namespaces)
   idp = root.findall("./md:EntityDescriptor[md:IDPSSODescriptor]", namespaces)

   ra_hash = raList[ra]["ra_hash"]
   ra_name = raList[ra]["ra_name"]
   ta_url = raList[ra]["ta_url"]

   for EntityDescriptor in idp:
         info = ""
         privacy = ""
         
         # Get entityID
         entityID = getEntityID(EntityDescriptor,namespaces)
         #p(entityID)
               
         if entityID == entityID:
            # Start processing SAML metadata for this entity and put that in a dict

            # Get hashed entityID
            cont_id = hashSHA1(entityID)

            # If an entity is already in the list of entties we do not need to provess the metadata and we only need to append the TA
            if cont_id in entityList: 
               p("DUP found! " + cont_id)
               # Update TA
               updateOIDCfedMetadata(entityList[cont_id], 'authority_hints',  ta_url)
            else:

               # Get InformationURL
               infoDict = getInformationURLs(EntityDescriptor, namespaces, 'idp')

               # Get PrivacyStatementURL
               privacyDict = getPrivacyStatementURLs(EntityDescriptor, namespaces, 'idp')

               # Get ServiceName
               serviceName = getDisplayName(EntityDescriptor,namespaces,'idp')

               # Build Resource Info Pages
               info = formatInfo(infoDict, format)

               # Build Resource Privacy Pages
               privacy = formatPrivacy(privacyDict, format)

               # Get Requested Attributes
               requestedAttributes = getRequestedAttribute(EntityDescriptor,namespaces)

               # Get Organization
               orgName = getOrganizationName(EntityDescriptor,namespaces,'en')
               orgURL = getOrganizationURL(EntityDescriptor,namespaces,'en')
               org = formatOrg(orgName, orgURL, format)

               # Get Contacts
               techContacts = getContacts(EntityDescriptor, namespaces, 'technical', 'json')
               suppContacts = getContacts(EntityDescriptor, namespaces, 'support', 'json')
               adminContacts = getContacts(EntityDescriptor, namespaces, 'administrative', 'json')
               securityContacts = getContacts(EntityDescriptor, namespaces, 'other', 'json')
               contacts = OrderedDict([
                  ('technical', techContacts),
                  ('support', suppContacts),
                  ('administrative', adminContacts),
                  ('security', securityContacts),
               ])

               logo = getLogoSmall(EntityDescriptor, namespaces, 'idp', format)

               # End of processing SAML metadata for this entity 
               # Now transform that to OIDCfed metadata

               # Generate key material
               keys=mkJWK(cont_id)

               # Build LEAF JSON Dictionary
               # Take care: this dict holds the leaf private key!
               leaf = OrderedDict([
               ('id',cont_id),
               ('type', 'op'),
               ('ra',ra_hash),
               ('raName',ra_name),
               ('taURL',ta_url),
               ('resourceName',serviceName),
               ('resourceProvider', org),
               ('resourceAttributes',requestedAttributes),
               ('entityID',entityID),
               ('resourceContacts',contacts), # Formatting not correct?
               ('info', info),
               ('logo', logo),
               ('privacy', privacy),
               ('keys', keys)
               ])     

               #Generate and Write json formatted metadata
               leafMetadata = mkOIDCfedMetadata(leaf,baseURL) 
      
               # Add leaf to entityList
               #if cont_id not in entityList: This should not happen...
               entityList[cont_id]=OrderedDict([
                  ('base', leaf),
                  ('metadata', leafMetadata)
               ]) 

   for EntityDescriptor in sp:
      info = ""
      privacy = ""
      
      # Get entityID
      entityID = getEntityID(EntityDescriptor,namespaces)
      #p(entityID)
            
      if entityID == entityID:
         # Start processing SAML metadata for this entity and put that in a dict

         # Get hashed entityID
         cont_id = hashSHA1(entityID)

         # If an entity is already in the list of entties we do not need to provess the metadata and we only need to append the TA
         if cont_id in entityList: 
            p("DUP found! " + cont_id)
            # Update TA
            updateOIDCfedMetadata(entityList[cont_id], 'authority_hints',  ta_url)
         else:

            # Get InformationURL
            infoDict = getInformationURLs(EntityDescriptor, namespaces, 'sp')

            # Get PrivacyStatementURL
            privacyDict = getPrivacyStatementURLs(EntityDescriptor, namespaces, 'sp')

            # Get ServiceName
            serviceName = getDisplayName(EntityDescriptor,namespaces,'sp')

            # Build Resource Info Pages
            info = formatInfo(infoDict, format)

            # Build Resource Privacy Pages
            privacy = formatPrivacy(privacyDict, format)

            # Get Requested Attributes
            requestedAttributes = getRequestedAttribute(EntityDescriptor,namespaces)

            # Get Organization
            orgName = getOrganizationName(EntityDescriptor,namespaces,'en')
            orgURL = getOrganizationURL(EntityDescriptor,namespaces,'en')
            org = formatOrg(orgName, orgURL, format)

            # Get Contacts
            techContacts = getContacts(EntityDescriptor, namespaces, 'technical', 'json')
            suppContacts = getContacts(EntityDescriptor, namespaces, 'support', 'json')
            adminContacts = getContacts(EntityDescriptor, namespaces, 'administrative', 'json')
            securityContacts = getContacts(EntityDescriptor, namespaces, 'other', 'json')
            contacts = OrderedDict([
               ('technical', techContacts),
               ('support', suppContacts),
               ('administrative', adminContacts),
               ('security', securityContacts),
            ])

            logo = getLogoSmall(EntityDescriptor, namespaces, 'idp', format)

            # End of processing SAML metadata for this entity 
            # Now transform that to OIDCfed metadata

            # Generate key material
            keys=mkJWK(cont_id)

            # Build LEAF JSON Dictionary
            # Take care: this dict holds the leaf private key!
            leaf = OrderedDict([
            ('id',cont_id),
            ('type', 'rp'),
            ('ra',ra_hash),
            ('raName',ra_name),
            ('taURL',ta_url),
            ('resourceName',serviceName),
            ('resourceProvider', org),
            ('resourceAttributes',requestedAttributes),
            ('entityID',entityID),
            ('resourceContacts',contacts), # Formatting not correct?
            ('info', info),
            ('logo', logo),
            ('privacy', privacy),
            ('keys', keys)
            ])     

            #Generate and Write json formatted metadata
            leafMetadata = mkOIDCfedMetadata(leaf,baseURL) 
   
            # Add leaf to entityList
            #if cont_id not in entityList: This should not happen...
            entityList[cont_id]=OrderedDict([
               ('base', leaf),
               ('metadata', leafMetadata)
            ]) 

def parseIdPs(ra_hash, inputfile, outputpath, namespaces, format="html"):
   p("Working on: " + inputfile) 

   # JSON IdP Output:
   # [
   #   {
   #     "id": #_sha1-hash-over-entityID_#,
   #     "resourceName": "#_resource-display-name_#",
   #     "resourceProvider": "#_organization-name-linked_#",
   #     "entityID": "#_entityID-resource_#",
   #     "resourceContacts": {
   #        "technical": [
   #                       "#_email-address-list_#"
   #                     ],
   #        "support": [],
   #        "administrative": []
   #     },
   #     "info": "<a href='#_info-url-it_#'>IT</a>, <a href='#_info-url-en_#'>EN</a>",
   #     "privacy": "<a href='#_privacy-url-it_#'>IT</a>, <a href='#_privacy-url-en_#'>EN</a>"
   #   }
   # ]

   tree = ET.parse(inputfile)
   root = tree.getroot()
   idp = root.findall("./md:EntityDescriptor[md:IDPSSODescriptor]", namespaces)

   idps = dict()
   list_idps = list()

   #cont_id = ""

   for EntityDescriptor in idp:
      info = ""
      privacy = ""
      
      # Get entityID
      entityID = getEntityID(EntityDescriptor,namespaces)
      p(entityID)

      if entityID == entityID:
          
         # Get hashed entityID
         cont_id = hashSHA1(entityID)

         # Get InformationURL
         infoDict = getInformationURLs(EntityDescriptor, namespaces, 'idp', "en")

         # Get PrivacyStatementURL
         privacyDict = getPrivacyStatementURLs(EntityDescriptor, namespaces, 'idp', "en")

         # Get ResourceName
         resourceName = getDisplayName(EntityDescriptor,namespaces,'idp', "en")

         # Build Resource Info Pages
         info = formatInfo(infoDict, format, "en")

         # Build Resource Privacy Pages
         privacy = formatPrivacy(privacyDict, format, "en")

         # Get Organization
         orgName = getOrganizationName(EntityDescriptor,namespaces,'en')
         orgURL = getOrganizationURL(EntityDescriptor,namespaces,'en')
         org = formatOrg(orgName, orgURL, format)

         # Get Contacts
         techContacts = getContacts(EntityDescriptor, namespaces, 'technical', format)
         suppContacts = getContacts(EntityDescriptor, namespaces, 'support', format)
         adminContacts = getContacts(EntityDescriptor, namespaces, 'administrative', format)
         securityContacts = getContacts(EntityDescriptor, namespaces, 'other', format)

         logo = getLogoSmall(EntityDescriptor, namespaces, 'idp', format)

         contacts = OrderedDict([
            ('technical', techContacts),
            ('support', suppContacts),
            ('administrative', adminContacts),
            ('security', securityContacts),
         ])

         # Build IdP JSON or HTML Dictionary
         idp = OrderedDict([
         ('id',cont_id),
         ('ra',ra_hash),
         ('resourceName',resourceName),
         ('resourceProvider', org),
         ('entityID',entityID),
         ('resourceContacts',contacts),
         ('info', info),
         ('logo', logo),
         ('privacy', privacy)
         ])     

      # per SP outup
      #path = all_outputpath + "/" + cont_id + ".json"
      #Path(all_outputpath).mkdir(parents=True, exist_ok=True)
      #result_sp = open(path, "w",encoding=None)
      #result_sp.write(json.dumps(sp,sort_keys=False, indent=4, ensure_ascii=False,separators=(',', ':')))
      #result_sp.close()

      list_idps.append(idp)

   #all SPs in one fed 
   path = outputpath + "/" + ra_hash + "/idps.json"
   Path(outputpath + ra_hash).mkdir(parents=True, exist_ok=True)
   result_idps = open(path, "w",encoding=None)
   result_idps.write(json.dumps(list_idps,sort_keys=False, indent=4, ensure_ascii=False,separators=(',', ':')))
   result_idps.close()

def main(argv):

   # SAML metadata handling and general io param's
   ROOTPATH='.'
   CONFIG_PATH = ROOTPATH + '/config/'
   INPUT_PATH = ROOTPATH + '/feeds/'
   OUTPUT_PATH = '/tmp/output/'
   EDUGAIN_RA_URI = 'https://www.edugain.org'
   entityList = {}
   inputfile = None
   inputpath = INPUT_PATH
   outputpath = OUTPUT_PATH

   namespaces = {
      'xml':'http://www.w3.org/XML/1998/namespace',
      'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
      'mdrpi': 'urn:oasis:names:tc:SAML:metadata:rpi',
      'shibmd': 'urn:mace:shibboleth:metadata:1.0',
      'mdattr': 'urn:oasis:names:tc:SAML:metadata:attribute',
      'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
      'ds': 'http://www.w3.org/2000/09/xmldsig#',
      'mdui': 'urn:oasis:names:tc:SAML:metadata:ui'
   }

   #OIDCfed params
   baseURL = "https://oidcfed.sa5vopaas.utr.surfcloud.nl/"
   metadataURLpath = ".well-known/openid-federation/"
   KEYS_PATH = ROOTPATH + '/keys/'

   # ToDo: make this a bit less brittle
   #fedName = inputfile.replace(inputpath, '').replace('.xml', '')
   #fed_outputpath=outputpath + "/" + fedName   
   #all_outputpath=outputpath + "/entities"

   # First load RA config
   raConf = loadJSONconfig(CONFIG_PATH + 'RAs2.json')
   RAs = setRAdata(raConf, INPUT_PATH, EDUGAIN_RA_URI)

   # For each RA process the entities
   for ra in RAs.keys():
        # Load entity data from federation endpoint(s) and retrunme the file locations
        RAs[ra]["filepath"] = fetchMetadata(RAs[ra]["md_url"], RAs[ra]["ra_name"], INPUT_PATH)
 
        # Now loop over RAs files to extract SP metadata and work that into a json
        parseLeaf(ra, RAs, entityList, RAs[ra]["filepath"][0], outputpath, namespaces, "json", baseURL)
        #parseIdPs(RAs[ra]["ra_name"], RAs[ra]["filepath"][0], outputpath, namespaces, "json")

   #Now we have processed all entities, write out the metadata to file
   #pj(entityList)
   
   for leafID in entityList:
      #pj(entityList[leafID])
      leafKeys = entityList[leafID]['base']['keys']
      leafMeta = entityList[leafID]['metadata']
      # Generic filepath for leafs

      #Export and Write private key
      writeFile(exportKey(leafKeys, "private"), leafID, outputpath, "jwk")
      #pj(leafMetadata)
      writeFile(leafMeta, leafID, outputpath, "json")

      #Generate and Write jwt signed metadata
      signedLeafMetadata = mkSignedOIDCfedMetadata(leafMeta, leafKeys)
      #p(signedLeafMetadata)
      writeFile(signedLeafMetadata, leafID, outputpath, "jwt")

      uploadMetadata(entityList[leafID]['base']['taURL'], entityList[leafID]['metadata']['sub'], entityList[leafID]['base']['type'])

if __name__ == "__main__":
   main(sys.argv[1:])
