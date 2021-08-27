

host = 'https://api.mastersindia.co'
certificate = 'qa_certs/qa_server.crt'
gstr_urls = {
    'ACCESS_TOKEN' : host + '/oauth/access_token',
    'auth_url' : host + '/v1.0/authenticate',
    'save_gstr_url' :host + '/v2.0/returns/gstr1',
    'Track_status_url' : host + '/v0.3/returns',
    'CERIFICATE_PATH': certificate
}

GstinInfo={     
    'gstin':'',
    'state':'',
    'gst_username':''
    
}

accessTokenInfo={    
    'username' :'',
    'password' :'',
    'client_id' :'',
    'client_secret' :'',
    'grant_type' : 'password'
}
