import requests,json,threading
import os


path="g:\\videos\\"
url = "https://api.metadefender.com/v4/hash/"

headers = {
    'apikey': "MetaDefenderKEY"
}

def Check_Metadefender(filehash):
    response=requests.get(url+filehash,headers=headers)
    dresponse=dict(response.json())
    try:
        print(dresponse['threat_name'])
        results_extended=dresponse['scan_results']['scan_details']
        for AVscanresult_dict in results_extended:
            if results_extended[AVscanresult_dict]['threat_found'] !="":
                
                return {'Name':dresponse['threat_name'],'AV_Engine':AVscanresult_dict,'malware_family':dresponse['malware_family']}
            
    except KeyError:#No virus
        pass
    except:
        print("Unknown Error")

            
#print(Check_Metadefender("0d770e0d6ee77ed9d53500688831040b83b53b9de82afa586f20bb1894ee7116"))