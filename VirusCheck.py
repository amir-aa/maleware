import requests,json,threading,hashlib
import os,sys,argparse



url = "https://api.metadefender.com/v4/hash/"

headers = {
    'apikey': "APIKEY"
}



def write_in_file(ofilename:str,content:str):
    with open(ofilename,'a') as f:
        f.write(content)
        f.close()
def Check_Metadefender(filehash:str,filepath:str,outputpath="scanresult.txt"):
    response=requests.get(url+filehash,headers=headers)
    
    dresponse=dict(response.json())
    try:
        print(dresponse['threat_name'])
        results_extended=dresponse['scan_results']['scan_details']
        for AVscanresult_dict in results_extended:
            if results_extended[AVscanresult_dict]['threat_found'] !="":
                report={'File':filepath,'Malware_Name':dresponse['threat_name'],'AV_Engine':AVscanresult_dict,'malware_family':dresponse['malware_family']}
                write_in_file(outputpath,f"{str(report)}\n")
                return report
            
    except KeyError:#No virus
        return None
    except Exception as e:
        print(e)
        print("Unknown Error")

def GetFileHash(filepath:str,BUF_SIZE = 16384):
     # Read file in 16kb chunks as a default value

    md5 = hashlib.md5()
    with open(filepath, 'rb') as f:

        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            
            md5.update(data)
    return md5.hexdigest()

    
def scan(path:str,hashBuffer:int=16384,threads_max=5):
    counter=0
    to_scan_list=[]
    Threadbox=[]
    for current_dir, subdirs, files in os.walk(path):
        # Current Iteration Directory
        
        # Files
        
        for filename in files:
            try:
                fullpath=os.path.join(current_dir,filename)
                h=GetFileHash(fullpath,hashBuffer)
               # print(f"[*] Hash Calculated {current_dir}{filename}")
                
                if counter < threads_max:

                    Threadbox.append(threading.Thread(target=Check_Metadefender(h,fullpath),daemon=True))
                    counter+=1
                #if the counter get max we have to ensure that threads activities are finished
                else:
                    print(len(Threadbox))
                    startfunc=lambda s:s.start()
                    map(startfunc,Threadbox)
                    fjoin=lambda t:print(t.join())
                    map(fjoin,Threadbox)
                    counter=0
                    Threadbox.clear()
                    print("batch Finished")
                    print("********************************************")
            except UnicodeEncodeError:
                pass
        

if __name__=="__main__":
    
    parser = argparse.ArgumentParser(description='Description')
    parser.add_argument('-t', '--threads',type=int, required=False,default=5)
    parser.add_argument('-b', '--buffer',type=int, required=False,default=16384)
    parser.add_argument('-p', '--path',type=str, required=True)
   
    args=parser.parse_args()
    PathtoScan=args.path
    threads_max=int(args.threads)
    hashbuffersize=args.buffer
    scan(PathtoScan,hashbuffersize,threads_max)



