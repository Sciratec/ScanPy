import requests, json, sys, time, shutil

args = sys.argv[1:]

headers = {
    'API-Key': '$APIKey', # Supply own key
    'Content-Type': 'application/json'
    }

publicPrivate = input("Private scan y/n? (Default: Public)\n")

def getimg(imgURL):
    filename = str(imgURL).split("/")[-1]
    getImage = requests.get(imgURL, headers=headers, stream=True)
    
    if getImage.status_code == 200:
        getImage.raw.decode_content == True
        with open(filename, 'wb') as f:
            shutil.copyfileobj(getImage.raw,f)
        print("Screenshot Downloaded")
    else:
        print(f"Cannot get image. Reason: {getImage.status_code}")

def phishingSite(url, ip, asn):
    print(f"\n{url} is a phishing site!")
    print(f"URL: {url} - IP: {ip} - Host: {asn}")
    

def checkVerdicts(apiResult):
    verdicts = apiResult['verdicts']
    url = apiResult['page']['url']
    ip = apiResult['page']['ip']
    asn = apiResult['page']['asnname']



    if "phishing" in verdicts['overall']['tags']:
        phishingSite(url, ip, asn)
    elif "phishing" in verdicts['urlscan']['tags']:
        phishingSite(url, ip, asn)
    elif "phishing" in verdicts['community']['tags']:
        phishingSite(url, ip, asn)
    else:
        print(f"{url} is clean")
        
    getImage = input("Download screenshot? y/n (Default: no)\n")

    if getImage == None or getImage.lower() == "n":
        exit()
    elif getImage.lower() == 'y':
        getimg(apiResult['task']['screenshotURL']) 


def resultsOfScan(jsonResp):
    jsonLoads = json.loads(jsonResp)
    if jsonLoads['message'] == 'Submission successful':
        apiResult = requests.get(jsonLoads['api'], headers=headers)
        checkVerdicts(json.loads(apiResult.text))
    else:
        print(jsonLoads['message'])

for arg in args:
    
    if publicPrivate == None or publicPrivate.lower() == "n":
        data = {"url": arg, "visibility": "public"}
        response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
        print(f"Waiting for urlscan to finish scanning {arg}...")
        time.sleep(30)
        resultsOfScan(response.text)
    elif publicPrivate.lower() == "y":
        data = {"url": arg, "visibility": "private"}
        response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
        print(f"Waiting for urlscan to finish scanning {arg}...")
        time.sleep(30)
        resultsOfScan(response.text)
    else:
        print("Not an option")