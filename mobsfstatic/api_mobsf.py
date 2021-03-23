import json
import os
import random
from requests_toolbelt import MultipartEncoder
import requests
import magic
import tempfile


def upload(file, server, apikey):
    # Upload a file
    multipart_data = MultipartEncoder(fields={'file': (file, open(file, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': apikey}


    resp = requests.post(server + 'api/v1/upload', data=multipart_data, headers=headers)

    return resp.json()


def scan(data, server, apikey):
    # Scan a file
    # @ARG1 : valid return value from upload()
    data = json.dumps(data)
    data_obj = json.loads(data)
    headers = {'Authorization': apikey}
    requests.post(server + 'api/v1/scan', data=data_obj, headers=headers)


def delete(dataobj, server, apikey):
    # Delete scan
    headers = {'Authorization': apikey}
    dataobj = json.dumps(dataobj)
    data_obj = {"hash": json.loads(dataobj)["hash"]}
    requests.post(server + 'api/v1/delete_scan', data=data_obj, headers=headers)


def generate_pdf(data, fdfile, server, apikey):
    # generate pdf report
    headers = {'Authorization': apikey}
    data = json.dumps(data)
    data_obj = {"hash": json.loads(data)["hash"]}
    response = requests.post(server + 'api/v1/download_pdf', data=data_obj, headers=headers, stream=True)
    # building the pdf file from the response
    with os.fdopen(fdfile, 'wb') as doc:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                doc.write(chunk)

def generate_json(data, server, apikey):
    # generate JSON report
    headers = {'Authorization': apikey}
    data = json.dumps(data)
    data_obj = {"hash": json.loads(data)["hash"]}
    resp = requests.post(server + 'api/v1/report_json', data=data_obj, headers=headers)
    return resp.text

def generate_code(data, fdfile, type, server):
    hash = data["hash"]
    req=requests.get(server + 'generate_downloads/?hash=' + hash + '&file_type=' + type)
    if req.status_code == 200:
        response = requests.get(server + 'download/' + hash + "-" + type + ".zip", stream=True)
        open(fdfile, 'wb').write(response.content)