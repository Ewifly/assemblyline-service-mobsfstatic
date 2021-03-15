import json
import os
import random
from requests_toolbelt import MultipartEncoder
import requests
import magic

from assemblyline.common.hexdump import hexdump
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT


API_KEY_SIZE = 64
SERVER = "http://192.168.10.78:8000/"

class Mobsfstatic(ServiceBase):
    def __init__(self, config=None):
        super(Mobsfstatic, self).__init__(config)

    def start(self):
        self.log.debug("MobSF service called")

    def stop(self):
        self.log.debug("MobSF service ended")

    def upload(self, file, apikey):
        # Upload a file
        self.log.debug("Uploading file : " + str(file))
        multipart_data = MultipartEncoder(fields={'file': (file, open(file, 'rb'), 'application/octet-stream')})
        headers = {'Content-Type': multipart_data.content_type, 'Authorization': apikey}
        
        
        resp = requests.post(SERVER + 'api/v1/upload', data=multipart_data, headers=headers)
        
        return resp.json()


    def scan(self, data, apikey):
        # Scan a file
        # @ARG1 : valid return value from upload()
        self.log.debug("Scanning file")
        data = json.dumps(data)
        data_obj = json.loads(data)
        headers = {'Authorization': apikey}
        requests.post(SERVER + 'api/v1/scan', data=data_obj, headers=headers)


    def delete(self, dataobj, apikey):
        # Delete scan
        self.log.debug("Deleting Scan")
        headers = {'Authorization': apikey}
        dataobj = json.dumps(dataobj)
        data_obj = {"hash": json.loads(dataobj)["hash"]}
        requests.post(SERVER + 'api/v1/delete_scan', data=data_obj, headers=headers)


    def generate_pdf(self, data, apikey):
        # generate pdf report
        self.log.debug(f'Requesting PDF report for')
        headers = {'Authorization': apikey}
        data = json.dumps(data)
        data_obj = {"hash": json.loads(data)["hash"]}
        response = requests.post(SERVER + 'api/v1/download_pdf', data=data_obj, headers=headers, stream=True)
        # building the pdf file from the response
        with open("report.pdf", 'wb') as doc:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    doc.write(chunk)
        self.log.debug("Report saved as report.pdf")


    def generate_json(self, data, apikey):
        # generate JSON report
        self.log.debug("generating JSON report")
        headers = {'Authorization': apikey}
        data = json.dumps(data)
        data_obj = {"hash": json.loads(data)["hash"]}
        resp = requests.post(SERVER + 'api/v1/report_json', data=data_obj, headers=headers)
        return resp.text


    def execute(self, request):
        """ call to mobsf """
        APIKEY = 'fa5e0f4bab4704b9c9d9d691b91ff360d8ab560804bb428e9f269ec7c0b0d331'

        source = request.file_path
        dest = source + ".apk"
        
        os.rename(source, dest)
        # """ API KEY RETRIEVING """
        # API_DOC = "api_docs"
        # html = requests.get(SERVER + API_DOC)
        # with open('doc.txt', "w+") as f:
        #     f.write(html.text)
        # with open('doc.txt', 'r') as f:
        #     datafile = f.readlines()
        #     for line in datafile:
        #         if "REST API Key" in line:
        #             for i in range(API_KEY_SIZE):
        #                 APIKEY = APIKEY + line[42 + i]
        # if os.path.exists("doc.txt"):
        #     os.remove("doc.txt")
        # if os.path.exists("doc.html"):
        #     os.remove("doc.html")

        """retrieve results"""
        APK = self.upload(dest, APIKEY)
        self.log.debug("\nresult :")
        self.log.debug(APK)
        self.scan(APK, APIKEY)
        self.generate_pdf(APK, APIKEY)
        json_mobsf = {}# self.generate_json(APK, APIKEY)
        json_mobsf['body'] = 'dumb text'
        """let's build the result section"""
        result = Result()
        text_section = ResultSection('MobSF Static section')
        result.add_section(text_section)

        report_section = ResultSection("Informations from MobSF", body_format=BODY_FORMAT.JSON,
                                        body = json.dumps(json_mobsf))
        result.add_section(report_section)

        """save PDF report from MobSF"""
        #TODO
        request.add_supplementary("report.pdf", "report.pdf", "PDF of the static analysis from MobSF")
        request.result = result
        
        """cleaning up"""
        self.delete(APK, APIKEY)
        """renaming the file again to allow assemblyline to remove it duh"""
        os.rename(dest, source)
        