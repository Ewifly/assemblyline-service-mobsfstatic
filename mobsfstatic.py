import json
import os
import random
from requests_toolbelt import MultipartEncoder
import requests
import magic

from assemblyline.common.hexdump import hexdump
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT

class Mobsfstatic(ServiceBase):
    def __init__(self, config=None):
        super(Mobsfstatic, self).__init__(config)

    def start(self):
        self.log.debug("MobSF service called")

    def stop(self):
        self.log.debug("MobSF service ended")

    def upload(self, file):
        print('XOXOXOXOXOXOXOXOXOXOXOXOXOXOXO')
        print(self.APIKEY)
        # Upload a file
        self.log.debug("Uploading file : " + str(file))
        multipart_data = MultipartEncoder(fields={'file': (file, open(file, 'rb'), 'application/octet-stream')})
        headers = {'Content-Type': multipart_data.content_type, 'Authorization': self.APIKEY}
        
        
        resp = requests.post(self.SERVER + 'api/v1/upload', data=multipart_data, headers=headers)
        
        return resp.json()


    def scan(self, data):
        # Scan a file
        # @ARG1 : valid return value from upload()
        self.log.debug("Scanning file")
        data = json.dumps(data)
        data_obj = json.loads(data)
        headers = {'Authorization': self.APIKEY}
        requests.post(self.SERVER + 'api/v1/scan', data=data_obj, headers=headers)


    def delete(self, dataobj):
        # Delete scan
        self.log.debug("Deleting Scan")
        headers = {'Authorization': self.APIKEY}
        dataobj = json.dumps(dataobj)
        data_obj = {"hash": json.loads(dataobj)["hash"]}
        requests.post(self.SERVER + 'api/v1/delete_scan', data=data_obj, headers=headers)


    def generate_pdf(self, data):
        # generate pdf report
        self.log.debug(f'Requesting PDF report for')
        headers = {'Authorization': self.APIKEY}
        data = json.dumps(data)
        data_obj = {"hash": json.loads(data)["hash"]}
        response = requests.post(self.SERVER + 'api/v1/download_pdf', data=data_obj, headers=headers, stream=True)
        # building the pdf file from the response
        with open("report.pdf", 'wb') as doc:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    doc.write(chunk)
        self.log.debug("Report saved as report.pdf")


    def generate_json(self, data):
        # generate JSON report
        self.log.debug("generating JSON report")
        headers = {'Authorization': self.APIKEY}
        data = json.dumps(data)
        data_obj = {"hash": json.loads(data)["hash"]}
        resp = requests.post(self.SERVER + 'api/v1/report_json', data=data_obj, headers=headers)
        return resp.text


    def execute(self, request):
        """ call to mobsf """
        self.APIKEY = request.get_param('api_key')
        self.SERVER = request.get_param('framework_url')
        print(self.SERVER)
        source = request.file_path
        dest = source + ".apk"
        
        os.rename(source, dest)

        """retrieve results"""
        APK = self.upload(dest)
        self.log.debug("\nresult :")
        self.log.debug(APK)
        self.scan(APK)
        json_mobsf = {}# self.generate_json(APK)
        json_mobsf['body'] = 'dumb text'
        """let's build the result section"""
        result = Result()
        text_section = ResultSection('MobSF Static section')
        result.add_section(text_section)

        report_section = ResultSection("Informations from MobSF", body_format=BODY_FORMAT.JSON,
                                        body = json.dumps(json_mobsf))
        result.add_section(report_section)

        if request.get_param('generate_pdf'):
            os.chdir(self.working_directory)
            """save PDF report from MobSF"""
            self.generate_pdf(APK)
            request.add_supplementary("report.pdf", "report.pdf", "PDF of the static analysis from MobSF")
        
        request.result = result
        """cleaning up"""
        self.delete(APK)
        """renaming the file again to allow assemblyline to remove it duh"""
        os.rename(dest, source)
        