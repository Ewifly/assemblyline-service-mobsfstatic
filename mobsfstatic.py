import json
import os
import random
from requests_toolbelt import MultipartEncoder
import requests
import magic
import tempfile
import api_mobsf
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

    def execute(self, request):
        """ call to mobsf """
        self.APIKEY = self.config.get('api_key', 'fa5e0f4bab4704b9c9d9d691b91ff360d8ab560804bb428e9f269ec7c0b0d331')
        self.SERVER = self.config.get('framework_url', 'http://192.168.10.78:8000/')
        source = request.file_path
        dest = source + ".apk"
        
        os.rename(source, dest)

        """retrieve results"""
        APK = api_mobsf.upload(dest, self.SERVER, self.APIKEY)
        api_mobsf.scan(APK, self.SERVER, self.APIKEY)
        json_mobsf = api_mobsf.generate_json(APK, self.SERVER, self.APIKEY)
        """let's build the result section"""
        result = Result()
        text_section = ResultSection('MobSF Static section')
        result.add_section(text_section)

        report_section = ResultSection("Informations from MobSF", body_format=BODY_FORMAT.TEXT,
                                        body = json.dumps(json_mobsf))
        result.add_section(report_section)

        if request.get_param('generate_pdf'):
            """save PDF report from MobSF"""
            fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
            api_mobsf.generate_pdf(APK, fd, self.SERVER, self.APIKEY)
            request.add_supplementary(temp_path, "report.pdf", "PDF of the static analysis from MobSF")
        
        request.result = result
        """cleaning up"""
        api_mobsf.delete(APK, self.SERVER, self.APIKEY)
        """renaming the file again to allow assemblyline to remove it duh"""
        os.rename(dest, source)
        