import json
import os
import random
from requests_toolbelt import MultipartEncoder
import requests
import magic
import tempfile
import api_mobsf
from static import ALL_ANDROID_PERMISSIONS
from assemblyline.common.hexdump import hexdump
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic

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

        report_section = ResultSection("Informations overview from MobSF")
        json_mobsf = json.loads(json_mobsf)
        
        if json_mobsf["app_name"]:
            app_name = json_mobsf["app_name"]
            report_section.add_line(f"App Name: {app_name}")
        
        if json_mobsf["package_name"] and json_mobsf["version_name"]:
            package_name, version_name = json_mobsf["package_name"], json_mobsf["version_name"]
            report_section.add_line(f"Package Name: {package_name} v.{version_name}")
        
        if json_mobsf["target_sdk"]:
            target_sdk = json_mobsf["target_sdk"]
            report_section.add_line(f"target SDK : {target_sdk}")

        if json_mobsf["min_sdk"]:
            min_sdk = json_mobsf["min_sdk"]
            report_section.add_line(f"max SDK : {min_sdk}")

        if json_mobsf["max_sdk"]:
            max_sdk = json_mobsf["max_sdk"]
            report_section.add_line(f"max SDK : {max_sdk}")

        # if json_mobsf['size']:
        #     size = json_mobsf["size"]
        #     report_section.add_line(f"size : {size}")

        # if json_mobsf['md5']:
        #     md5 = json_mobsf["md5"]
        #     report_section.add_line(f"MD5 : {md5}")
        # if json_mobsf['sha1']:
        #     sha1 = json_mobsf["sha1"]
        #     report_section.add_line(f"SHA1 : {sha1}")
        # if json_mobsf['sha256']:
        #     sha256 = json_mobsf["sha256"]
        #     report_section.add_line(f"SHA256 : {sha256}")
        if "signature: True" in json_mobsf["certificate_analysis"]["certificate_info"]:
            report_section.add_line(f"APK is signed")
        else:
            ResultSection("APK is not signed", parent=report_section, heuristic=Heuristic(4))
        if 'permissions' in json_mobsf or len(json_mobsf['permissions'] != 0):
            permissions = json_mobsf['permissions']
            dangerous_permissions = []
            unknown_permissions = []
            result_permissions = ResultSection("Permissions used", parent=report_section)
            for perm in json_mobsf["permissions"]:
                if perm in ALL_ANDROID_PERMISSIONS:
                    if 'dangerous' in ALL_ANDROID_PERMISSIONS[perm]:
                        dangerous_permissions.append(perm)
                    else:
                        result_permissions.add_line(perm)
                        result_permissions.add_tag('file.apk.permission', perm)
                else:
                    unknown_permissions.append(perm)

            if len(set(permissions)) < len(permissions):
                ResultSection("Some permissions are defined more then once", parent=report_section,
                              heuristic=Heuristic(1))
            if dangerous_permissions:
                result_dangerous_permissions = ResultSection("Dangerous permissions used", parent=report_section,
                                                   heuristic=Heuristic(2))
                for perm in dangerous_permissions:
                    result_dangerous_permissions.add_line(perm)
                    result_dangerous_permissions.add_tag('file.apk.permission', perm)
            
            if unknown_permissions:
                result_unknown_permissions = ResultSection("Unknown permissions used", parent=report_section,
                                                 heuristic=Heuristic(3))
                for perm in unknown_permissions:
                    result_unknown_permissions.add_line(perm)
                    result_unknown_permissions.add_tag('file.apk.permission', perm)
            
            if json_mobsf["android_api"]:
                result_api_used = ResultSection("Android API used", parent=report_section)
                for api in json_mobsf["android_api"]:
                    result_api_used.add_line(api)
                    result_api_used.add_tag('file.apk.api', api)

            if json_mobsf["apkid"]:
                result_apkid =  ResultSection("APK ID analysis", parent=report_section)
                dic_section = {}
                for section in json_mobsf["apkid"]:
                    dic_section["result_section_{}".format(section)] = ResultSection("{}".format(section), parent=result_apkid)
                    for feature in json_mobsf["apkid"][section]:
                        dic_section["result_section_{}".format(section)].add_line(feature)



        result.add_section(report_section)

        if request.get_param('generate_pdf'):
            """save PDF report from MobSF"""
            fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
            api_mobsf.generate_pdf(APK, fd, self.SERVER, self.APIKEY)
            request.add_supplementary(temp_path, "report.pdf", "PDF of the static analysis from MobSF")
        
        """cleaning up"""
        if request.get_param('delete_after_scan'):
            api_mobsf.delete(APK, self.SERVER, self.APIKEY)
        else :
            url = self.SERVER + "recent_scans/"

            url_section = ResultSection('URL to the scan', parent=report_section, body_format=BODY_FORMAT.URL,
                                        body=json.dumps({"name": "Scan!", "url": url}))
            url_section.add_tag('URL to the MobSF scan generated', url)
        request.result = result
        """renaming the file again to allow assemblyline to remove it duh"""
        os.rename(dest, source)
        