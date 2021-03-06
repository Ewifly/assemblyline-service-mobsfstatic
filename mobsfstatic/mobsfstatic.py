import json
import os
import random
from requests_toolbelt import MultipartEncoder
import time
import requests
import magic
import tempfile
from mobsfstatic.api_mobsf import upload, scan, generate_json, generate_pdf, generate_code, delete
from mobsfstatic.static import ALL_MOBSF_ANDROID_FEATURES
from mobsfstatic.static import ALL_ANDROID_PERMISSIONS
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
        result = Result()
        source = request.file_path
        self.APIKEY = self.config.get('api_key')
        self.SERVER = self.config.get('framework_url')

        print(self.SERVER)

        dest = source + ".apk"
        

        os.rename(source, dest)

        """retrieve results"""
        APK = upload(dest, self.SERVER, self.APIKEY)
        scan(APK, self.SERVER, self.APIKEY)
        json_mobsf = generate_json(APK, self.SERVER, self.APIKEY)
        """let's build the result section"""

        report_section = ResultSection("Informations overview from MobSF")
        json_mobsf = json.loads(json_mobsf)
        
        if json_mobsf["security_score"]:
            score = json_mobsf["security_score"]
            if score <= 15:
                result_score_critical = ResultSection("score from MobSF", parent=report_section, heuristic=Heuristic(8))
                result_score_critical.add_line(score)
                result_score_critical.add_tag("file.apk.mobsf.score", score)
            elif 15 < score <= 40:
                result_score_high = ResultSection("score from MobSF", parent=report_section,
                                                heuristic=Heuristic(9))
                result_score_high.add_line(score)
                result_score_high.add_tag("file.apk.mobsf.score", score)
            elif 40 < score <= 70:
                result_score_medium = ResultSection("score from MobSF", parent=report_section,
                                                heuristic=Heuristic(10))
                result_score_medium.add_line(score)
                result_score_medium.add_tag("file.apk.mobsf.score", score)
            else:
                result_score_low= ResultSection("score from MobSF", parent=report_section)
                result_score_low.add_line(score)
                result_score_low.add_tag("file.apk.mobsf.score", score)

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
            result_features = ResultSection("Features used", parent=report_section)
            all_features,info_features ,suspicious_features, dangerous_features, undefined_features, details = [], [], [], [], [], []
            dic_report_features = {} #dictionary of reportsection for each insteresting feature raised
            for section in json_mobsf["apkid"]:
                all_features.append(list(json_mobsf["apkid"][section].keys()))
            all_features = all_features[0]
            for section in json_mobsf["apkid"]:
                for key in all_features:
                    details.append([key, json_mobsf["apkid"][section][key]])
            for feature in all_features:
                if feature in ALL_MOBSF_ANDROID_FEATURES:
                    dic_report_features["{0}".format(feature)] = ResultSection("detail for {0}".format(feature)) #create a report section to show details afterwards
                    if 'danger' in ALL_MOBSF_ANDROID_FEATURES[feature]:
                        dangerous_features.append(feature)
                    elif 'warning' in ALL_MOBSF_ANDROID_FEATURES[feature]:
                        suspicious_features.append(feature)
                    else:
                        info_features.append(feature)
                else:
                    undefined_features.append(feature)

            if info_features:
                for feature in info_features:
                    result_features.add_line(feature)
                    result_features.add_tag('file.apk.feature', feature)
                    for detail in details:
                            if detail[0] == feature:
                                for unitary in detail[1]:
                                    dic_report_features[feature].add_line(unitary)
                    result_features.add_subsection(dic_report_features[feature])

            if dangerous_features:
                result_dangerous_features = ResultSection("Dangerous features used", parent=report_section,
                                                heuristic=Heuristic(6))
                for feature in dangerous_features:
                    result_dangerous_features.add_line(feature)
                    result_dangerous_features.add_tag('file.apk.feature', feature)
                    for detail in details:
                        if detail[0] == feature:
                            for unitary in detail[1]:
                                dic_report_features[feature].add_line(unitary)
                                dic_report_features[feature].add_tag('file.apk.feature.{}'.format(feature), unitary)
                    result_dangerous_features.add_subsection(dic_report_features[feature])
            if suspicious_features:
                result_suspicious_features = ResultSection("Suspicious features used", parent=report_section,
                                                heuristic=Heuristic(5))
                for feature in suspicious_features:
                    result_suspicious_features.add_line(feature)
                    result_suspicious_features.add_tag('file.apk.feature', feature)
                    for detail in details:
                        if detail[0] == feature:
                            for unitary in detail[1]:
                                dic_report_features[feature].add_line(unitary)
                                dic_report_features[feature].add_tag('file.apk.feature.{}'.format(feature), unitary)
                    result_suspicious_features.add_subsection(dic_report_features[feature])

            if undefined_features:
                result_undefined_features = ResultSection("Undefined features used", parent=report_section,
                                                heuristic=Heuristic(7))
                for feature in undefined_features:
                    result_undefined_features.add_line(feature)
                    result_undefined_features.add_tag('file.apk.feature', feature)
                    for detail in details:
                        if detail[0] == feature:
                            for unitary in detail[1]:
                                dic_report_features[feature].add_line(unitary)
                                dic_report_features[feature].add_tag('file.apk.feature.{}'.format(feature), unitary)
                    result_undefined_features.add_subsection(dic_report_features[feature])

        result.add_section(report_section)

        if request.get_param('generate_pdf'):
            """save PDF report from MobSF"""
            fd, temp_path = tempfile.mkstemp(dir=self.working_directory)
            generate_pdf(APK, fd, self.SERVER, self.APIKEY)
            request.add_supplementary(temp_path, "report.pdf", "PDF of the static analysis from MobSF")
        
        """generate smali/java code"""
        if request.get_param('generate_smali_or_java'):
            fd_smali, temp_path_smali = tempfile.mkstemp(dir=self.working_directory)
            fd_java, temp_path_java = tempfile.mkstemp(dir=self.working_directory)

            generate_code(APK, fd_smali, 'smali', self.SERVER)
            generate_code(APK, fd_java, 'java', self.SERVER)
            request.add_supplementary(temp_path_smali, "smali", "smali code")
            request.add_supplementary(temp_path_java, "java", "java code")
        
        """cleaning up"""
        if request.get_param('delete_after_scan'):
            delete(APK, self.SERVER, self.APIKEY)
        else :
            url = self.SERVER + "recent_scans/"

            url_section = ResultSection('URL to the scan', parent=report_section, body_format=BODY_FORMAT.URL,
                                        body=json.dumps({"name": "Scan!", "url": url}))
            url_section.add_tag('URL to the MobSF scan generated', url)
        
        request.result = result
        """renaming the file again to allow assemblyline to remove it duh"""
        os.rename(dest, source)
