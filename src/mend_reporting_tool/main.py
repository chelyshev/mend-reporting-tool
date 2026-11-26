from time import sleep
import requests
import argparse
import zipfile
import os
import re
import sys
from importlib.metadata import version, PackageNotFoundError

PACKAGE_NAME = "mend-reporting-tool"
REPORT_FILENAME_PATTERN = re.compile(r"report-.+-(?:SCA|Container)-[^.]+\.[^.]+")


def get_version():
  try:
    return version(PACKAGE_NAME)
  except PackageNotFoundError:
    return "unknown (package not installed)"

def getRefreshToken(baseURL, email, userKey):
  url = "https://"+baseURL+"/api/v3.0/login"

  payload = {
    "email": email,
    "userKey": userKey
  }

  headers = {
    "Content-Type": "application/json"
  }

  response = requests.post(url, json=payload, headers=headers)

  data = response.json()
  if data["response"] == "Login failed":
    print(">>> Login failed. Check your Mend User Email (-userEmail) and Mend User Key (-userKey).")
    sys.exit(1)
  return data["response"]["refreshToken"]

def getAccessToken(baseURL, refreshToken):
  url = "https://"+baseURL+"/api/v3.0/login/accessToken"

  payload = {}

  headers = {
    "Content-Type": "application/json",
    "wss-refresh-token": refreshToken
  }

  response = requests.post(url, json=payload, headers=headers)

  data = response.json()
  return data["response"]["jwtToken"]

def generateSBOM(baseURL, projectUUID, reportType, reportFormat, accessToken):
  url = "https://"+baseURL+"/api/v3.0/projects/"+projectUUID+"/dependencies/reports/SBOM"

  payload = {
    "name": "SCA_report-"+reportType,
    "format": reportFormat,
    "sendEmailNotification": False,
    "labelsUuidList": [],
    "excludeInactiveProjects": True,
    "reportType": reportType,
    "maxDepthLevel": 1,
    "includeVulnerabilities": True,
    "isMlBomReport": False
  }

  authHeader = 'Bearer ' + accessToken
  headers = {
    "Content-Type": "application/json",
    "Authorization": authHeader
  }

  response = requests.post(url, json=payload, headers=headers)

  data = response.json()
  # print(data)
  if "errorMessage" in data["response"]:
    print(f">>> {data['response']['errorMessage']}. Check the Report Format parameter (-format) and try again.")
    sys.exit(1)
  return data["response"]["uuid"]

def generateContainerSBOM(baseURL, projectUUID, reportType, reportFormat, accessToken):
  url = "https://"+baseURL+"/api/v3.0/projects/"+projectUUID+"/images/reports/SBOM"

  payload = {
    "name": "Container_report-"+reportType,
    "scopeUuid": projectUUID,
    "scopeType": "project",
    "scopeUuidList": [projectUUID],
    "projectUuids": [projectUUID],
    "format": reportFormat,
    "sendEmailNotification": False,
    "labelsUuidList": [],
    "excludeInactiveProjects": True,
    "reportType": reportType,
    "includeVulnerabilities": True
  }

  headers = {
    "Content-Type": "application/json",
    "Authorization": 'Bearer ' + accessToken
  }

  response = requests.post(url, json=payload, headers=headers)
  response.raise_for_status()

  data = response.json()
  if "errorMessage" in data["response"]:
    print(f">>> {data['response']['errorMessage']}. Check the Report Format parameter (-format) and try again.")
    sys.exit(1)
  return data["response"]["uuid"]

def checkReportStatus(baseURL, orgUuid, reportUUID, accessToken):
  url = "https://"+baseURL+"/api/v3.0/orgs/"+orgUuid+"/reports/"+reportUUID

  headers = {
    "Content-Type": "application/json",
    "Authorization": 'Bearer ' + accessToken
  }

  response = requests.get(url, headers=headers)

  data = response.json()
  return data["response"]["status"]

def downloadReport(baseURL, orgUuid, reportUUID, projectUUID, accessToken):
  url = "https://"+baseURL+"/api/v3.0/orgs/"+orgUuid+"/reports/download/"+reportUUID

  headers = {
    "Authorization": 'Bearer ' + accessToken
  }

  filename = "report-"+projectUUID+".zip"

  try:
    # Stream the response to avoid loading it all into memory
    with requests.get(url, stream=True, timeout=10, headers=headers) as response:
      response.raise_for_status()  # Raise an error for bad status codes

      # Open file in binary write mode
      with open(filename, 'wb') as file:
        for chunk in response.iter_content(chunk_size=8192):
          if chunk:  # Filter out keep-alive chunks
            file.write(chunk)

    print(f">>> The report saved to '{filename}' successfully.")

  except requests.exceptions.RequestException as e:
    print(f">>> Error fetching URL: {e}")
  except OSError as e:
    print(f">>> File error: {e}")

def unzipReport(projectUUID, scanType=None, reportType=None):
  pathZipReport = 'report-'+projectUUID+'.zip'
  with zipfile.ZipFile(pathZipReport, 'r') as zip_ref:
    if scanType is not None and reportType is not None:
      for member in zip_ref.infolist():
        memberPath = member.filename.replace('/', os.path.sep)
        if os.path.altsep:
          memberPath = memberPath.replace(os.path.altsep, os.path.sep)
        memberPath = os.path.splitdrive(memberPath)[1]
        parts = [part for part in memberPath.split(os.path.sep)
                 if part not in ('', os.path.curdir, os.path.pardir)]
        if not parts:
          continue
        filename = parts[-1]
        destinationPath = os.path.join('mend-reports', *parts)
        if REPORT_FILENAME_PATTERN.fullmatch(filename) and os.path.exists(destinationPath):
          raise FileExistsError(f"Report already exists: {destinationPath}")

    zip_ref.extractall('mend-reports')

    if scanType is not None and reportType is not None:
      for root, _, files in os.walk('mend-reports'):
        for filename in files:
          if REPORT_FILENAME_PATTERN.fullmatch(filename):
            continue
          sourcePath = os.path.join(root, filename)
          _, extension = os.path.splitext(filename)
          destinationFilename = f"report-{projectUUID}-{scanType}-{reportType}{extension}"
          destinationPath = os.path.join('mend-reports', destinationFilename)
          if os.path.abspath(sourcePath) != os.path.abspath(destinationPath):
            if os.path.exists(destinationPath):
              os.remove(destinationPath)
            os.rename(sourcePath, destinationPath)

    print(f">>> The report '{pathZipReport}' extracted to 'mend-reports' folder.")
  if os.path.exists(pathZipReport):
    os.remove(pathZipReport)
    print(f">>> Deleted: {pathZipReport}")

def main():
  # First parser: only for --version
  version_parser = argparse.ArgumentParser(add_help=False)
  version_parser.add_argument("-v","--version", action="store_true", help="Show version and exit")
  args, remaining_argv = version_parser.parse_known_args()

  if args.version:
    print(get_version())
    sys.exit(0)

  # Main parser: all other arguments
  parser = argparse.ArgumentParser(description="This is script to generate reports through Mend API v3.0.")

  parser.add_argument("-v","--version", action="store_true", help="Show version and exit", required=False)
  parser.add_argument("-mendAPI",
                      help="Mend API v3.0 server hostname without https://, like `api-saas.whitesourcesoftware.com`",
                      required=True)
  parser.add_argument("-orgUUID", help="Organization UUID", required=True)
  parser.add_argument("-userEmail", help="User Email", required=True)
  parser.add_argument("-userKey", help="User Key", required=True)
  parser.add_argument("-projectUUID", help="List of Project UUIDs separeted by ','", required=True)
  parser.add_argument("-scanType", default="SCA",
                      help="Scan Type. Acceptable types: `SCA`, `Container`. Optional, default: `SCA`",
                      required=False)
  parser.add_argument("-reportType", default="cycloneDX_1_6",
                      help="Report Type. Acceptable SCA report types: `vulnerabilities`, `inventory`, `dueDiligence`, `risk`, `sbom`, `spdx`, `spdx_2_3`, `cycloneDX`, `cycloneDX_1_5`, `cycloneDX_1_6`. Acceptable container SBoM report types: `imgSpdx`, `imgSpdx_2_3`, `imgCycloneDX` (v1.4), `imgCycloneDX_1_5` (v1.5), and `imgCycloneDX_1_6` (v1.6). The `vulnerabilities` report type generates vulnerability report. The `dueDiligence` report type generates OSS licenses risk analysis report. The `risk` report type generates OSS security risk analysis report. The `inventory` report type generates OSS inventory report. The `sbom`,`spdx`, and `spdx_2_3` report types generate SBoM in `SPDX` format. The `cycloneDX`, `cycloneDX_1_5`, and `cycloneDX_1_6` report types generate SBoM in `CycloneDX` format. Optional, default: `cycloneDX_1_6` for SCA scanType.",
                      required=False)
  parser.add_argument("-format", default="json",
                      help="Report Format. Acceptable formats for  reportType `vulnerabilities`: `json`, `excel`; for reportType `sbom`,`spdx`,`spdx_2_3`: `json`, `yaml`; for reportType `cycloneDX`: `json`; for reportType `risk`: `pdf`;  for reportType `inventory`: `excel`;  for reportType `dueDiligence`: `excel`. Container SBoM reports default to `json`; other formats depend on the selected report type and API support. Optional, default: `json`",
                      required=False)
  parser.add_argument("-unzip", default="yes",
                      help="Extract report to the 'mend-reports' folder. Variants: yes, no. Optional, default: `yes`. In case of `no` report in .zip format will be saved in the current directory",
                      required=False)

  # Parse arguments
  args = parser.parse_args()

  baseURL = args.mendAPI
  orgUUID = args.orgUUID
  userEmail = args.userEmail
  userKey = args.userKey
  projectUUID_list = args.projectUUID
  scanType = args.scanType
  reportType = args.reportType
  reportFormat = args.format
  extractReport = args.unzip

  refreshToken = getRefreshToken(baseURL, userEmail, userKey)
  accessToken = getAccessToken(baseURL, refreshToken)
  # print (accessToken)
  for item in projectUUID_list.split(","):
    projectUUID = item.strip()
    print(f"### Processing Project UUID: {projectUUID}")
    if scanType == "Container":
      if reportType not in ["imgSpdx", "imgSpdx_2_3", "imgCycloneDX", "imgCycloneDX_1_5", "imgCycloneDX_1_6"]:
        print(f">>> Report Type {reportType} is not supported for Container scan. Please use `imgSpdx`, `imgSpdx_2_3`, `imgCycloneDX`, `imgCycloneDX_1_5`, or `imgCycloneDX_1_6`.")
        sys.exit(1)
      reportUUID = generateContainerSBOM(baseURL, projectUUID, reportType, reportFormat, accessToken)
    elif scanType == "SCA":
      if reportType not in ["vulnerabilities", "inventory", "dueDiligence", "risk", "sbom", "spdx", "spdx_2_3", "cycloneDX", "cycloneDX_1_5", "cycloneDX_1_6"]:
        print(
          f">>> Report Type {reportType} is not supported for SCA scan. Please use `vulnerabilities`, `inventory`, `dueDiligence`, `risk`, `sbom`, `spdx`, `spdx_2_3`, `cycloneDX`, `cycloneDX_1_5`, or `cycloneDX_1_6`.")
        sys.exit(1)
      reportUUID = generateSBOM(baseURL, projectUUID, reportType, reportFormat, accessToken)
    else:
        print(f">>> Scan Type {scanType} is not supported. Please use `SCA` or `Container`.")
        sys.exit(1)
    reportStatus = ""
    while reportStatus != "SUCCESS":
      sleep(3)
      reportStatus = checkReportStatus(baseURL, orgUUID, reportUUID, accessToken)
      # print (reportStatus)
      if reportStatus == "SUCCESS":
        downloadReport(baseURL, orgUUID, reportUUID, projectUUID, accessToken)
        if extractReport == "yes":
          unzipReport(projectUUID, scanType, reportType)
          print(">>> Report is ready in `mend-reports` folder.")
        else:
          print(">>> Report is ready in `./` folder.")
      elif reportStatus == "IN_PROGRESS":
        print(">>> Report generation in progress, please wait")
      elif reportStatus in ("FAILED", "FAILURE"):
        print(">>> Report generation failed, please try again later")
        sys.exit(1)
      else:
        print(">>> Report generation in progress, please wait")


if __name__ == "__main__":
    main()