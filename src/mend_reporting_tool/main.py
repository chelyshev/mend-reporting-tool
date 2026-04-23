from time import sleep

import requests
import argparse
import zipfile
import os
import sys


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
    print(">>> Login failed. Check your Mend User Email and Mend User Key.")
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

def unzipReport(projectUUID):
  pathZipReport = 'report-'+projectUUID+'.zip'
  with zipfile.ZipFile(pathZipReport, 'r') as zip_ref:
    zip_ref.extractall('mend-reports')
    print(f">>> The report '{pathZipReport}' extracted to 'mend-reports' folder.")
  if os.path.exists(pathZipReport):
    os.remove(pathZipReport)
    print(f">>> Deleted: {pathZipReport}")

def main():
  # Create parser
  parser = argparse.ArgumentParser(description="This is script to generate reports through Mend API v3.0.")

  # Add arguments
  parser.add_argument("-mendAPI",
                      help="Mend API v3.0 server hostname without https://, like `api-saas.whitesourcesoftware.com`",
                      required=True)
  parser.add_argument("-orgUUID", help="Organization UUID", required=True)
  parser.add_argument("-userEmail", help="User Email", required=True)
  parser.add_argument("-userKey", help="User Key", required=True)
  parser.add_argument("-projectUUID", help="List of Project UUIDs separeted by ','", required=True)
  parser.add_argument("-reportType", default="sbom",
                      help="Report Type, for example: `vulnerabilities`, `sbom`, `spdx`, `spdx_2_3`, `cycloneDX`, `cycloneDX_1_5`, `cycloneDX_1_6`. The `vulnerabilities` report type generates vulnerability report. The `sbom` report type generates `spdx` format. Optional, default: `sbom`",
                      required=False)
  parser.add_argument("-format", default="json",
                      help="Report Format, acceptable formats for `vulnerabilities` reportType: `json`, `excel`; for `sbom` reportType: `json`, `yaml`. Optional, default: `json`",
                      required=False)
  parser.add_argument("-unzip", default="no",
                      help="Extract report to the 'mend-reports' folder. Variants: yes, no. Optional, default: `no`",
                      required=False)

  # Parse arguments
  args = parser.parse_args()

  baseURL = args.mendAPI
  orgUUID = args.orgUUID
  userEmail = args.userEmail
  userKey = args.userKey
  projectUUID_list = args.projectUUID
  reportType = args.reportType
  reportFormat = args.format
  extractReport = args.unzip
  refreshToken = getRefreshToken(baseURL, userEmail, userKey)
  accessToken = getAccessToken(baseURL, refreshToken)
  # print (accessToken)
  for item in projectUUID_list.split(","):
    projectUUID = item.strip()
    print(f"### Processing Project UUID: {projectUUID}")
    reportUUID = generateSBOM(baseURL, projectUUID, reportType, reportFormat, accessToken)
    reportStatus = ""
    while reportStatus != "SUCCESS":
      sleep(3)
      reportStatus = checkReportStatus(baseURL, orgUUID, reportUUID, accessToken)
      # print (reportStatus)
      if reportStatus == "SUCCESS":
        downloadReport(baseURL, orgUUID, reportUUID, projectUUID, accessToken)
        if extractReport == "yes":
          unzipReport(projectUUID)
          print(">>> Report is ready in `mend-reports` folder.")
        else:
          print(">>> Report is ready in `./` folder.")
      elif reportStatus == "IN_PROGRESS":
        print(">>> Report generation in progress, please wait")
      elif reportStatus == "FAILED":
        print(">>> Report generation failed, please try again later")
        sys.exit(1)
      else:
        print(">>> Report generation in progress, please wait")


if __name__ == "__main__":
    main()