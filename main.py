from time import sleep

import requests
import argparse


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
    "labelsUuidList": [
      "string"
    ],
    "excludeInactiveProjects": True,
    "reportType": reportType,
    "maxDepthLevel": 0,
    "includeVulnerabilities": True,
    "isMlBomReport": True,
    "additionalParams": {
      "property1": [
        "string"
      ],
      "property2": [
        "string"
      ]
    }
  }

  authHeader = 'Bearer ' + accessToken
  headers = {
    "Content-Type": "application/json",
    "Authorization": authHeader
  }

  response = requests.post(url, json=payload, headers=headers)

  data = response.json()
  print(data)
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

def downloadReport(baseURL, orgUuid, reportUUID, accessToken):
  url = "https://"+baseURL+"/api/v3.0/orgs/"+orgUuid+"/reports/download/"+reportUUID

  headers = {
    "Authorization": 'Bearer ' + accessToken
  }

  filename = "report-"+reportUUID+".zip"

  try:
    # Stream the response to avoid loading it all into memory
    with requests.get(url, stream=True, timeout=10, headers=headers) as response:
      response.raise_for_status()  # Raise an error for bad status codes

      # Open file in binary write mode
      with open(filename, 'wb') as file:
        for chunk in response.iter_content(chunk_size=8192):
          if chunk:  # Filter out keep-alive chunks
            file.write(chunk)

    print(f"Response body saved to '{filename}' successfully.")

  except requests.exceptions.RequestException as e:
    print(f"Error fetching URL: {e}")
  except OSError as e:
    print(f"File error: {e}")


if __name__ == '__main__':
    # Create parser
    parser = argparse.ArgumentParser(description="This is script to generate reports through Mend API v3.0.")

    # Add arguments
    parser.add_argument("-mendAPI", help="Mend API v3.0 server hostname without https://, like `api-saas.whitesourcesoftware.com`", required=True)
    parser.add_argument("-orgUUID", help="Organization UUID", required=True)
    parser.add_argument("-userEmail", help="user Email", required=True)
    parser.add_argument("-userKey", help="user Key", required=True)
    parser.add_argument("-projectUUID", help="Project UUID", required=True)
    parser.add_argument("-reportType", help="report Type, for example: `vulnerabilities`, `sbom`, `spdx`, `spdx_2_3`, `cycloneDX`, `cycloneDX_1_5`, `cycloneDX_1_6`. The `vulnerabilities` report type generates vulnerability report. The `sbom` report type generates `spdx` format. ", required=True)
    parser.add_argument("-format", default="json", help="report Format, acceptable formats for `vulnerabilities` reportType: `json`, `excel`; for `sbom` reportType: `json`, `yaml`", required=False)

    # Parse arguments
    args = parser.parse_args()

    baseURL = args.mendAPI
    orgUUID = args.orgUUID
    userEmail = args.userEmail
    userKey = args.userKey
    projectUUID = args.projectUUID
    reportType = args.reportType # The "vulnerabilities" report type generates vulnerability report. The "sbom" report type generates `spdx` format. The following report types do not work "spdx", "spdx_2_3", "cycloneDX", "cycloneDX_1_5", "cycloneDX_1_6"
    reportFormat = args.format
    refreshToken = getRefreshToken(baseURL, userEmail, userKey)
    accessToken = getAccessToken(baseURL, refreshToken)
    # print (accessToken)
    reportUUID = generateSBOM(baseURL, projectUUID, reportType, reportFormat, accessToken)
    reportStatus = ""
    while reportStatus != "SUCCESS":
      sleep(3)
      reportStatus = checkReportStatus(baseURL, orgUUID, reportUUID, accessToken)
      print (reportStatus)
      if reportStatus == "SUCCESS":
        downloadReport(baseURL, orgUUID, reportUUID, accessToken)
        print("Report is ready")
        break
      elif reportStatus == "IN_PROGRESS":
        print("Report generation in progress, please wait")
      elif reportStatus == "FAILED":
        print("Report generation failed, please try again later")
        break
      else:
        print("Report generation in progress, please wait")



