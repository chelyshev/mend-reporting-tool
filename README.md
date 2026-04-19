# Mend Report Generation tool

### How To Install
```shell
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### How To Use
```shell
$ python main.py -h
usage: main.py [-h] -mendAPI MENDAPI -orgUUID ORGUUID -userEmail USEREMAIL -userKey USERKEY -projectUUID PROJECTUUID -reportType REPORTTYPE

This is script to generate reports through Mend API v3.0.

options:
  -h, --help            show this help message and exit
  -mendAPI MENDAPI      mendAPI - Mend API v3.0 server hostname without https://, like `api-saas.whitesourcesoftware.com`
  -orgUUID ORGUUID      OrganizationUUID
  -userEmail USEREMAIL  userEmail
  -userKey USERKEY      userKey
  -projectUUID PROJECTUUID
                        ProjectUUID
  -reportType REPORTTYPE
                        reportType, for example: `sbom`, `spdx`, `spdx_2_3`, `cycloneDX`, `cycloneDX_1_5`, `cycloneDX_1_6`


### Response example:
Response body saved to 'report-888b5eea-985c-4646-bae3-2bf6353f14b4.zip' successfully.
Report is ready
```