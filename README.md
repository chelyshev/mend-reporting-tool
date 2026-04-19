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
               [-format FORMAT]

This is script to generate reports through Mend API v3.0.

options:
  -h, --help            show this help message and exit
  -mendAPI MENDAPI      Mend API v3.0 server hostname without https://, like `api-saas.whitesourcesoftware.com`
  -orgUUID ORGUUID      Organization UUID
  -userEmail USEREMAIL  user Email
  -userKey USERKEY      user Key
  -projectUUID PROJECTUUID
                        Project UUID
  -reportType REPORTTYPE
                        report Type, for example: `vulnerabilities`, `sbom`, `spdx`, `spdx_2_3`, `cycloneDX`, `cycloneDX_1_5`, `cycloneDX_1_6`.     
                        The `vulnerabilities` report type generates vulnerability report. The `sbom` report type generates `spdx` format.
  -format FORMAT        report Format, acceptable formats for `vulnerabilities` reportType: `json`, `excel`; for `sbom` reportType: `json`, `yaml`
  

### Response example:
Response body saved to 'report-888b5eea-985c-4646-bae3-2bf6353f14b4.zip' successfully.
Report is ready
```