# Mend Report Generation tool
This is script to generate reports through [Mend API v3.0](https://api-docs.mend.io/platform/3.0).

### How To Use
```shell
$ mend-reporting-tool -h
usage: mend-reporting-tool [-h] -mendAPI MENDAPI -orgUUID ORGUUID -userEmail USEREMAIL -userKey USERKEY -projectUUID PROJECTUUID
                           [-reportType REPORTTYPE] [-format FORMAT] [-unzip UNZIP]

This is script to generate reports through Mend API v3.0.

options:
  -h, --help            show this help message and exit
  -mendAPI MENDAPI      Mend API v3.0 server hostname without https://, like `api-saas.whitesourcesoftware.com`
  -orgUUID ORGUUID      Organization UUID
  -userEmail USEREMAIL  User Email
  -userKey USERKEY      User Key
  -projectUUID PROJECTUUID
                        List of Project UUIDs separeted by ','
  -reportType REPORTTYPE
                        Report Type, for example: `vulnerabilities`, `sbom`, `spdx`, `spdx_2_3`, `cycloneDX`, `cycloneDX_1_5`,
                        `cycloneDX_1_6`. The `vulnerabilities` report type generates vulnerability report. The `sbom` report type generates    
                        `spdx` format. Optional, default: `sbom`
  -format FORMAT        Report Format, acceptable formats for `vulnerabilities` reportType: `json`, `excel`; for `sbom` reportType: `json`,    
                        `yaml`. Optional, default: `json`
  -unzip UNZIP          Extract report to the 'mend-reports' folder. Variants: yes, no. Optional, default: `no`

### Example:
mend-reporting-tool  -mendAPI $MEND_API -orgUUID $MEND_ORGANIZATION_UUID -userEmail $MEND_EMAIL  -userKey $MEND_USER_KEY -projectUUID $PROJECT_UUID -reportType sbom -format yaml -unzip yes

### Processing Project UUID: <Project_UUID>
>>> The report saved to 'report-<Project_UUID>.zip' successfully.
>>> The report 'report-<Project_UUID>.zip' extracted to 'mend-reports' folder.
>>> Deleted: report-<Project_UUID>.zip
>>> Report is ready in `mend-reports` folder.
...

# Content of `mend-reports` folder:
$ ls -l mend-reports/
-rw-r--r-- 1 alex alex 1033049 Apr 20 23:50 '<Project_Name>-project-SPDX-reportyaml'
```

### How To Install
```shell
pip install 'mend-reporting-tool==0.2.1'
```

### How To Install from source code
```shell
git clone https://github.com/chelyshev/mend-reporting-tool.git
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```
