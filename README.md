# Mend Report Generation tool
This is script to generate reports through [Mend API v3.0](https://api-docs.mend.io/platform/3.0).

### How To Use
```shell
$ mend-reporting-tool -h
usage: mend-reporting-tool [-h] [-v] -mendAPI MENDAPI -orgUUID ORGUUID -userEmail USEREMAIL -userKey USERKEY -projectUUID PROJECTUUID
                           [-reportType REPORTTYPE] [-format FORMAT] [-unzip UNZIP]

This is script to generate reports through Mend API v3.0.

options:
  -h, --help            show this help message and exit
  -v, --version         Show version and exit
  -mendAPI MENDAPI      Mend API v3.0 server hostname without https://, like `api-saas.whitesourcesoftware.com`
  -orgUUID ORGUUID      Organization UUID
  -userEmail USEREMAIL  User Email
  -userKey USERKEY      User Key
  -projectUUID PROJECTUUID
                        List of Project UUIDs separeted by ','
  -reportType REPORTTYPE
                        Report Type, acceptable report types: `vulnerabilities`, `inventory`, `dueDiligence`, `risk`, `sbom`, `spdx`, `spdx_2_3`,   
                        `cycloneDX`, `cycloneDX_1_5`, `cycloneDX_1_6`. The `vulnerabilities` report type generates vulnerability report. The        
                        `dueDiligence` report type generates OSS licenses risk analysis report. The `risk` report type generates OSS security risk  
                        analysis report. The `inventory` report type generates OSS inventory report. The `sbom`,`spdx`, and `spdx_2_3` report       
                        types generate SBoM in `SPDX` format. The `cycloneDX`, `cycloneDX_1_5`, and `cycloneDX_1_6` report types generate SBoM in   
                        `CycloneDX` format. Optional, default: `cycloneDX_1_6`
  -format FORMAT        Report Format, acceptable formats for reportType `vulnerabilities`: `json`, `excel`; for reportType
                        `sbom`,`spdx`,`spdx_2_3`: `json`, `yaml`; for reportType `cycloneDX`: `json`; for reportType `risk`: `pdf`; for reportType  
                        `inventory`: `excel`; for reportType `dueDiligence`: `excel`. Optional, default: `json`
  -unzip UNZIP          Extract report to the 'mend-reports' folder. Variants: yes, no. Optional, default: `yes`. In case of `no` report in .zip    
                        format will be saved in the current directory
 
### Example:
mend-reporting-tool  -mendAPI $MEND_API -orgUUID $MEND_ORGANIZATION_UUID -userEmail $MEND_EMAIL  -userKey $MEND_USER_KEY -projectUUID $PROJECT_UUID -reportType cycloneDX_1_6 -format json -unzip yes

### Processing Project UUID: <Project_UUID>
>>> The report saved to 'report-<Project_UUID>.zip' successfully.
>>> The report 'report-<Project_UUID>.zip' extracted to 'mend-reports' folder.
>>> Deleted: report-<Project_UUID>.zip
>>> Report is ready in `mend-reports` folder.
...

# Example of possible reports Types and Formats in `mend-reports` folder:
$ ls mend-reports/
<Project_Name>-project-CycloneDX-report-<Project_UUID>.json
<Project_Name>-project-SPDX-report.json
<Project_Name>-project-SPDX-report.yaml
<Project_Name>-due-diligence-report.xlsx
<Project_Name>-inventory-report_Page_1.xlsx
<Project_Name>-risk.pdf
<Project_Name>-vulnerability-report.json
<Project_Name>-vulnerability-report.xlsx
```

### How To Install
```shell
pip install 'mend-reporting-tool==0.2.2'
```

### How To Install from source code
```shell
git clone https://github.com/chelyshev/mend-reporting-tool.git
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```
