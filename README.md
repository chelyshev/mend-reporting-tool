# Mend Report Generation tool
This is script to generate reports through [Mend API v3.0](https://api-docs.mend.io/platform/3.0).

### How To Use
```shell
$ mend-reporting-tool -h
usage: mend-reporting-tool [-h] [-v] -mendAPI MENDAPI -orgUUID ORGUUID -userEmail USEREMAIL -userKey USERKEY -projectUUID PROJECTUUID
                           [-scanType SCANTYPE] [-reportType REPORTTYPE] [-format FORMAT] [-unzip UNZIP]

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
  -scanType SCANTYPE    Scan Type. Acceptable types: `SCA`, `Container`. Optional, default: `SCA`
  -reportType REPORTTYPE
                        Report Type. Acceptable SCA report types: `vulnerabilities`, `inventory`, `dueDiligence`, `risk`, `sbom`, `spdx`,
                        `spdx_2_3`, `cycloneDX`, `cycloneDX_1_5`, `cycloneDX_1_6`. Acceptable container SBoM report types: `imgSpdx`,
                        `imgSpdx_2_3`, `imgCycloneDX` (v1.4), `imgCycloneDX_1_5` (v1.5), and `imgCycloneDX_1_6` (v1.6). The `vulnerabilities`
                        report type generates vulnerability report. The `dueDiligence` report type generates OSS licenses risk analysis report.
                        The `risk` report type generates OSS security risk analysis report. The `inventory` report type generates OSS inventory
                        report. The `sbom`,`spdx`, and `spdx_2_3` report types generate SBoM in `SPDX` format. The `cycloneDX`, `cycloneDX_1_5`,
                        and `cycloneDX_1_6` report types generate SBoM in `CycloneDX` format. Optional, default: `cycloneDX_1_6` for SCA scanType.
  -format FORMAT        Report Format. Acceptable formats for reportType `vulnerabilities`: `json`, `excel`; for reportType
                        `sbom`,`spdx`,`spdx_2_3`: `json`, `yaml`; for reportType `cycloneDX`: `json`; for reportType `risk`: `pdf`; for reportType
                        `inventory`: `excel`; for reportType `dueDiligence`: `excel`. Container SBoM reports default to `json`; other formats
                        depend on the selected report type and API support. Optional, default: `json`
  -unzip UNZIP          Extract report to the 'mend-reports' folder. Variants: yes, no. Optional, default: `yes`. In case of `no` report in .zip
                        format will be saved in the current directory
 
### Examples:
# Generate SBoM report for SCA scan in CycloneDX 1.6 format and extract it to `mend-reports` folder:
mend-reporting-tool  -mendAPI $MEND_API -orgUUID $MEND_ORGANIZATION_UUID -userEmail $MEND_EMAIL  -userKey $MEND_USER_KEY -projectUUID $PROJECT_UUID -scanType SCA -reportType cycloneDX_1_6 -format json -unzip yes

# Generate vulnerabilities report for SCA scan in Excel format and extract it to `mend-reports` folder:
mend-reporting-tool  -mendAPI $MEND_API -orgUUID $MEND_ORGANIZATION_UUID -userEmail $MEND_EMAIL  -userKey $MEND_USER_KEY -projectUUID $PROJECT_UUID -scanType SCA -reportType vulnerabilities -format excel -unzip yes

# Generate SBoM report for Container scan in CycloneDX 1.6 format and extract it to `mend-reports` folder:  
mend-reporting-tool  -mendAPI $MEND_API -orgUUID $MEND_ORGANIZATION_UUID -userEmail $MEND_EMAIL  -userKey $MEND_USER_KEY -projectUUID $PROJECT_UUID -scanType Container -reportType imgCycloneDX_1_6 -format json -unzip yes


### Example of output:
### Processing Project UUID: <Project_UUID>
>>> The report saved to 'report-<Project_UUID>.zip' successfully.
>>> The report 'report-<Project_UUID>.zip' extracted to 'mend-reports' folder.
>>> Deleted: report-<Project_UUID>.zip
>>> Report is ready in `mend-reports` folder.
...

# Example of possible reports Types and Formats in `mend-reports` folder:
$ ls mend-reports/
report-<Project_UUID>-SCA-cycloneDX_1_6.json
report-<Project_UUID>-SCA-spdx_2_3.yaml
report-<Project_UUID>-SCA-vulnerabilities.xlsx
report-<Project_UUID>-SCA-dueDiligence.xlsx
report-<Project_UUID>-SCA-risk.pdf
report-<Project_UUID>-Container-imgSpdx.json
report-<Project_UUID>-Container-imgCycloneDX_1_6.json
```

### Container scan SBoM
Use the UUID of a Mend Container image project with one of these `-reportType` values:
`imgSpdx`, `imgSpdx_2_3`, `imgCycloneDX`, `imgCycloneDX_1_5`, or `imgCycloneDX_1_6`.
These types use the [Container SBoM export API](https://api-docs.mend.io/platform/3.0/reports/exportimgsbomreport)
instead of the SCA dependencies API. Existing SCA report types and defaults are unchanged.
The container request sets `scopeType` to `project` and populates `scopeUuid`,
`scopeUuidList`, and `projectUuids` with the project UUID being processed.

```shell
mend-reporting-tool -mendAPI $MEND_API -orgUUID $MEND_ORGANIZATION_UUID -userEmail $MEND_EMAIL -userKey $MEND_USER_KEY -projectUUID $CONTAINER_PROJECT_UUID -reportType imgCycloneDX_1_6 -format json -unzip yes
```

Comma-separated project UUIDs and `-unzip no` are supported just as for SCA reports.
The default format is `json`; other formats depend on the selected report type and API support.
Reports are downloaded as `report-<Project_UUID>.zip` and, by default, extracted to `mend-reports`.
Extracted files are renamed to `report-<Project_UUID>-<scanType>-<reportType>.<extension>`.

### How To Install
```shell
pip install 'mend-reporting-tool==0.3.0'
```

### How To Install from source code
```shell
git clone https://github.com/chelyshev/mend-reporting-tool.git
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```
