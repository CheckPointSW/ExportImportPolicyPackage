# ExportImportPolicyPackage
Check Point ExportImportPolicyPackage tool enables you to export a policy package from a Management database to a .tar.gz file, which can then be imported into any other Management database. The tool is supported for version R80.10 and above.

This tool can be used for backups, database transfers, testing, and more.

#### In the case you are exporting a policy package from a CMA, please verify that a global policy was NOT assigned to that CMA. The tool doesn't support exporting a policy with global policy assigned!

## Description
This tool enables you to export a policy package (Access Policy, Threat Policy or both) from a Management database into a .tar.gz file.

#### Release Notes:

* There are some types of objects that the script might not be able to export. In such a case, an appropriate dummy object will be exported instead, and a message will be logged into the log files to notify you of this. In the Check Point SmartConsole you can easily replace each of these objects by searching "export_error" in the search field, see where each object is used, create the necessary object manually, then replace it.

* Processing of Data Center Object types - before importing to the destination Management database, you must manually create a Data Center object using the exact same name as in the source Management database, and ensure connectivity.

## Instructions
Clone the repository with this command:
```git
git clone https://github.com/CheckPoint-APIs-Team/ExportImportPolicyPackage
```
or by clicking the Download ZIP button. 

Download and install the [Check Point API Python SDK](https://github.com/CheckPointSW/cp_mgmt_api_python_sdk) 
repository, follow the instructions in the SDK repository.

To export a package, run the import_export_package.py script. An interactive menu will guide you the rest of the way. Command line flags may also be set in order to skip some or all of the menu.

#### A lot more details can of course be accessed with the '-h' option. This option also prints the current version of the tool.

## Development Environment
The tool is developed using Python language version 2.7.9 and [Check Point API Python SDK.](https://github.com/CheckPoint-APIs-Team/cpapi-python-sdk)
