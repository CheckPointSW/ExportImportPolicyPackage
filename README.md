# ExportImportPolicyPackage
Check Point ExportImportPolicyPackage tool enables you to export a policy package from a R80.10 Management database to a .tar.gz file, which can then be imported into any other R80.10 Management database.

This tool can be used for backups, database transfers, testing, and more.

## Description
This tool enables you to export a policy package (Access Policy, Threat Policy or both) from a Management database into a .tar.gz file.

Notice: There are some types of objects that the script might not be able to export. In such a case, an appropriate dummy object will be exported instead, and a message will be logged into the log files to notify you of this. In the Check Point SmartConsole you can easily replace each of these objects by searching "export_error" in the search field, see where each object is used, create the necessary object manually, then replace it.

## Instructions
Clone the repository with this command:
```git
git clone --recursive https://github.com/CheckPoint-APIs-Team/ExportImportPolicyPackage
```
or by clicking the Download ZIP button. In this case, the "cp_mgmt_api_python_sdk" folder will be created empty and you will need to manually download and copy the [Check Point API Python SDK](https://github.com/CheckPoint-APIs-Team/cpapi-python-sdk) content into this folder.

To export a package, run the import_export_package.py script. An interactive menu will guide you the rest of the way. Command line flags may also be set in order to skip some or all of the menu.

#### A lot more details can of course be accessed with the '-h' option.

## Development Environment
The tool is developed using Python language version 2.7.9 and [Check Point API Python SDK.](https://github.com/CheckPoint-APIs-Team/cpapi-python-sdk)
