from __future__ import print_function

import copy
import sys

# A package for reading passwords without displaying them on the console.
import getpass


class Menu:
    def __init__(self, args):
        self.export = None
        self.level = 0
        self.title = None
        self.options = None
        self.last_option = None
        self.args = args
        self.self_args = copy.deepcopy(args)
        self.lowest_level = 0

        self.build()

    def display(self):
        Menu.menu_print(self.title, 1)
        for i in range(1, len(self.options)):
            self.menu_print(str(i) + ". " + self.options[i - 1], 0)
        if self.options:
            self.menu_print(str(len(self.options)) + ". " + self.options[len(self.options) - 1], 1)
            self.menu_print("99. " + self.last_option, 0)
        self.handle_input()

    def build(self):
        display = True
        if self.level == 0:
            if not self.args.operation:
                self.title = "\nWelcome to the Policy Package Import/Export Tool.\n" \
                             "What would you like to do?"
                self.options = ["Import a package", "Export a package"]
                self.last_option = "Exit" if self.level == self.lowest_level else "Back"
            else:
                self.export = self.args.operation == "export"
                self.level = 1
                self.lowest_level = 1
                display = False
        elif self.level == 1 and self.export:
            if not self.args.name:
                self.title = "Please enter a Policy Package name to export:"
                self.options = []
            else:
                self.level = 2
                self.lowest_level = 2
                display = False
        elif self.level == 1 and not self.export:
            if not self.args.file:
                self.title = "Please specify the path to the file you wish to import:"
                self.options = []
            else:
                self.level = 2
                self.lowest_level = 2
                display = False
        elif self.level == 2:
            if not (self.args.username or self.args.password or
                        self.args.session_id or self.args.session_file or self.args.root):
                self.title = "Please select a login method:"
                self.options = ["Enter user credentials manually", "Login as Root",
                                "Use an existing session file", "Use an existing session UID"]
                self.last_option = "Back"
            else:
                if self.args.root:
                    self.self_args.login = '2'
                elif self.args.username or self.args.password:
                    self.self_args.login = '1'
                elif self.args.session_file:
                    self.self_args.login = '3'
                else:
                    self.self_args.login = '4'
                self.level = 3
                self.lowest_level = 3
                display = False
        elif self.level == 3 and self.export:
            if not self.args.force:
                self.title = "The script will run with the following parameters:\n" + \
                             "Export Access-Control layers = " + str(self.self_args.access or self.self_args.all) + "\n" + \
                             "Export NAT layers = " + str(self.self_args.nat or self.self_args.all) + "\n" + \
                             "Export Threat-Prevention layers = " + str(self.self_args.threat or self.self_args.all) + "\n" + \
                             "Export HTTPS Inspection layers = " + str(self.self_args.https or self.self_args.all) + "\n" + \
                             "Output-file name = " + str(self.self_args.output_file) + "\n" + \
                             "Management Server IP = " + str(self.self_args.management) + "\n" + \
                             "Management Server Port = " + str(self.self_args.port) + "\n" + \
                             "Management Server Domain = " + str(self.self_args.domain)
                self.options = ["Change Settings", "Run"]
                self.last_option = "Exit" if self.level == self.lowest_level else "Back"
            else:
                if not self.self_args.login == '1':
                    return
                else:
                    self.level = 5
        elif self.level == 3 and not self.export:
            if not self.args.force:
                self.title = "The script will run with the following parameters:\n" + \
                             "Custom name for imported package (optional) = " + str(self.self_args.name) + "\n" + \
                             "Management Server IP = " + str(self.self_args.management) + "\n" + \
                             "Management Server Port = " + str(self.self_args.port) + "\n" + \
                             "Management Server Domain = " + str(self.self_args.domain)
                self.options = ["Change Settings", "Run"]
                self.last_option = "Exit" if self.level == self.lowest_level else "Back"
            else:
                if not self.self_args.login == '1':
                    return
                else:
                    self.level = 5
        elif self.level == 4 and self.export:
            access_string = "Enable" if not self.self_args.access else "Disable"
            threat_string = "Enable" if not self.self_args.threat else "Disable"
            nat_string = "Enable" if not self.self_args.nat else "Disable"
            https_string = "Enable" if not self.self_args.https else "Disable"
            self.title = "Please select a setting to change:"
            self.options = [access_string + " export of Access-Control Rulebases",
                            threat_string + " export of Threat-Prevention Rulebases",
                            nat_string + " export of NAT Rulebases",
                            https_string + " export of HTTPS Inspection Rulebases",
                            "Output file name", "Change Management Server IP", "Change Management Server Port",
                            "Change the domain name"]
            self.last_option = "Exit" if self.level == self.lowest_level else "Back"
        elif self.level == 4 and not self.export:
            self.title = "Please select a setting to change:"
            self.options = ["Specify custom name for imported package",
                            "Change Management Server IP",
                            "Change Management Server Port", "Change the domain name"]
            self.last_option = "Exit" if self.level == self.lowest_level else "Back"
        elif self.level == 5:
            if not self.args.username:
                self.title = "Please enter your username:"
                self.options = []
            else:
                self.level = 6
                display = False
        elif self.level == 6:
            if not self.args.password:
                # The menu title will be provided at the password prompt
                self.title = ""
                self.options = []
            else:
                return
        if display:
            self.display()
        else:
            self.build()

    def handle_input(self):
        if self.level == 0:
            try:
                choice = int(raw_input())
                if choice == 1:
                    self.self_args.operation = "import"
                elif choice == 2:
                    self.self_args.operation = "export"
                elif choice == 99:
                    sys.exit(0)
                else:
                    self.display_wrong_choice()
            except ValueError:
                self.display_wrong_choice()
            self.export = self.self_args.operation == "export"
            self.level = 1
        elif self.level == 1 and self.export:
            self.self_args.name = raw_input()
            self.level = 2
        elif self.level == 1 and not self.export:
            self.self_args.file = raw_input()
            self.level = 2
        elif self.level == 2:
            try:
                choice = int(raw_input())
                if choice not in range(1, len(self.options) + 1) and not choice == 99:
                    self.display_wrong_choice()
                elif choice == 99:
                    if self.level == self.lowest_level:
                        sys.exit(0)
                    else:
                        self.level = 0
                else:
                    self.self_args.login = str(choice)
                    self.level = 3
            except ValueError:
                self.display_wrong_choice()
        elif self.level == 3:
            try:
                choice = int(raw_input())
                if choice == 1:
                    self.level = 4
                elif choice == 2:
                    if not self.self_args.login == '1':
                        return
                    self.level = 5
                elif choice == 99:
                    if self.level == self.lowest_level:
                        sys.exit(0)
                    else:
                        self.level = 2
                else:
                    self.display_wrong_choice()
            except ValueError:
                self.display_wrong_choice()
        elif self.level == 4 and self.export:
            try:
                choice = int(raw_input())
                if choice == 1:
                    self.self_args.access = not self.self_args.access
                    self.menu_print(
                        "Exporting of Access-Control layers " + "enabled" if self.self_args.access else "disabled", 2)
                elif choice == 2:
                    self.self_args.threat = not self.self_args.threat
                    self.menu_print(
                        "Exporting of Threat-Prevention layers " + "enabled" if self.self_args.threat else "disabled", 2)
                elif choice == 3:
                    self.self_args.nat = not self.self_args.nat
                    self.menu_print(
                        "Exporting of NAT layers " + "enabled" if self.self_args.nat else "disabled", 2)
                elif choice == 4:
                    self.self_args.https = not self.self_args.https
                    self.menu_print(
                        "Exporting of HTTPS Inspection layers " + "enabled" if self.self_args.https else "disabled", 2)
                elif choice == 5:
                    self.menu_print("Please enter the output file name:", 0)
                    self.self_args.output_file = raw_input()
                elif choice == 6:
                    self.menu_print("Please enter the IP address of the management server:", 0)
                    self.self_args.management = raw_input()
                elif choice == 7:
                    self.menu_print("Please enter the port on the management server to connect to:", 0)
                    self.self_args.port = raw_input()
                elif choice == 8:
                    self.menu_print("Please enter the IP address or name of the domain you wish to connect to:", 0)
                    self.self_args.domain = raw_input()
                self.level = 3
            except ValueError:
                self.display_wrong_choice()
        elif self.level == 4 and not self.export:
            try:
                choice = int(raw_input())
                if choice == 1:
                    self.menu_print("Please enter a name for the imported package", 0)
                    self.self_args.name = raw_input()
                elif choice == 2:
                    self.menu_print("Please enter the IP address of the management server:", 0)
                    self.self_args.management = raw_input()
                elif choice == 3:
                    self.menu_print("Please enter the port on the management server to connect to:", 0)
                    self.self_args.port = raw_input()
                elif choice == 4:
                    self.menu_print("Please enter the IP address or name of the domain you wish to connect to:", 0)
                    self.self_args.domain = raw_input()
                self.level = 3
            except ValueError:
                self.display_wrong_choice()
        elif self.level == 5:
            if not self.self_args.username:
                self.self_args.username = raw_input()
            self.level = 6
        elif self.level == 6:
            if not self.self_args.password:
                if sys.stdin.isatty():
                    self.self_args.password = getpass.getpass("Please enter your password:\n")
                else:
                    print("Attention! Your password will be shown on the screen!", file=sys.stderr)
                    self.self_args.password = raw_input("Please enter your password:\n")
            return
        self.build()

    def display_wrong_choice(self):
        self.menu_print("Invalid input. Please choose an option in the range 1:" + str(len(self.options)) + " or 99.",
                        1)
        self.handle_input()

    @staticmethod
    def menu_print(content, num_blank_lines):
        print(content)
        for i in range(1, num_blank_lines):
            print()
