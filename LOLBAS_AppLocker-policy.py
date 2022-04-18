import csv
import argparse
import time
import uuid

def createAppLockerPolicy(csv_in):

    xml_publisherrule = """\
<FilePublisherRule Id="{uuid}" Name="Signed by O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="Block Microsoft signed file execution outside of allowed locations (exceptions)" UserOrGroupSid="{sid}" Action="Deny">
    <Conditions>
    <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="*" BinaryName="*">
        <BinaryVersionRange LowSection="*" HighSection="*" />
    </FilePublisherCondition>
    </Conditions>
    <Exceptions>
    <FilePathCondition Path="%OSDRIVE%\ProgramData\*" />
    <FilePathCondition Path="%PROGRAMFILES%\*" />
    <FilePathCondition Path="%WINDIR%\*" />
    </Exceptions>
</FilePublisherRule>\
    """

    xml_template = """\
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="NotConfigured">
    {XMLPublisherRule}
    {XMLExecRules}
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="NotConfigured">
    {XMLWinInstRules}
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="NotConfigured">
    {XMLPublisherRule}
    {XMLScriptRules}
  </RuleCollection>
  <RuleCollection Type="Dll" EnforcementMode="NotConfigured">
    {XMLPublisherRule}
    {XMLDLLsRules}
  </RuleCollection>
  <RuleCollection Type="Appx" EnforcementMode="NotConfigured" />
</AppLockerPolicy>\
    """

    xml_template_defaults = """\
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="NotConfigured">
    {XMLPublisherRule}
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default Rule) All files located in the Program Files folder" Description="Allows members of the Everyone group to run applications that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="(Default Rule) All files located in the Windows folder" Description="Allows members of the Everyone group to run applications that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="(Default Rule) All files" Description="Allows members of the local Administrators group to run all applications." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
    {XMLExecRules}
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="NotConfigured">
    <FilePublisherRule Id="b7af7102-efde-4369-8a89-7a6a392d1473" Name="(Default Rule) All digitally signed Windows Installer files" Description="Allows members of the Everyone group to run digitally signed Windows Installer files." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FilePathRule Id="5b290184-345a-4453-b184-45305f6d9a54" Name="(Default Rule) All Windows Installer files in %systemdrive%\Windows\Installer" Description="Allows members of the Everyone group to run all Windows Installer files located in %systemdrive%\Windows\Installer." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\Installer\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="64ad46ff-0d71-4fa0-a30b-3f3d30c5433d" Name="(Default Rule) All Windows Installer files" Description="Allows members of the local Administrators group to run all Windows Installer files." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*.*" />
      </Conditions>
    </FilePathRule>
    {XMLWinInstRules}
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="NotConfigured">
    {XMLPublisherRule}
    <FilePathRule Id="06dce67b-934c-454f-a263-2515c8796a5d" Name="(Default Rule) All scripts located in the Program Files folder" Description="Allows members of the Everyone group to run scripts that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="9428c672-5fc3-47f4-808a-a0011f36dd2c" Name="(Default Rule) All scripts located in the Windows folder" Description="Allows members of the Everyone group to run scripts that are located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="ed97d0cb-15ff-430f-b82c-8d7832957725" Name="(Default Rule) All scripts" Description="Allows members of the local Administrators group to run all scripts." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
    {XMLScriptRules}
  </RuleCollection>
  <RuleCollection Type="Dll" EnforcementMode="NotConfigured">
    {XMLPublisherRule}
    <FilePathRule Id="bac4b0bf-6f1b-40e8-8627-8545fa89c8b6" Name="(Default Rule) Microsoft Windows DLLs" Description="Allows members of the Everyone group to load DLLs located in the Windows folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="3737732c-99b7-41d4-9037-9cddfb0de0d0" Name="(Default Rule) All DLLs located in the Program Files folder" Description="Allows members of the Everyone group to load DLLs that are located in the Program Files folder." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="fe64f59f-6fca-45e5-a731-0f6715327c38" Name="(Default Rule) All DLLs" Description="Allows members of the local Administrators group to load all DLLs." UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
    {XMLDLLsRules}
  </RuleCollection>
  <RuleCollection Type="Appx" EnforcementMode="NotConfigured">
    <FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db40eed693ba" Name="(Default Rule) All signed packaged apps" Description="Allows members of the Everyone group to run packaged apps that are signed." UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>\
    """

# String template for file path rules in AppLocker config
    filePathRule = """\
    <FilePathRule Id="{uuid}" Name="{filename}" Description="{description}" UserOrGroupSid="{sid}" Action="Deny">
        <Conditions>
            <FilePathCondition Path="{filepath}" />
        </Conditions>
    </FilePathRule>\n\
"""


# create variables to store rules in the collections of AppLocker    
    ExecCollection = ["exe", "com"]
    ExecRules = ''

    WinInstCollection = ["msi", "mst", "msp"]
    WinInstRules = ''

    ScriptsCollection = ["ps1", "bat", "cmd", "vbs", "js"]
    ScriptsRules = ''

    DLLsCollection = ["dll", "ocx"]
    DLLsRules = ''

# Packaged apps not applicable, rules can only be done based on publisher, also no examples included in LOLBAS project

    # Open input CSV 
    with open(csv_in) as input_csv:
        data = csv.reader(input_csv)
        IDcount = 1
        # Loop through lines of CSV
        for row in data:
            if(row[4] == "AppLocker"):

                FileName = row[1]
                FilePath = row[3]

            # Find correct collection for AppLocker rule
                if((FilePath.split("."))[-1].lower() in ExecCollection):
                    
                    rule = filePathRule.format(uuid = str(uuid.uuid4()), filename = FileName, description = "Rule automatically created by LOLBAS_AppLocker-policy.py script", sid = args.sid, filepath = FilePath)
                    ExecRules += rule

                elif((FilePath.split("."))[-1].lower() in WinInstCollection):
                    
                    rule = filePathRule.format(uuid = str(uuid.uuid4()), filename = FileName, description = "Rule automatically created by LOLBAS_AppLocker-policy.py script", sid = args.sid, filepath = FilePath)
                    WinInstRules += rule

                elif((FilePath.split("."))[-1].lower() in ScriptsCollection):
                    
                    rule = filePathRule.format(uuid = str(uuid.uuid4()), filename = FileName, description = "Rule automatically created by LOLBAS_AppLocker-policy.py script", sid = args.sid, filepath = FilePath)
                    ScriptsRules += rule

                elif((FilePath.split("."))[-1].lower() in DLLsCollection):
                    
                    rule = filePathRule.format(uuid = str(uuid.uuid4()), filename = FileName, description = "Rule automatically created by LOLBAS_AppLocker-policy.py script", sid = args.sid, filepath = FilePath)
                    DLLsRules += rule

    if(args.includepublisher):    
        if(args.excludedefaults):
            output = xml_template.format(XMLExecRules=ExecRules, XMLWinInstRules=WinInstRules, XMLScriptRules=ScriptsRules, XMLDLLsRules=DLLsRules, XMLPublisherRule=xml_publisherrule.format(uuid=str(uuid.uuid4()), sid=args.sid))
        else:
            output = xml_template_defaults.format(XMLExecRules=ExecRules, XMLWinInstRules=WinInstRules, XMLScriptRules=ScriptsRules, XMLDLLsRules=DLLsRules, XMLPublisherRule=xml_publisherrule.format(uuid=str(uuid.uuid4()), sid=args.sid))
    else:
        if(args.excludedefaults):
            output = xml_template.format(XMLExecRules=ExecRules, XMLWinInstRules=WinInstRules, XMLScriptRules=ScriptsRules, XMLDLLsRules=DLLsRules, XMLPublisherRule="")
        else:
            output = xml_template_defaults.format(XMLExecRules=ExecRules, XMLWinInstRules=WinInstRules, XMLScriptRules=ScriptsRules, XMLDLLsRules=DLLsRules, XMLPublisherRule="")
    return output



if __name__ == "__main__":
    # Get and parse arguments
    parser = argparse.ArgumentParser(description="Helper script to create policy XML for AppLocker from CSV input, script is from: https://github.com/hrunkaru/LOTLDefence",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-o", "--output", help="Output XML file path for AppLocker policy (default is current folder)")
    parser.add_argument("-e", "--excludedefaults", help="Exclude default AppLocker rules. Strongly suggested to include default rules, unless similar rules are in existing policy you plan to merge this one with.", default=False)
    parser.add_argument("-p", "--includepublisher", help="Include Publisher rule to block Microsoft signed binaries from non-native locations.", default=True, action='store_false')
    parser.add_argument("-s", "--src", help="Path to CSV output from LOLBAS-filepaths.py script (-p switch), where required rows are marked with AppLocker or WDAC manually", required=True)
    parser.add_argument("-t", "--sid", help="Target SID group for the created AppLocker policies.", required=True) # Add argument for user/group SID
    args = parser.parse_args()


    # Paths
    ## Input
    CSV_in = args.src

    ## Timestring to use in names
    timestr = time.strftime("_%Y%m%d_%H%M%S")

    ## WDAC Output file
    if(args.output):
        output_file = args.output
    else:
        output_file = 'AppLocker_policy' + timestr + '.xml'


    # Create data to output
    output_data = createAppLockerPolicy(CSV_in)

    # Save output to file
    with open (output_file, 'w') as policy_out:
        policy_out.write(output_data)
    print("All done, find the output file at: " + output_file)
