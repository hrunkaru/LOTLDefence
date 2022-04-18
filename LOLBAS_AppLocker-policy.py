import csv
import argparse
import time
import uuid

def createAppLockerPolicy(csv_in):

    xml_template = """\
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="NotConfigured">
    {XMLExecRules}
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="NotConfigured">
    {XMLWinInstRules}
  </RuleCollection>
  <RuleCollection Type="Script" EnforcementMode="NotConfigured">
    {XMLScriptRules}
  </RuleCollection>
  <RuleCollection Type="Dll" EnforcementMode="NotConfigured">
    {XMLDLLsRules}
  </RuleCollection>
  <RuleCollection Type="Appx" EnforcementMode="NotConfigured" />
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
            if(row[3] == "AppLocker"):

                FileName = row[1]
                FilePath = row[4]

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



    output = xml_template.format(XMLExecRules=ExecRules, XMLWinInstRules=WinInstRules, XMLScriptRules=ScriptsRules, XMLDLLsRules=DLLsRules)
    return output



if __name__ == "__main__":
    # Get and parse arguments
    parser = argparse.ArgumentParser(description="Helper script to create policy XML for AppLocker from CSV input, script is from: https://github.com/hrunkaru/LOTLDefence",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-o", "--output", help="Output XML file path for AppLocker policy (default is current folder)")
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
