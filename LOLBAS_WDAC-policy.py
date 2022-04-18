import csv
import argparse
import time

def createWDACPolicy(csv_in):

    xml_template = """\
<?xml version="1.0" encoding="utf-8" ?> 
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
    <FileRules>
{FRules}
    </FileRules>
<SigningScenarios>
<SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="User Mode Signing Scenarios">
<ProductSigners>
    <FileRulesRef>
{FRulesRef}
    </FileRulesRef>
</ProductSigners>
</SigningScenario>
</SigningScenarios>
<UpdatePolicySigners /> 
<CiSigners /> 
<HvciOptions>0</HvciOptions> 
</SiPolicy>\
    """

    FileRules = ''
    FileRulesRef = ''

    with open(csv_in) as input_csv:
        data = csv.reader(input_csv)
        IDcount = 1
        for row in data:
            if(row[4] == "WDAC"):
            
                #IDstr =  'ID_DENY_LOLBAS_' + str(IDcount) + '_' + row[0]
                IDstr =  'ID_DENY_LOLBAS_' + row[0].upper() + '_' +str(IDcount)
                IDcount += 1
                FriendlyName = row[1]
                FilePath = row[3]

                FileRules += f'\t\t<Deny ID="{IDstr}" FriendlyName="{FriendlyName}" FilePath="{FilePath}" />\n'

                FileRulesRef += f'\t\t<FileRuleRef RuleID="{IDstr}" />\n'

    output = xml_template.format(FRules=FileRules, FRulesRef=FileRulesRef)
    return output



if __name__ == "__main__":
    # Get and parse arguments
    parser = argparse.ArgumentParser(description="Helper script to create policy XML for Windows Defender Application Control from CSV input, script is from: https://github.com/hrunkaru/LOTLDefence",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-o", "--wdacoutput", help="Output XML file path for WDAC policy (default is current folder)")
    parser.add_argument("-s", "--src", help="Path to CSV output from LOLBAS-filepaths.py script (-p switch), where required rows are marked with AppLocker or WDAC manually", required=True)
    args = parser.parse_args()


    # Paths
    ## Input
    CSV_in = args.src

    ## Timestring to use in names
    timestr = time.strftime("_%Y%m%d_%H%M%S")

    ## WDAC Output file
    if(args.wdacoutput):
        WDACOutput = 'args.wdacoutput'
    else:
        WDACOutput = 'WDAC_policy' + timestr + '.xml'


    # Create data to output
    output_data = createWDACPolicy(CSV_in)


    # Save output to file
    with open (WDACOutput, 'w') as policy_out:
        policy_out.write(output_data)
        print("All done, find output file at: " + WDACOutput)
