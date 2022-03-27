import os
from pathlib import Path
import yaml
# pip3 install pyyml to install module 'yaml'
import csv
import argparse
import time


def cleanYAMLlastline(data):
    if (data[-1:][0] == "---\n"):
            newdata = data[:-1]
    return newdata

def createFilepaths(pathToYamls):
    filepaths = []
    subdir_list = os.listdir(pathToYamls)
    for dir in subdir_list:
        filenames = os.listdir(Path(pathToYamls, dir))
        for filename in filenames:
            filepaths.append(str((Path(dir, filename))))
    return filepaths

def createCSVsummary(filepaths_list):
    with open (pathToOutputCSV, 'w') as csv_out:

        #Create CSV header
        writer = csv.writer(csv_out)
        writer.writerow(["Category", "Name", "Description", "Path"])

        for file in filepaths_list:
            splitname = file.split(".")

            with open(Path(pathToYAMLs, file), 'r') as yaml_in:
                lines = yaml_in.readlines()
                # Clean YAML files from appended '---' when no item is following
                yaml_data = cleanYAMLlastline(lines)
                data = yaml.load(''.join(yaml_data), Loader=yaml.FullLoader)

                recordtype = file.split("/")[-2]

                common_values = []
                common_values.append(recordtype)
                common_values.append(data['Name'] if ('Name' in data) else "N/A")
                common_values.append(data['Description'] if all(['Description' in data, len(str(data['Description'])) > 1]) else "N/A")
                try:
                    for fpath in data['Full_Path']:
                        write_values = []
                        write_values.extend(common_values)
                        if fpath['Path']:
                            if len(str(fpath['Path'])) > 1:
                                write_values.append(fpath['Path'])
                            else:
                                write_values.append("N/A")
                        else:
                            write_values.append("N/A")
                        writer.writerow(write_values)
                except:
                    write_values = []
                    write_values.extend(common_values)
                    write_values.append("N/A")
                    writer.writerow(write_values)





if __name__ == "__main__":
    # Get and parse arguments
    parser = argparse.ArgumentParser(description="Parser script to collect filepaths from LOLBAS project YAML files. \nLOLBAS Project: https://github.com/LOLBAS-Project/LOLBAS \nParser script from: https://github.com/hrunkaru/LOTLDefence",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-o", "--output", help="Output CSV file path (default is current folder)")
    parser.add_argument("-s", "--src", help="Path to local copy of LOLBAS project", required=True)
    args = parser.parse_args()

    # path to local copy of LOLBAS project files from this project:
    # https://github.com/LOLBAS-Project/LOLBAS
    pathToLOLBAS = args.src
    # path to yml files in the LOLBAS project
    pathToYAMLs = Path(pathToLOLBAS, "yml")

    # output file name and path
    timestr = time.strftime("_%Y%m%d_%H%M%S")
    if(args.output):
        pathToOutputCSV = args.output
    else:
        pathToOutputCSV = 'LOLBAS_filepaths' + timestr + '.csv'
    
    # create list of filepaths to iterate
    filepaths = createFilepaths(pathToYAMLs)

    # create CSV summary of LOLBAS yaml files
    createCSVsummary(filepaths)

    # print output when done
    print("Parsing done. Find the output file at: \n" + pathToOutputCSV)
