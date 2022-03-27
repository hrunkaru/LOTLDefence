import os
from pathlib import Path
import yaml
# pip3 install pyyml to install module 'yaml'
import csv

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
                        print(fpath)
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

    # TODO: Add commandline argument parsing to replace hardcoded parameters

    # path to local copy of LOLBAS project files from this project:
    # https://github.com/LOLBAS-Project/LOLBAS
    pathToLOLBAS = "LOLBAS-data/LOLBAS-master"
    pathToYAMLs = Path(pathToLOLBAS, "yml")
    pathToOutputCSV = 'LOLBAS_filepaths.csv'
    
    # create list of filepaths to iterate
    filepaths = createFilepaths(pathToYAMLs)

    # create CSV summary of LOLBAS yaml files
    createCSVsummary(filepaths)
