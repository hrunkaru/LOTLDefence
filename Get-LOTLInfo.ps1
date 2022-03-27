param ($pathToPathsCSV = "LOLBAS_filepaths.csv", $outfile = "LOTLInfo_$(Get-Date -UFormat "%Y-%m-%d_%H-%M-%S").csv")

$data = import-csv $pathToPathsCSV
$outputdata = @()
$countTestPath = 0

write-debug "Total items found from input CSV file: $($data | Measure-Object | Select-Object -ExpandProperty count)"

# filtering by type
# Include both OSBinaries and OtherMSBinaries, exclude OSLibraries and OSScripts
#write-debug "Total items after filtering by type: $($data | Where-Object Category -like "*Binaries" | Measure-Object | Select-Object -ExpandProperty count)"
#$data | Where-Object Category -like "*Binaries" | ForEach-Object {

# no filtering
$data  | ForEach-Object {
#    
    if (Test-Path -Path $_.Path){
        $countTestPath += 1

        $item = $(Get-AuthenticodeSignature $_.Path |
         Select-Object -Property * -ExpandProperty SignerCertificate | 
         Select-Object statusmessage, signaturetype, isosbinary, issuer, subject, Name, Path
         )
         $item.Name = $_.Name
         $item.Path = $_.Path
         $outputdata += $item

    }
    else {
        $item = $_ | Select-Object statusmessage, signaturetype, isosbinary, issuer, subject, Name, Path
        $item.StatusMessage = "File not found"
        $outputdata += $item
    }
}

write-debug "Total existing paths in the system: $countTestPath"
$outputdata | Export-Csv -Path $outfile -NoTypeInformation
write-debug "Total items in output data: $($outputdata | Measure-Object | Select-Object -expandproperty count)"

write-host "All done, find the output at: $outfile" 
