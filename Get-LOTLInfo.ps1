$pathToPathsCSV = "LOLBAS_filepaths.csv"
$outfile = "LOTLInfo_$(Get-Date -UFormat "%Y-%m-%d_%H-%M-%S").csv"

$data = import-csv $pathToPathsCSV
$outputdata = @()

# Include both OSBinaries and OtherMSBinaries, exclude OSLibraries and OSScripts
$data | Where-Object Category -like "*Binaries" | ForEach-Object {
    
    # for each file gather signature data with:
    # Select-Object -Property statusmessage, signaturetype, isosbinary -ExpandProperty SignerCertificate | Select-Object statusmessage, signaturetype, isosbinary, issuer, subject

    if (Test-Path -Path $_.Path){
        
         $outputdata += Get-AuthenticodeSignature $_.Path | Select-Object -Property statusmessage, signaturetype, isosbinary -ExpandProperty SignerCertificate | Select-Object statusmessage, signaturetype, isosbinary, issuer, subject
    }
}

$outputdata | Export-Csv -Path $outfile -NoTypeInformation

