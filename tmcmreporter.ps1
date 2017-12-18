$starttime='2017-11-01';
$endtime='2017-11-30';
$timeresolution=10; # time slot aggregation or resolution; month=7, day=10, minute=16
$dbconfiguration=@{
    db_server=''; # SQL SERVER NAME OR IP ADDRESS
    db_name='db_ControlManager'; # TMCM DATABASE NAME
    db_user='sa'; # DB USER
    db_pass=''; # DB PASS
# Malware detections grouped by datetime, malware name
    sql1="SELECT CONVERT(char($timeresolution), CLF_LogGenerationTime, 20) AS 'DateTime', 
    dbo.tb_AVVirusLog.VLF_VirusName AS 'MalwareName', COUNT(*) AS 'Detections'
    FROM dbo.tb_AVVirusLog
    WHERE CLF_LogGenerationTime>='$starttime' AND CLF_LogGenerationTime<='$endtime'
    GROUP BY CONVERT(char($timeresolution), CLF_LogGenerationTime, 20), dbo.tb_AVVirusLog.VLF_VirusName
    order by 'DateTime'";
}

$temppath = split-path -parent $MyInvocation.MyCommand.Definition # path of currently executing script
try {
	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlConnection.ConnectionString = "Server=$($dbconfiguration.db_server); Database=$($dbconfiguration.db_name); Integrated Security=False; User ID=$($dbconfiguration.db_user); Password=$($dbconfiguration.db_pass);";
	$SqlConnection.Open()
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlCmd.CommandText=$dbconfiguration.sql1
	$SqlCmd.Connection = $SqlConnection
	$SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
	$SqlAdapter.SelectCommand = $SqlCmd
	$DataSet = New-Object System.Data.DataSet
	$SqlAdapter.Fill($DataSet)
}
catch {
	"ERROR connecting to db $($dbconfiguration.db_name) on server $($dbconfiguration.db_server)" | Out-File -filepath "$temppath\$($dbconfiguration.db_name).log";
	exit;
}

foreach($record in $DataSet.Tables[0])
{
    Write-Host "$($record.DateTime)`t$($record.MalwareName)`t$($record.Detections)"
}