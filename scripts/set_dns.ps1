param(
    [string]$Server = "127.0.0.1"
)

$adapters = Get-DnsClientServerAddress -AddressFamily IPv4
foreach ($adapter in $adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $Server
}
