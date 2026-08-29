$ErrorActionPreference = 'Stop'

Write-Host 'The legacy Penumbra Gate installer at /install.ps1 has been withdrawn.' -ForegroundColor Yellow
Write-Host 'It referenced commands and build steps that the current Gate release does not provide.'
Write-Host 'No installation or system change was attempted.'
Write-Host ''
Write-Host 'Review the current, versioned instructions before installing:'
Write-Host '  https://penumbraforge.com/gate/wiki/getting-started/'
Write-Host '  https://github.com/penumbraforge/gate'

exit 1
