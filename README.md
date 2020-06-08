# Research
# CVE-2020-13905
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!GetPlugInInfo+0x0000000000038ed4.

## [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"

## [VulnerabilityType Other]
User mode write access violations

## [Vendor of Product]
Irfanview

## [Affected Product Code Base]
IrFanView 32-bit - 4.54

## [Affected Component]
Plugin Formats.dll read file hdr. FORMATS!GetPlugInInfo+0x38ed4: 1006f044 8806 mov byte ptr [esi],al  ds:002b:0af8f000=??

## [Attack Type]
Local

## [CVE Impact Other]
User mode write access violations

## [Attack Vectors]
To exploit vulnerability, someone must open a crafted HDR file.

## [Reference]
https://github.com/nhiephon/Research/blob/master/README.md \
https://www.irfanview.com/plugins.htm

## [Discoverer]
nhiephon from NCSC of Vietnam

# CVE-2020-13906
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!GetPlugInInfo+0x0000000000038eb7.

## [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"

## [VulnerabilityType Other]
User mode write access violations

## [Vendor of Product]
Irfanview

## [Affected Product Code Base]
IrfanView 32-bit - 4.54

## [Affected Component]
Plugin Formats.dll read file hdr. FORMATS!GetPlugInInfo+0x38eb7: 1006f027 8806 mov byte ptr [esi],al  ds:002b:0af4f000=??

## [Attack Type]
Local

## [CVE Impact Other]
User mode write access violations

## [Attack Vectors]
To exploit vulnerability, someone must open a crafted HDR file.

## [Reference]
https://github.com/nhiephon/Research/blob/master/README.md \
https://www.irfanview.com/plugins.htm

## [Discoverer]
nhiephon from NCSC of Vietnam
