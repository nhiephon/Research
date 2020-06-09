# Research
```
_nhiephon@twitter.com
natuan1337@gmail.com
```

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

# ???
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!ReadXPM_W+0x0000000000000531.

## [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"

## [VulnerabilityType Other]
User mode write access violations

## [Vendor of Product]
Irfanview

## [Affected Product Code Base]
IrfanView 32-bit - 4.54

## [Affected Component]
Plugin Formats.dll read file xpm. FORMATS!ReadXPM_W+0x531:10003991 880429 mov byte ptr [ecx+ebp],al  ds:002b:0f7ff000=??

## [Attack Type]
Local

## [CVE Impact Other]
User mode write access violations

## [Attack Vectors]
To exploit vulnerability, someone must open a crafted XPM file.

## [Reference]
https://github.com/nhiephon/Research/blob/master/README.md \
https://www.irfanview.com/plugins.htm

## [Discoverer]
nhiephon from NCSC of Vietnam

# ???
IrfanView 4.54 allows data from Faulting Address is used as one or more arguments in a subsequent Function Call starting at FORMATS!ReadMosaic+0x0000000000000981.

## [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"

## [VulnerabilityType Other]
Data from the faulting address is later used to a function call.

## [Vendor of Product]
Irfanview

## [Affected Product Code Base]
IrfanView 32-bit - 4.54

## [Affected Component]
Plugin Formats.dll read file xbm. FORMATS!ReadMosaic+0x981: 10003171 8a91e8110d10 mov dl,byte ptr FORMATS!GetPlugInInfo+0x9b078  ds:002b:dcd9deb4=??

## [Attack Type]
Local

## [CVE Impact Other]

## [Attack Vectors]
To exploit vulnerability, someone must open a crafted XBM file.

## [Reference]
https://github.com/nhiephon/Research/blob/master/README.md \
https://www.irfanview.com/plugins.htm

## [Discoverer]
nhiephon from NCSC of Vietnam
