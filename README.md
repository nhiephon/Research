## Research
[Twitter](https://twitter.com/_nhiephon)

[Hackerone](https://hackerone.com/nhiephon)

[Facebook Whitehat](https://www.facebook.com/whitehat/profile/nhiephon.nat)

### 2022
<details><summary>CVE-2022-0273</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0273

</p>
</details>

<details><summary>CVE-2022-0405</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0405

</p>
</details>

<details><summary>CVE-2022-0406</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0406

</p>
</details>

<details><summary>CVE-2022-0574</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0574

</p>
</details>

<details><summary>CVE-2022-0578</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0578

</p>
</details>

<details><summary>CVE-2022-0665</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0665

</p>
</details>

<details><summary>CVE-2022-0697</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0697

</p>
</details>

<details><summary>CVE-2022-0716</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0716

</p>
</details>

<details><summary>CVE-2022-0726</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0726

</p>
</details>

<details><summary>CVE-2022-0727</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0727

</p>
</details>

<details><summary>CVE-2022-0761</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0761

</p>
</details>

<details><summary>CVE-2022-0912</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0912

</p>
</details>

<details><summary>CVE-2022-0917</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0917

</p>
</details>

<details><summary>CVE-2022-0950</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0950

</p>
</details>

<details><summary>CVE-2022-40405</summary>
<p>

#### [Description]
WoWonder Social Network Platform v4.1.2 was discovered to contain a SQL injection vulnerability via the offset parameter at requests.php?f=load-my-blogs.
#### [Vulnerability Type]
SQL Injection
#### [Vendor of Product]
WoWonder (www.wowonder.com)
#### [Affected Product Code Base]
WoWonder Social Network Platform - 4.1.2
#### [Affected Component]
target.website/requests.php?f=load-my-blogs&offset=inject_here
#### [Attack Type]
Remote
#### [Impact Information Disclosure]
True
#### [Attack Vectors]
Remote attackers can gain access to the database by exploiting a request to "requests.php?f=load-my-blogs" via "offset" parameter.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.wowonder.com
#### [Discoverer]
NXQ, nhiephon from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2022-42984</summary>
<p>

#### [Description]
WoWonder Social Network Platform 4.1.4 was discovered to contain a SQL injection vulnerability via the offset parameter at requests.php?f=search&s=recipients.
#### [Vulnerability Type]
SQL Injection
#### [Vendor of Product]
WoWonder (www.wowonder.com)
#### [Affected Product Code Base]
WoWonder Social Network Platform - 4.1.4
#### [Affected Component]
target.website/requests.php?f=search&s=recipients&query=inject_here
#### [Attack Type]
Remote
#### [Impact Denial of Service]
True
#### [Impact Information Disclosure]
True
#### [Attack Vectors]
Remote attackers can gain access to the database by exploiting a request to "requests.php?f=search&s=recipients" via "query" parameter.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.wowonder.com
#### [Discoverer]
NXQ, nhiephon from NCSC of Vietnam

</p>
</details>

### 2021
<details><summary>CVE-2021-3967</summary>
<p>

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3967

</p>
</details>

### 2020
<details><summary>CVE-2020-13905</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!GetPlugInInfo+0x0000000000038ed4.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
IrFanView 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll read file hdr. FORMATS!GetPlugInInfo+0x38ed4: 1006f044 8806 mov byte ptr [esi],al ds:002b:0af8f000=??
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted HDR file.
#### [Reference]
https://github.com/nhiephon/Research/blob/master/README.md \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
Nguyễn Quang and Lưu Minh Trí from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-13906</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!GetPlugInInfo+0x0000000000038eb7.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
IrFanView 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll read file hdr. FORMATS!GetPlugInInfo+0x38eb7: 1006f027 8806 mov byte ptr [esi],al ds:002b:0af4f000=??
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted HDR file.
#### [Reference]
https://github.com/nhiephon/Research/blob/master/README.md \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
TuanDA, HiepHV from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23545</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!ReadXPM_W+0x0000000000000531.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
IrFanView 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll read file xpm. FORMATS!ReadXPM_W+0x531: 10003991 880429 mov byte ptr [ecx+ebp],al ds:002b:0f7ff000=??
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted XPM file.
#### [Reference]
https://github.com/nhiephon/Research/blob/master/README.md \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
NXQ from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23546</summary>
<p>

### [Description]
IrfanView 4.54 allows attackers to cause a denial of service or possibly other unspecified impacts via a crafted XBM file, related to a "Data from Faulting Address is used as one or more arguments in a subsequent Function Call starting at FORMATS!ReadMosaic+0x0000000000000981.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
The data from the faulting address is later used to a function call
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
IrfanView 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll read file xbm. FORMATS!ReadMosaic+0x981: 10003171 8a91e8110d10 mov dl,byte ptr FORMATS!GetPlugInInfo+0x9b0b8  ds:002b:dcd9deb4=??
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted XBM file.
#### [Reference]
https://github.com/nhiephon/Research/blob/master/README.md \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
NXQ from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23549</summary>
<p>

#### [Description]
IrfanView 4.54 allows attackers to cause a denial of service or possibly other unspecified impacts via a crafted .cr2 file, related to a "Data from Faulting Address controls Branch Selection starting at FORMATS!GetPlugInInfo+0x00000000000047f6".
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
Denial Of Service, Overflow
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
IrFanView 32-bit - 4.54
#### [Affected Component]
FORMATS!GetPlugInInfo+0x47f6: 10039416 8b0a mov ecx, dword ptr [edx] ds:002b:48663000=????????
#### [Attack Type]
Local
#### [CVE Impact Other]
Denial of Service
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted CR2 file.
#### [Reference]
https://github.com/nhiephon/Research/blob/master/README.md \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
NPD from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23550</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!GetPlugInInfo+0x0000000000007e82.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
Irfanview 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll read file dds. FORMATS!GetPlugInInfo+0x7e82: 1003cb12 8807  mov byte ptr [edi], al  ds:002b:0ae3d000=??
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DDS file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
nhiephon from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23551</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!GetPlugInInfo+0x0000000000007e30.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
Irfanview 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll read file dds. FORMATS!GetPlugInInfo+0x7e30: 1003cac0 89448ffc  mov dword ptr [edi+ecx*4-4], eax ds:002b:0af2d000=????????
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DDS file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
nhiephon from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23552</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!GetPlugInInfo+0x0000000000007e62.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
Irfanview 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll read file dds. FORMATS!GetPlugInInfo+0x7e62: 1003caf2 8807  mov byte ptr [edi], al  ds:002b:0aebd000=??
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DDS file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
nhiephon from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23553</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!GetPlugInInfo+0x0000000000007d33.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
Irfanview 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll read file dds. FORMATS!GetPlugInInfo+0x7d33: 1003c9c3 f3a5 rep movs dword ptr es:[edi], dword ptr [esi]
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DDS file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
nhiephon from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23554</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!GetPlugInInfo+0x0000000000007e20.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
Irfanview 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll read file dds. FORMATS!GetPlugInInfo+0x7e20: 1003cab0 89448ff4  mov dword ptr [edi+ecx*4-0Ch], eax  ds:002b:0af1d000=????????
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DDS file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
nhiephon from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23555</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!GetPlugInInfo+0x0000000000007e6e.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
Irfanview 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll read file dds. FORMATS!GetPlugInInfo+0x7e6e: 1003cafe 8807  mov byte ptr [edi], al  ds:002b:0b03d000=??
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DDS file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
nhiephon from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23556</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!GetPlugInInfo+0x0000000000007e28.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
Irfanview 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll read file dds. FORMATS!GetPlugInInfo+0x7e28: 1003cab8 89448ff8  mov dword ptr [edi+ecx*4-8], eax ds:002b:0b0cd000=????????
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DDS file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
nhiephon from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23557</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!ShowPlugInSaveOptions_W+0x000000000000755d.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
IrfanView 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll version 4.55.4 read file DCR. FORMATS!ShowPlugInSaveOptions_W+0x755d: 10012eed 66891471        mov     word ptr [ecx+esi*2],dx  ds:002b:0b0a1000=????
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DCR file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
nhiephon from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23558</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!ShowPlugInSaveOptions_W+0x0000000000007f4b.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
IrfanView 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll version 4.55.4 read file DCR. FORMATS!ShowPlugInSaveOptions_W+0x7f4b: 100138db 66890c47        mov     word ptr [edi+eax*2],cx  ds:002b:1bc44e40=????
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DCR file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
nhiephon from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23559</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!ShowPlugInSaveOptions_W+0x0000000000007d7f.
#### [Additional Information]
Vendor fixed the error in the plugin. Please read "https://www.irfanview.com/plugins.htm"
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
IrfanView 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll version 4.55.4 read file DCR. FORMATS!ShowPlugInSaveOptions_W+0x7d7f: 1001370f 66891443 mov word ptr [ebx+eax*2],dx  ds:002b:0b0e1000=????
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DCR file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
nhiephon from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23560</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!ShowPlugInSaveOptions_W+0x000000000001bcab.
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
IrfanView 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll version 4.55.4 read file DCR. FORMATS!ShowPlugInSaveOptions_W+0x1bcab: 1002763b 6689047e        mov     word ptr [esi+edi*2],ax  ds:002b:4642d000=????
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DCR file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
nhiephon from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23561</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!ShowPlugInSaveOptions_W+0x0000000000005722.
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
IrfanView 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll version 4.55.4 read file DCR. FORMATS!ShowPlugInSaveOptions_W+0x5722: 100110b2 6689044a        mov     word ptr [edx+ecx*2],ax  ds:002b:0b0a1000=????
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DCR file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
SPT from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23562</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!ShowPlugInSaveOptions_W+0x000000000000aefe.
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
IrfanView 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll version 4.55.4 read file DCR. FORMATS!ShowPlugInSaveOptions_W+0xaefe: 1001688e d918            fstp    dword ptr [eax]      ds:002b:00000000=????????
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DCR file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
HuyenNT, KetDV from NCSC of Vietnam

</p>
</details>

<details><summary>CVE-2020-23563</summary>
<p>

#### [Description]
IrfanView 4.54 allows a user-mode write access violation starting at FORMATS!ShowPlugInSaveOptions_W+0x0000000000002cba.
#### [VulnerabilityType Other]
User mode write access violations
#### [Vendor of Product]
Irfanview
#### [Affected Product Code Base]
IrfanView 32-bit - 4.54
#### [Affected Component]
Plugin Formats.dll version 4.55.4 read file DCR. FORMATS!ShowPlugInSaveOptions_W+0x2cba: 1000e64a 6689044a        mov     word ptr [edx+ecx*2],ax  ds:002b:0b091000=????
#### [Attack Type]
Local
#### [CVE Impact Other]
User mode write access violations
#### [Attack Vectors]
To exploit vulnerability, someone must open a crafted DCR file.
#### [Reference]
https://github.com/nhiephon/Research \
https://www.irfanview.com/plugins.htm
#### [Discoverer]
LuongNP, ChienTD from NCSC of Vietnam

</p>
</details>
