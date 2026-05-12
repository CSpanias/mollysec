---
title: "NTDS Extraction Methods"
date: "2026-03-13"
author: "mollysec"
description: "Article focusing the process of NTDS.dit file, Active Directory's database, during the password audit process."
featured: true
tags: [

]
categories: [

]
series: "Password Audits"
thumbnail: "/images/password-audits-part-1-thumbnail.jpg"
draft: true
---

# Comparison Matrix (Audit-Relevant Methods)

| Method | Speed | DC Impact | Network Traffic | Disk Space (DC) |
|--------|-------|-----------|-----------------|-----------------|
| **DRSUAPI** | Fast (minutes) | Minimal | Low (~100MB) | None |
| **VSS/NTDSUTIL** | Medium (15-30min) | Low | High (10GB+) | Temporary (~10GB) |
| **VSS/WMI** | Medium (15-30min) | Low | High (10GB+) | Temporary (~10GB) |
| **Kerb-Key-List** | Fast (minutes) | Minimal | Low | None |

The real difference:
-use-vss: Uses ntdsutil.exe (Microsoft's official AD backup tool) to create an IFM export, which internally uses shadow copies
-use-remoteSSWMI-NTDS: Uses vssadmin.exe via WMI to directly create and access shadow copies

Both are remote, both download files, both parse locally - the difference is which Windows tool is used to create the shadow copy and how it's accessed.

```bash
  -use-remoteSSWMI      Remotely create Shadow Snapshot via WMI and download SAM, SYSTEM and SECURITY from it, the
                        parse locally
  -use-remoteSSWMI-NTDS
                        Dump NTDS.DIT also when using the Remote Shadow Snapshot Method via WMI. Use it with dumping
                        from a DC. IMPORTANT: this flag only works when also using -use-remoteSSWMI
  -remoteSSWMI-remote-volume REMOTESSWMI_REMOTE_VOLUME
                        Remote Volume to perform the Shadow Snapshot and download SAM, SYSTEM and SECURITY. It
                        defaults to C:\
  -remoteSSWMI-local-path REMOTESSWMI_LOCAL_PATH
                        Path where download SAM, SYSTEM and SECURITY from Shadow Snapshot. It defaults to current path
```

### Method 3: NTDSUTIL Module - Living Off the Land

The `ntdsutil` module, implementend in [ntdsutil.py](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/ntdsutil.py),leverages Microsoft's legitimate [`ntdsutil.exe`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/use-ntdsutil-manage-ad-files) administrative tool. This method uses the [Install From Media (IFM) functionality](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc816722(v=ws.10)), which was designed to allow administrators to create installation media for new DCs without requiring network-based replication.

```bash
nxc smb 192.168.1.100 -u da-mollysec -p 'Passw0rd123!' -M ntdsutil
```

The module begins by executing `ntdsutil.exe` remotely via PowerShell to create a full IFM backup:

![NetExec's ntdsutil.py executing a full IFM backup](/images/nxc-ntds-ntdsutil-1.png "Executing a full IFM backup via PowerShell.")

The IFM export creates a structured directory containing the `NTDS.dit` database and registry hives. The module then retrieves three critical files over SMB: the `NTDS.dit` file containing the encrypted AD database, the `SYSTEM` hive containing the Boot Key needed for decryption, and the `SECURITY` hive containing cached credentials:

![Extracting the NTDS.dit, SYSTEM, and SECURITY files](/images/nxc-ntds-ntdsutil-2.png "Extracting the NTDS.dit, SYSTEM, and SECURITY files.")

It then instantiates Impacket's `NTDSHashes` class to parse the ESE database format used by `NTDS.dit`. The `isRemote=False` parameter indicates local file parsing, while `useVSSMethod=True` treats it as a VSS-style dump:

![Instatiating Impacket's NTDSHashes class](/images/nxc-ntds-ntdsutil-3.png "Instatiating Impacket's NTDSHashes class.")

As credentials are extracted, a callback function processes each hash through filtering and validation steps. The `--enabled` flag filters output to display only accounts that are currently enabled in AD, reducing noise from disabled accounts of former employees or decommissioned services. In addition, computer accounts (identified by the trailing `$`) are excluded, and valid NTLM hashes are stored in NetExec's credential database:

![Filtering NTLM hashes](/images/nxc-ntds-ntdsutil-4.png "Filtering NTLM hashes.")

After parsing completes, the module performs cleanup by removing the IFM export from the DC:

![Removing the IFM export from the DC](/images/nxc-ntds-ntdsutil-5.png "Removing the IFM export from the DC.")

If the `DIR_RESULT` option is specified, local copies are preserved and NetExec provides the command to re-parse files manually with `secretsdump.py`:

![Manual parsing of the extracted files with secretsdump](/images/nxc-ntds-ntdsutil-6.png "Manual parsing of the extracted files with secretsdump.")

This method requires local administrator privileges but does not require specific AD replication permissions. The operation generates significant disk activity and creates forensic artifacts including the IFM export directory and associated Windows event logs.

### Method 4: NTDS-DUMP-RAW Module - Raw Disk Access

The `ntds-dump-raw` module, implementend in [`ntds-dump-raw.py`](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/ntds-dump-raw.py), takes a fundamentally different approach by bypassing the Windows filesystem layer entirely. It reads raw disk sectors directly from `\\.\PhysicalDrive0`, allowing extraction of files that are actively locked by the operating system, such as `NTDS.dit`, which is held open exclusively by the AD database engine (`ntds.exe`).

The module reads the first 1024 bytes of the physical disk to identify the partition scheme (MBR or GPT) and locate the NTFS system partition:

![Reading the first 1024 bytes of the physical disk](/images/nxc-ntds-ntds_dump_raw-1.png "Reading the first 1024 bytes of the physical disk.")

It then reads the NTFS boot sector to extract filesystem metadata, i.e., bytes per sector, sectors per cluster, and the Master File Table (MFT) starting location:

![Extracting critical filesystem metadata](/images/nxc-ntds-ntds_dump_raw-2.png "Extracting critical filesystem metadata.")

The MFT contains a record for every file and directory on the volume. The module extracts the entire MFT (typically ~99MB on a DC) and parses it to locate `ntds.dit`, `SYSTEM`, and `SECURITY`. For each file, it:
1. Searches MFT records by examining the `$FILE_NAME` attribute
2. Reconstructs the full path to verify it's extracting the correct file (e.g., `C:\Windows\NTDS\ntds.dit`)
3. Decodes NTFS data runs to determine which physical disk clusters contain the file content
4. Reads file data directly from raw disk clusters, then gzip-compresses and base64-encodes it before transfer

With files successfully transferred, the module extracts the Boot Key from the `SYSTEM` registry hive and instantiates Impacket's `NTDSHashes` class with `isRemote=False` to parse the ESE database locally:

![Instantiating Impacket's NTDSHashes class](/images/nxc-ntds-ntds_dump_raw-10.png "Instantiating Impacket's NTDSHashes class.")

This method requires local administrator privileges and remote code execution capability. While it bypasses filesystem locks and does not require VSS, it generates significant network traffic during MFT and file extraction. The operation leaves minimal artifacts on the DC beyond command execution logs, as no shadow copies or temporary files are created on the target system.

### Comparative Analysis of Methods

| Feature | DRSUAPI | VSS | NTDSUTIL | RAW |
|---------|---------|-----|----------|---------------|
| **Speed** | Fast | Medium | Slow | Medium |
| **Disk Activity** | None | High | High | Medium |
| **File Artifacts** | None | Temporary | Temporary | None (on target) |
| **Network Traffic** | Low | Medium | Medium | Very High |
| **Required Permissions** | Replication rights | Local Admin | Local Admin | Local Admin |
| **Bypasses File Locks** | N/A | No (uses VSS) | No (uses VSS) | Yes |
| **Primary Use Case** | Default operations | No replication rights | Built-in tooling approach | VSS restricted |

## Native Windows Approach: ntdsutil.exe

Ntdsutil is Microsoft's native utility for NTDS database management, and its "Install From Media" (IFM) creation feature produces a complete, offline copy of NTDS.dit along with the necessary registry hives. This functionality was originally designed for promoting new domain controllers without network replication, but it serves our password audit purposes perfectly.

The IFM creation command is remarkably simple:

```bash
ntdsutil "activate instance ntds" "ifm" "create full C:\\temp\\ntds_dump" quit quit
```

Alternatively, we can use VSS snapshots for more granular control:

```bash
ntdsutil snapshot "activate instance ntds" create quit quit
ntdsutil snapshot "mount {GUID}" quit quit
copy <mounted_snapshot_path>\\Windows\\NTDS\\ntds.dit C:\\temp\\
copy <mounted_snapshot_path>\\Windows\\System32\\config\\SYSTEM C:\\temp\\
```

The native Windows approach offers significant advantages when we already have interactive access to a domain controller through RDP or WinRM. As a built-in Windows utility, ntdsutil requires no third-party software installation. The direct filesystem access eliminates network overhead, making this typically the fastest extraction method available. The tool produces clean, ready-to-transfer files in a single directory and leverages Windows' native shadow copy infrastructure for reliable VSS handling.

Ntdsutil does require execution directly on the domain controller, which means we need RDP, WinRM, or PSExec access. We also need to ensure sufficient disk space for the IFM set, which typically consumes several gigabytes depending on the Active Directory database size.

This method excels when we're operating from a Windows jump host within the client environment rather than our Kali attack platform. If we've already established an RDP session to perform other domain controller analysis, ntdsutil becomes the most efficient option available.

After extraction, we need to transfer the large files off the DC back to our analysis environment. We should also clean up the IFM directory to avoid leaving unnecessary artifacts, though from a pure password audit perspective this is more about professional hygiene than operational security.

# Benchmarking and Performance Testing

To determine the optimal extraction method for your specific environment, we recommend systematic benchmarking across several dimensions. Speed comparison testing should measure time to first hash (how quickly does extraction begin), total extraction time from initiation to usable output, and network transfer time for remote methods to understand the complete operational timeline.

Reliability testing involves running each method multiple times across different domain controllers to assess success rate consistency, error handling quality, and environmental dependencies such as specific network configurations or SPNs. We want to understand not just whether a method works, but how it fails when problems occur and whether error messages provide actionable troubleshooting information.

Output consistency verification ensures that all methods extract complete hash sets by comparing hash counts across methods, produce consistent formatting that's directly compatible with cracking tools, and capture additional credential material like cleartext passwords and Kerberos keys when relevant.

A sample benchmark template for documenting results:

| Method | Extraction Time | File Size | Hash Count | Success Rate | Notes |
| --- | --- | --- | --- | --- | --- |
| NetExec LDAP+VSS | TBD | TBD | TBD | TBD | Test from Kali |
| secretsdump | TBD | TBD | TBD | TBD | Test from Kali |
| ntdsutil | TBD | TBD | TBD | TBD | Test from DC RDP |
| Mimikatz DCSync | TBD | TBD | TBD | TBD | Test from Windows host |

Populate this table with results from your specific client environment to build institutional knowledge about which methods perform best under your typical engagement conditions.

# Conclusion

This first installment has established the foundational components of Active Directory password auditing: understanding how credentials are stored, why `NTDS.dit` extraction requires both the database and `SYSTEM` hive, and the various methods available for obtaining this critical data.

We've examined five distinct extraction approaches, each with specific technical implementations and operational tradeoffs:
* Impacket's `secretsdump` remains the industry standard for remote DCSync operations, offering reliable DRSUAPI-based extraction with minimal disk activity on the target DC. Its SMB dependency is rarely a limitation in standard password audit engagements.
* NetExec's four methods provide tactical flexibility: the default DRSUAPI wrapper for standard operations, VSS when replication permissions are unavailable, ntdsutil for living-off-the-land approaches, and raw disk access when filesystem-level restrictions apply.
* Native `ntdsutil.exe` excels when we already have interactive access to a domain controller, delivering the fastest extraction through direct filesystem access without network overhead.
* Mimikatz DCSync offers LDAP-based replication that bypasses SMB requirements, useful for quick verification of specific accounts or environments with restrictive network policies.

With DA credentials and network access to a domain controller, any of these methods will successfully extract the complete credential dataset. The choice between them depends on operational context: whether we're working remotely from Kali or locally from a Windows host, whether we need all hashes or targeted extraction, and whether specific network protocols face restrictions.