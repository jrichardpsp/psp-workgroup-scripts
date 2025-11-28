Migrating Workgroup-Based Workstations to Entra Joined Using Support Scripts

Author: Jamie Richard
Email: jamie.richard@powersyncpro.com

##Use Case

You have multiple machines that are workgroup joined with no directory services.
You need to migrate them to Entra Joined without disrupting users’ local profiles.

These machines are not remotely managed (e.g., not in Intune or an RMM), and the migration must be completed manually.

PowerSyncPro should:
- Install and register correctly
- Schedule and run migration tasks
- Use the statically defined runbook bundled with the script (you cannot change the runbook from the PSP UI; the script hardcodes it)

##Limitations

- Only one local user profile can be migrated per machine.
- If multiple users exist, you must choose one to migrate.
- Additional users may sign in afterward using Entra UPN, but:
--> Their old local profile will not be automatically migrated. Data must be moved manually.
- You must have a Dummy AD Domain, containing a computer object for each workstation.

This can be:
The client’s existing AD domain, or A lightweight dummy domain running on the PSP server (e.g., pspdummy.local)

Licensing must include:
The dummy domain as the source, and
The Entra tenant (e.g., company.onmicrosoft.com) as the target.

##What You Need

#You must know:
- Hostname of the workgroup PC
- Local username for the profile being migrated
- Entra UPN (email address) of the target user
These values will be placed into a CSV included with the migration agent and deployed via RMM.

#You must have:
- A copy of the PowerSyncPro Migration Agent installer with .NET: PSPMigrationAgentInstaller.msi

The support scripts:
1-Lookup_User_GUID.ps1
2-Create_Dummy_AD_Objects.ps1
Workgroup_Migrator.ps1


###Steps to Complete###
1. Create the CSV
- Create a file named mig_db.csv with the following columns:
  computer_name,local_username,target_upn,target_entraid

Column Description
- computer_name	Hostname of the workgroup PC (e.g., CLIENT-WRK001)
- local_username	Local user account on the PC (e.g., John)
- target_upn	User’s Entra ID UPN (e.g., john.smith@company.co.nz)
- target_entraid	Leave blank — this will be auto-populated by a script.

An empty template CSV may also be used.

2. Populate Entra GUID From the UPN

Run:
.\1-Lookup_User_GUID.ps1 -CsvPath .\mig_db.csv

The script will:
- Prompt you to authenticate against the target Entra tenant.
- Look up each UPN.
- Populate the target_entraid column with the correct Entra GUID.

3. Prepare the Dummy AD Domain

PowerSyncPro requires computer objects in AD to represent each workstation.
Because workgroup PCs don't exist in AD, we must create dummy objects.

You have two options:
Use the client’s existing AD domain or Promote your PSP server to a DC and create a dummy domain (e.g., pspdummy.local)

You must:
- Add the dummy domain as a source directory in PowerSyncPro.
- Create a Match Only sync profile between the dummy AD and Entra.
- No users need to be matched — this is only for computer objects.

Once the domain structure is ready, run the dummy object creation script:

.\2-Create_Dummy_AD_Objects.ps1 -CsvPath .\mig_db.csv -TargetOU "OU=PSP Computers,DC=pspdummy,DC=local"
!! Ensure you have an OU that matches this name already created.  You cannot use the default computers container. !!

This will:
- Create AD computer objects for each computer_name in the CSV.
- Allow PSP to ingest them during sync.

Ensure:
- Dummy domain is configured in PSP
- You run a sync to import the objects
- Your PSP instance is licensed with the dummy domain as a source

4. Customize the Deployment Script (workgroup_migrator.ps1)

Before deployment, update the following variables:

Variable	-- Description

$basePath	-- Directory where CSV + MSI will be placed by RMM (e.g., C:\Temp)

$csvName	-- Must match the CSV filename, typically mig_db.csv

$domainName	-- FQDN of dummy AD (e.g., pspdummy.local)

$RunbookGUIDs	-- GUID(s) of the Runbook used for migration

$pspmig_loc	-- Filename of PSP Migration Agent installer

$psp_server	-- PSP server URL (e.g., https://psp1.company.com/Agent)

$psp_psk	-- Migration Agent PSK

To find the Runbook GUID, see:
https://kb.powersyncpro.com/workgroup-workstation-migration-process?from_search=181792766

After editing, save the script.

Deploy via RMM to in-scope machines:
- workgroup_migrator.ps1
- mig_db.csv
- PSPMigrationAgentInstaller.msi

Your RMM/Automox will deploy these to the workstation.

5. RMM Deployment Setup

Your RMM should:
- Deploy the CSV + MSI to the $baseDir (e.g., C:\Temp)
- Run workgroup_migrator.ps1 as SYSTEM or Administrator

The script will:
- Pre-stage device details
- Register the device with PSP
- Populate the translation/mapping table
- Trigger migration immediately if the device is already in an active batch (otherwise it will wait for its scheduled batch window)

##Logging##

The script logs extensively to: C:\Temp

This includes:
- PSP installer logs
- Migration prep logs

Script output

Any errors captured during prep or registration
