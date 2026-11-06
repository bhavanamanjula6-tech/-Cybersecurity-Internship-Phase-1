/**
 * Curated MITRE ATT&CK Enterprise v14.1 Reference Subset
 * Provenance: MITRE ATT&CK® Framework v14.1 (Enterprise Domain) - Curated Reference Subset
 * URL: https://attack.mitre.org
 * Notice: This is a curated reference subset for demonstration and triage correlation.
 * It does NOT claim complete framework coverage.
 */

import { MitreTactic, MitreTechnique, MitreMitigation } from '../types/mitre';

export const MITRE_PROVENANCE_INFO = {
  version: 'MITRE ATT&CK® v14.1 Enterprise (Curated Subset)',
  domain: 'Enterprise Matrix (Curated Reference Subset)',
  licensedUnder: 'Terms of Use: MITRE ATT&CK is a registered trademark of The MITRE Corporation.',
  coverageNotice: 'Curated demonstration subset; does not represent full framework coverage.',
  verifiedSource: 'https://attack.mitre.org',
  importedAt: '2026-10-12',
};

export const AUTHENTIC_MITRE_TACTICS: MitreTactic[] = [
  {
    id: 'TA0001',
    name: 'Initial Access',
    shortName: 'initial-access',
    description: 'Techniques used by adversaries to gain an initial foothold within a network.',
  },
  {
    id: 'TA0002',
    name: 'Execution',
    shortName: 'execution',
    description: 'Techniques that result in adversary-controlled code running on a local or remote system.',
  },
  {
    id: 'TA0003',
    name: 'Persistence',
    shortName: 'persistence',
    description: 'Techniques used to keep access to systems across restarts, changed credentials, and other interruptions.',
  },
  {
    id: 'TA0004',
    name: 'Privilege Escalation',
    shortName: 'privilege-escalation',
    description: 'Techniques used to gain higher-level permissions on a system or network.',
  },
  {
    id: 'TA0005',
    name: 'Defense Evasion',
    shortName: 'defense-evasion',
    description: 'Techniques used to avoid detection throughout their compromise.',
  },
  {
    id: 'TA0006',
    name: 'Credential Access',
    shortName: 'credential-access',
    description: 'Techniques for stealing credentials like account names and passwords.',
  },
  {
    id: 'TA0007',
    name: 'Discovery',
    shortName: 'discovery',
    description: 'Techniques an adversary may use to observe the system and its environment.',
  },
  {
    id: 'TA0008',
    name: 'Lateral Movement',
    shortName: 'lateral-movement',
    description: 'Techniques an adversary uses to extend access to other systems on a network.',
  },
  {
    id: 'TA0011',
    name: 'Command and Control',
    shortName: 'command-and-control',
    description: 'Techniques used to communicate with systems under adversary control within a victim network.',
  },
  {
    id: 'TA0040',
    name: 'Impact',
    shortName: 'impact',
    description: 'Techniques used by adversaries to disrupt availability or compromise integrity of systems and data.',
  },
];

export const AUTHENTIC_MITRE_MITIGATIONS: MitreMitigation[] = [
  {
    id: 'M1017',
    name: 'User Training',
    description: 'Train users to be aware of access or social engineering techniques and report unexpected activity.',
    sourceUrl: 'https://attack.mitre.org/mitigations/M1017/',
  },
  {
    id: 'M1026',
    name: 'Privileged Account Management',
    description: 'Manage the creation, modification, use, and permissions associated with privileged accounts.',
    sourceUrl: 'https://attack.mitre.org/mitigations/M1026/',
  },
  {
    id: 'M1038',
    name: 'Execution Prevention',
    description: 'Block execution of code initiating from unauthorized sources or paths via AppLocker, WDAC, or Software Restriction Policies.',
    sourceUrl: 'https://attack.mitre.org/mitigations/M1038/',
  },
  {
    id: 'M1040',
    name: 'Network Segmentation',
    description: 'Architect sections of the network to isolate critical systems, functions, or sensitive data groups.',
    sourceUrl: 'https://attack.mitre.org/mitigations/M1040/',
  },
  {
    id: 'M1027',
    name: 'Password Policies',
    description: 'Set and enforce secure password policies for accounts, including length, complexity, and expiration restrictions.',
    sourceUrl: 'https://attack.mitre.org/mitigations/M1027/',
  },
  {
    id: 'M1042',
    name: 'Disable or Remove Feature or Program',
    description: 'Remove or disable unnecessary components, software services, and administrative interfaces to reduce surface area.',
    sourceUrl: 'https://attack.mitre.org/mitigations/M1042/',
  },
  {
    id: 'M1018',
    name: 'User Account Management',
    description: 'Manage user accounts to prevent unauthorized creation, modification, or credential misuse.',
    sourceUrl: 'https://attack.mitre.org/mitigations/M1018/',
  },
  {
    id: 'M1037',
    name: 'Filter Network Traffic',
    description: 'Use network appliances or host firewalls to filter ingress and egress network traffic.',
    sourceUrl: 'https://attack.mitre.org/mitigations/M1037/',
  },
];

export const AUTHENTIC_MITRE_TECHNIQUES: MitreTechnique[] = [
  {
    id: 'T1059.001',
    name: 'Command and Scripting Interpreter: PowerShell',
    tactics: ['TA0002'],
    description: 'Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.',
    platforms: ['Windows'],
    dataSources: ['Process: Process Creation', 'Script: Script Execution', 'Command: Command Execution'],
    mitigationIds: ['M1038', 'M1042'],
    detectionGuidance: 'Monitor process creation arguments for powershell.exe invoking -enc, -EncodedCommand, -nop, -WindowStyle Hidden, or downloading external scripts via Net.WebClient or Invoke-WebRequest. Enable PowerShell Script Block Logging (Event ID 4104).',
    sourceUrl: 'https://attack.mitre.org/techniques/T1059/001/',
  },
  {
    id: 'T1003.001',
    name: 'OS Credential Dumping: LSASS Memory',
    tactics: ['TA0006'],
    description: 'Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).',
    platforms: ['Windows'],
    dataSources: ['Process: Process Access', 'Command: Command Execution'],
    mitigationIds: ['M1026', 'M1042'],
    detectionGuidance: 'Monitor processes requesting PROCESS_VM_READ or PROCESS_ALL_ACCESS access masks to lsass.exe (e.g. Sysmon Event ID 10). Detect usage of procdump.exe, comsvcs.dll MiniDump exports, or Mimikatz signatures.',
    sourceUrl: 'https://attack.mitre.org/techniques/T1003/001/',
  },
  {
    id: 'T1047',
    name: 'Windows Management Instrumentation',
    tactics: ['TA0002'],
    description: 'Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and conduct remote process spawning.',
    platforms: ['Windows'],
    dataSources: ['Process: Process Creation', 'Network Traffic: Network Connection Creation'],
    mitigationIds: ['M1026', 'M1040'],
    detectionGuidance: 'Monitor for wmic.exe process spawning child processes (cmd.exe, powershell.exe) or RPC endpoint mapper activity over TCP port 135 followed by dynamic high-range RPC ports.',
    sourceUrl: 'https://attack.mitre.org/techniques/T1047/',
  },
  {
    id: 'T1021.002',
    name: 'Remote Services: SMB/Windows Admin Shares',
    tactics: ['TA0008'],
    description: 'Adversaries may use valid accounts to remotely access administrative file shares (C$, ADMIN$) to move laterally within an environment.',
    platforms: ['Windows'],
    dataSources: ['Network Traffic: Network Connection Creation', 'Logon Session: Logon Session Creation'],
    mitigationIds: ['M1040', 'M1026'],
    detectionGuidance: 'Monitor Windows Event ID 5140 (network share object accessed) targeting IPC$, ADMIN$, or C$ from anomalous internal source IPs. Monitor TCP port 445 cross-subnet traffic.',
    sourceUrl: 'https://attack.mitre.org/techniques/T1021/002/',
  },
  {
    id: 'T1078.002',
    name: 'Valid Accounts: Domain Accounts',
    tactics: ['TA0001', 'TA0003', 'TA0004', 'TA0008'],
    description: 'Adversaries may obtain and abuse credentials of existing domain accounts to maintain persistence, elevate privileges, or move laterally.',
    platforms: ['Windows'],
    dataSources: ['Logon Session: Logon Session Creation', 'User Account: User Account Authentication'],
    mitigationIds: ['M1026', 'M1027', 'M1018'],
    detectionGuidance: 'Monitor for logon type 3 (network) and logon type 10 (remote interactive) anomalies, unusual logon hours, impossible travel, or access from non-standard endpoints.',
    sourceUrl: 'https://attack.mitre.org/techniques/T1078/002/',
  },
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactics: ['TA0001'],
    description: 'Adversaries may attempt to exploit a vulnerability in an Internet-facing computer or program using software, bug, or misconfiguration.',
    platforms: ['Linux', 'Windows', 'Network'],
    dataSources: ['Application Log: Application Log Content', 'Network Traffic: Network Traffic Flow'],
    mitigationIds: ['M1040', 'M1037', 'M1042'],
    detectionGuidance: 'Correlate web server log HTTP 500 errors, anomalous child processes spawned by w3wp.exe, nginx, or httpd, and spikes in URI payload sizes.',
    sourceUrl: 'https://attack.mitre.org/techniques/T1190/',
  },
  {
    id: 'T1071.001',
    name: 'Application Layer Protocol: Web Protocols',
    tactics: ['TA0011'],
    description: 'Adversaries may communicate using application layer protocols associated with web traffic (HTTP/HTTPS) to blend in with normal network traffic.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSources: ['Network Traffic: Network Traffic Content', 'Network Traffic: Network Traffic Flow'],
    mitigationIds: ['M1037'],
    detectionGuidance: 'Inspect TLS handshake certificates for self-signed or newly created domains, high-frequency beaconing intervals (jitter analysis), and anomalous User-Agent strings.',
    sourceUrl: 'https://attack.mitre.org/techniques/T1071/001/',
  },
  {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactics: ['TA0040'],
    description: 'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.',
    platforms: ['Windows', 'Linux', 'macOS'],
    dataSources: ['File: File Modification', 'Process: Process Creation'],
    mitigationIds: ['M1038', 'M1040'],
    detectionGuidance: 'Detect high-frequency file modification spikes across shared storage, deletion of Volume Shadow Copies (vssadmin delete shadows), and mass file extension renaming.',
    sourceUrl: 'https://attack.mitre.org/techniques/T1486/',
  },
];
