/**
 * CIC-IDS2017 Network Flow Telemetry Types
 * Schema reflects standard Canadian Institute for Cybersecurity (CIC-IDS2017) flow metrics.
 */

export interface NetworkFlowRecord {
  flowId: string;
  sourceIp: string;
  sourcePort: number;
  destinationIp: string;
  destinationPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP';
  timestamp: string;
  flowDurationMs: number;
  totalFwdPackets: number;
  totalBwdPackets: number;
  flowBytesPerSec: number;
  flowPacketsPerSec: number;
  synFlagCount: number;
  rstFlagCount: number;
  ackFlagCount: number;
  label: 'BENIGN' | 'PortScan' | 'DoS Slowloris' | 'DDoS' | 'FTP-Patator' | 'SSH-Patator' | 'Bot';
  provenance: string; // E.g., 'Synthetic Example (CIC-IDS2017 Schema)'
}
