#!/usr/bin/env python3
"""
Fortigate Configuration Analyzer
A comprehensive tool to review Fortigate configurations offline and identify
misconfigurations and best practice violations.
"""

import re
import yaml
import json
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents a configuration finding"""
    category: str
    severity: Severity
    title: str
    description: str
    location: str
    recommendation: str
    current_value: str = ""


@dataclass
class ConfigAnalysis:
    """Stores the complete analysis results"""
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)
    score: int = 100


class FortiGateConfigAnalyzer:
    """Main analyzer class for Fortigate configurations"""
    
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = None
        self.analysis = ConfigAnalysis()
        self.yaml_format = None  # Track if using FortiGate 7.2+ YAML format
        
    def _get_config_section(self, *path):
        """
        Get configuration section handling both YAML formats
        
        Args:
            *path: Path components (e.g., 'system', 'global')
        
        Returns:
            Configuration section or empty dict
        """
        # For FortiGate 7.2+ YAML format: vdom -> [list] -> {vdom_name: {global: {system_X: ...}}}
        if 'vdom' in self.config:
            vdoms = self.config['vdom']
            if isinstance(vdoms, list) and len(vdoms) > 0:
                first_vdom = vdoms[0]
                if isinstance(first_vdom, dict):
                    vdom_data = list(first_vdom.values())[0]
                    
                    # Navigate through path
                    current = vdom_data
                    for component in path:
                        if isinstance(current, dict):
                            # Handle underscore variations (system_global vs system.global)
                            key = component.replace('.', '_')
                            if key in current:
                                current = current[key]
                            elif component in current:
                                current = current[component]
                            else:
                                return {}
                        else:
                            return {}
                    return current if isinstance(current, dict) else {}
        
        # For flat/CLI-parsed structure
        current = self.config
        for component in path:
            if isinstance(current, dict) and component in current:
                current = current[component]
            else:
                return {}
        return current if isinstance(current, dict) else {}
        
    def load_config(self) -> bool:
        """Load and parse the configuration file"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if not content.strip():
                print("Error: Configuration file is empty")
                return False
            
            print(f"File size: {len(content)} bytes")
            
            # Try YAML first
            print("Attempting to parse as YAML...")
            try:
                self.config = yaml.safe_load(content)
                if isinstance(self.config, dict) and self.config:
                    print(f"✅ Configuration loaded as YAML format")
                    print(f"Found top-level keys: {', '.join(list(self.config.keys())[:10])}")
                    return True
                elif self.config is None:
                    print("   YAML parsed but returned None (empty or comments only)")
                else:
                    print(f"   YAML parsed but got {type(self.config).__name__} instead of dict")
            except yaml.YAMLError as e:
                print(f"   Not valid YAML: {str(e)[:100]}")
            
            # Try JSON
            print("Attempting to parse as JSON...")
            try:
                self.config = json.loads(content)
                if isinstance(self.config, dict) and self.config:
                    print(f"✅ Configuration loaded as JSON format")
                    print(f"Found top-level keys: {', '.join(list(self.config.keys())[:10])}")
                    return True
                else:
                    print(f"   JSON parsed but got {type(self.config).__name__} instead of dict")
            except json.JSONDecodeError as e:
                print(f"   Not valid JSON: {str(e)[:100]}")
            
            # Parse Fortigate CLI format
            print("Attempting to parse as FortiGate CLI format...")
            self.config = self._parse_fortigate_cli(content)
            if isinstance(self.config, dict) and self.config:
                print(f"✅ Configuration loaded as FortiGate CLI format")
                print(f"Found configuration sections: {', '.join(list(self.config.keys())[:10])}")
                return True
            else:
                print("   Could not parse as FortiGate CLI format")
            
            # If we get here, nothing worked
            print("\n" + "="*70)
            print("Error: Could not parse configuration file in any supported format")
            print("="*70)
            print("\nFile preview (first 500 characters):")
            print("-" * 70)
            print(content[:500])
            print("-" * 70)
            print("\nSupported formats:")
            print("  1. FortiGate CLI - Lines starting with 'config', 'edit', 'set', 'end'")
            print("  2. YAML - Hierarchical format with colons and indentation")
            print("  3. JSON - Curly braces and quotes")
            print("\nPlease check if your file is:")
            print("  - A valid FortiGate configuration export")
            print("  - Properly formatted YAML or JSON")
            print("  - Not encrypted or corrupted")
            return False
            
        except FileNotFoundError:
            print(f"Error: Configuration file '{self.config_file}' not found")
            return False
        except UnicodeDecodeError as e:
            print(f"Error: File encoding issue - {e}")
            print("Try converting file to UTF-8 encoding")
            return False
        except Exception as e:
            print(f"Error loading config: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _parse_fortigate_cli(self, content: str) -> Dict:
        """Parse Fortigate CLI configuration format"""
        config = {}
        section_stack = [config]
        path_stack = []
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Start of a config block
            if line.startswith('config '):
                section_path = line.split('config ', 1)[1].strip().split()
                path_stack.append(section_path)
                
                # Navigate to the right place in config dict
                current = config
                for part in section_path:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                
                section_stack.append(current)
                
            # Edit block
            elif line.startswith('edit '):
                edit_name = line.split('edit ', 1)[1].strip().strip('"')
                current_section = section_stack[-1]
                
                if 'entries' not in current_section:
                    current_section['entries'] = {}
                
                current_section['entries'][edit_name] = {}
                section_stack.append(current_section['entries'][edit_name])
                
            # Set command
            elif line.startswith('set '):
                parts = line.split(None, 2)
                current_section = section_stack[-1]
                
                if len(parts) >= 3:
                    key = parts[1]
                    value = parts[2].strip('"')
                    current_section[key] = value
                elif len(parts) == 2:
                    current_section[parts[1]] = True
                    
            # End of block
            elif line == 'next':
                if len(section_stack) > 1:
                    section_stack.pop()
                    
            elif line == 'end':
                if len(section_stack) > 1:
                    section_stack.pop()
                if path_stack:
                    path_stack.pop()
        
        return config
    
    def analyze(self) -> ConfigAnalysis:
        """Run all analysis checks"""
        if not self.config:
            print("Configuration not loaded. Call load_config() first.")
            # Initialize empty summary to prevent KeyError
            self.analysis.summary = {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'INFO': 0,
                'TOTAL': 0
            }
            return self.analysis
        
        print("Starting Fortigate configuration analysis...")
        
        # Run all checks
        self._check_system_settings()
        self._check_admin_settings()
        self._check_firewall_policies()
        self._check_interfaces()
        self._check_vpn_settings()
        self._check_antivirus_ips()
        self._check_ha_settings()
        self._check_logging()
        self._check_snmp_settings()
        self._check_routing()
        self._check_dns_settings()
        self._check_ntp_settings()
        
        # Calculate summary and score
        self._calculate_summary()
        
        return self.analysis
    
    def _add_finding(self, category: str, severity: Severity, title: str, 
                     description: str, location: str, recommendation: str, 
                     current_value: str = ""):
        """Add a finding to the analysis"""
        finding = Finding(
            category=category,
            severity=severity,
            title=title,
            description=description,
            location=location,
            recommendation=recommendation,
            current_value=current_value
        )
        self.analysis.findings.append(finding)
    
    def _check_system_settings(self):
        """Check system-level settings"""
        
        # FortiGate 7.2+ YAML format uses vdom hierarchy
        # Structure: vdom -> [vdom_name] -> global -> system_global
        # OR flat structure: system -> global
        
        system = None
        global_settings = {}
        
        # Try FortiGate 7.2+ YAML structure first
        if 'vdom' in self.config:
            vdoms = self.config['vdom']
            if isinstance(vdoms, list) and len(vdoms) > 0:
                # Get first vdom (usually 'root')
                first_vdom = vdoms[0]
                if isinstance(first_vdom, dict):
                    vdom_data = list(first_vdom.values())[0]
                    if 'global' in vdom_data:
                        global_config = vdom_data['global']
                        global_settings = global_config.get('system_global', {})
        
        # Try flat structure (CLI parsed or older format)
        if not global_settings and 'system' in self.config:
            system = self.config['system']
            global_settings = system.get('global', {})
        
        # Check hostname
        hostname = global_settings.get('hostname', global_settings.get('alias', ''))
        if hostname in ['FortiGate', 'FGT', '']:
            self._add_finding(
                "System Configuration",
                Severity.MEDIUM,
                "Default Hostname Detected",
                "The device is using a default or generic hostname.",
                "system_global -> hostname",
                "Set a unique, descriptive hostname that follows your naming convention.",
                hostname
            )
        
        # Check timezone
        if 'timezone' not in global_settings:
            self._add_finding(
                "System Configuration",
                Severity.LOW,
                "Timezone Not Configured",
                "System timezone is not explicitly set.",
                "system_global -> timezone",
                "Configure timezone for accurate logging and scheduling."
            )
        
        # Check admin-timeout (might be named differently in YAML)
        admin_timeout = global_settings.get('admintimeout', global_settings.get('admin-timeout', '480'))
        if str(admin_timeout).isdigit() and int(admin_timeout) > 30:
            self._add_finding(
                "System Configuration",
                Severity.MEDIUM,
                "Admin Session Timeout Too Long",
                f"Admin session timeout is set to {admin_timeout} minutes.",
                "system_global -> admintimeout",
                "Set admin timeout to 15-30 minutes maximum for security.",
                str(admin_timeout)
            )
        
        # Check for pre-login banner
        pre_login_banner = global_settings.get('pre-login-banner', global_settings.get('pre_login_banner', 'disable'))
        if pre_login_banner in ['disable', False]:
            self._add_finding(
                "System Configuration",
                Severity.LOW,
                "Pre-login Banner Not Enabled",
                "Pre-login banner is not configured for legal protection.",
                "system_global -> pre-login-banner",
                "Enable pre-login banner with appropriate legal notice."
            )
    
    def _check_admin_settings(self):
        """Check administrative access settings"""
        system = self.config.get('system', {})
        admin_section = system.get('admin', {})
        
        if 'entries' in admin_section:
            admins = admin_section['entries']
            
            # Check for default admin account
            if 'admin' in admins:
                self._add_finding(
                    "Administrative Access",
                    Severity.HIGH,
                    "Default Admin Account Active",
                    "The default 'admin' account is still active.",
                    "config system admin",
                    "Rename or disable the default admin account and use custom administrator accounts."
                )
            
            # Check for accounts without strong authentication
            for admin_name, admin_config in admins.items():
                # Check for two-factor authentication
                if admin_config.get('two-factor') in ['disable', None]:
                    self._add_finding(
                        "Administrative Access",
                        Severity.HIGH,
                        f"Two-Factor Authentication Not Enabled for '{admin_name}'",
                        f"Administrator '{admin_name}' does not have 2FA enabled.",
                        f"config system admin -> edit {admin_name}",
                        "Enable two-factor authentication (TOTP, RADIUS, or LDAP with 2FA) for all admin accounts."
                    )
                
                # Check for wildcard trusthosts
                trusthost = admin_config.get('trusthost1', admin_config.get('trusthost', ''))
                if trusthost in ['0.0.0.0 0.0.0.0', '', '0.0.0.0/0']:
                    self._add_finding(
                        "Administrative Access",
                        Severity.CRITICAL,
                        f"No Trusted Host Restriction for '{admin_name}'",
                        f"Administrator '{admin_name}' can login from any IP address.",
                        f"config system admin -> edit {admin_name}",
                        "Configure specific trusted hosts/networks for administrative access."
                    )
    
    def _check_firewall_policies(self):
        """Check firewall policy configurations"""
        firewall = self.config.get('firewall', {})
        policy = firewall.get('policy', {})
        
        if 'entries' not in policy:
            self._add_finding(
                "Firewall Policies",
                Severity.INFO,
                "No Firewall Policies Found",
                "No firewall policies detected in configuration.",
                "config firewall policy",
                "Ensure firewall policies are properly configured."
            )
            return
        
        policies = policy['entries']
        
        for policy_id, policy_config in policies.items():
            # Check for 'any' services in policies
            service = policy_config.get('service', '')
            if service == 'ALL' or service == 'all':
                self._add_finding(
                    "Firewall Policies",
                    Severity.MEDIUM,
                    f"Policy {policy_id}: Using 'ALL' Services",
                    f"Policy {policy_id} allows all services instead of specific ones.",
                    f"config firewall policy -> edit {policy_id}",
                    "Restrict to only necessary services. Use service groups for multiple services.",
                    service
                )
            
            # Check for 'all' source/destination
            srcaddr = policy_config.get('srcaddr', '')
            dstaddr = policy_config.get('dstaddr', '')
            
            if srcaddr == 'all':
                self._add_finding(
                    "Firewall Policies",
                    Severity.MEDIUM,
                    f"Policy {policy_id}: Source Address Set to 'all'",
                    f"Policy {policy_id} allows traffic from any source.",
                    f"config firewall policy -> edit {policy_id}",
                    "Define specific source addresses or address groups.",
                    srcaddr
                )
            
            if dstaddr == 'all':
                self._add_finding(
                    "Firewall Policies",
                    Severity.MEDIUM,
                    f"Policy {policy_id}: Destination Address Set to 'all'",
                    f"Policy {policy_id} allows traffic to any destination.",
                    f"config firewall policy -> edit {policy_id}",
                    "Define specific destination addresses or address groups.",
                    dstaddr
                )
            
            # Check for disabled logging
            logtraffic = policy_config.get('logtraffic', 'disable')
            if logtraffic in ['disable', 'utm']:
                self._add_finding(
                    "Firewall Policies",
                    Severity.MEDIUM,
                    f"Policy {policy_id}: Logging Not Enabled",
                    f"Policy {policy_id} does not have full traffic logging enabled.",
                    f"config firewall policy -> edit {policy_id}",
                    "Enable 'logtraffic all' for security monitoring and compliance.",
                    logtraffic
                )
            
            # Check for missing UTM/security profiles
            action = policy_config.get('action', '')
            if action == 'accept':
                has_av = 'av-profile' in policy_config
                has_ips = 'ips-sensor' in policy_config
                has_webfilter = 'webfilter-profile' in policy_config
                has_app_control = 'application-list' in policy_config
                
                if not (has_av or has_ips or has_webfilter or has_app_control):
                    self._add_finding(
                        "Firewall Policies",
                        Severity.HIGH,
                        f"Policy {policy_id}: No Security Profiles Applied",
                        f"Policy {policy_id} accepts traffic without UTM inspection.",
                        f"config firewall policy -> edit {policy_id}",
                        "Apply appropriate security profiles (AV, IPS, Web Filter, Application Control)."
                    )
            
            # Check NAT settings
            nat = policy_config.get('nat', 'disable')
            if nat == 'enable':
                # Check for IP pool usage
                ippool = policy_config.get('ippool', 'disable')
                if ippool == 'disable':
                    self._add_finding(
                        "Firewall Policies",
                        Severity.LOW,
                        f"Policy {policy_id}: NAT Without IP Pool",
                        f"Policy {policy_id} uses NAT without an IP pool (port overload on outgoing interface).",
                        f"config firewall policy -> edit {policy_id}",
                        "Consider using IP pools for better control and tracking of NAT translations."
                    )
    
    def _check_interfaces(self):
        """Check interface configurations"""
        system = self.config.get('system', {})
        interface = system.get('interface', {})
        
        if 'entries' not in interface:
            return
        
        interfaces = interface['entries']
        
        for iface_name, iface_config in interfaces.items():
            # Check for interfaces without description
            if 'description' not in iface_config or not iface_config.get('description'):
                self._add_finding(
                    "Interface Configuration",
                    Severity.LOW,
                    f"Interface '{iface_name}': No Description",
                    f"Interface {iface_name} does not have a description.",
                    f"config system interface -> edit {iface_name}",
                    "Add descriptive comments to all interfaces for documentation."
                )
            
            # Check for management access on WAN interfaces
            mode = iface_config.get('mode', '')
            role = iface_config.get('role', '')
            allowaccess = iface_config.get('allowaccess', '')
            
            if role == 'wan' and allowaccess:
                protocols = allowaccess.split()
                dangerous_protocols = ['http', 'https', 'ssh', 'telnet', 'fgfm']
                found_dangerous = [p for p in protocols if p in dangerous_protocols]
                
                if found_dangerous:
                    self._add_finding(
                        "Interface Configuration",
                        Severity.CRITICAL,
                        f"Interface '{iface_name}': Management Access on WAN",
                        f"WAN interface {iface_name} allows management access: {', '.join(found_dangerous)}",
                        f"config system interface -> edit {iface_name}",
                        "Remove management access from WAN interfaces. Use dedicated management interfaces or VPN.",
                        allowaccess
                    )
            
            # Check for DHCP on critical interfaces
            if mode == 'dhcp' and role in ['lan', 'dmz']:
                self._add_finding(
                    "Interface Configuration",
                    Severity.MEDIUM,
                    f"Interface '{iface_name}': DHCP Client on Internal Interface",
                    f"Internal interface {iface_name} is configured as DHCP client.",
                    f"config system interface -> edit {iface_name}",
                    "Use static IP addressing for internal interfaces for stability."
                )
    
    def _check_vpn_settings(self):
        """Check VPN configurations"""
        vpn = self.config.get('vpn', {})
        
        # Check IPsec phase1
        ipsec_phase1 = vpn.get('ipsec', {}).get('phase1-interface', {})
        if 'entries' in ipsec_phase1:
            for vpn_name, vpn_config in ipsec_phase1['entries'].items():
                # Check for weak encryption
                proposal = vpn_config.get('proposal', '')
                if any(weak in proposal.lower() for weak in ['des', '3des', 'md5']):
                    self._add_finding(
                        "VPN Configuration",
                        Severity.HIGH,
                        f"VPN '{vpn_name}': Weak Encryption Algorithm",
                        f"VPN tunnel {vpn_name} uses weak encryption: {proposal}",
                        f"config vpn ipsec phase1-interface -> edit {vpn_name}",
                        "Use strong encryption: AES-256-GCM or AES-256-CBC with SHA-256 or better.",
                        proposal
                    )
                
                # Check DH group
                dhgrp = vpn_config.get('dhgrp', '')
                if dhgrp in ['1', '2', '5']:
                    self._add_finding(
                        "VPN Configuration",
                        Severity.HIGH,
                        f"VPN '{vpn_name}': Weak DH Group",
                        f"VPN tunnel {vpn_name} uses weak DH group: {dhgrp}",
                        f"config vpn ipsec phase1-interface -> edit {vpn_name}",
                        "Use DH group 14 or higher (preferably 19, 20, or 21).",
                        dhgrp
                    )
                
                # Check for DPD
                dpd = vpn_config.get('dpd', 'disable')
                if dpd == 'disable':
                    self._add_finding(
                        "VPN Configuration",
                        Severity.MEDIUM,
                        f"VPN '{vpn_name}': DPD Not Enabled",
                        f"Dead Peer Detection is disabled for VPN {vpn_name}",
                        f"config vpn ipsec phase1-interface -> edit {vpn_name}",
                        "Enable DPD (on-idle or on-demand) to detect and recover from failed tunnels."
                    )
        
        # Check SSL VPN settings
        ssl_vpn = vpn.get('ssl', {}).get('settings', {})
        if ssl_vpn:
            # Check for weak SSL/TLS versions
            ssl_min_version = ssl_vpn.get('ssl-min-proto-ver', '')
            if ssl_min_version in ['tls-1.0', 'tls-1.1', 'ssl-3.0']:
                self._add_finding(
                    "VPN Configuration",
                    Severity.HIGH,
                    "SSL VPN: Weak TLS Version Allowed",
                    f"SSL VPN allows weak TLS version: {ssl_min_version}",
                    "config vpn ssl settings",
                    "Set minimum TLS version to 1.2 or 1.3.",
                    ssl_min_version
                )
            
            # Check source address for SSL VPN
            source_address = ssl_vpn.get('source-address', '')
            if not source_address or source_address == 'all':
                self._add_finding(
                    "VPN Configuration",
                    Severity.MEDIUM,
                    "SSL VPN: No Source Address Restriction",
                    "SSL VPN portal allows connections from any source.",
                    "config vpn ssl settings",
                    "Restrict SSL VPN access to specific source IP ranges when possible."
                )
    
    def _check_antivirus_ips(self):
        """Check antivirus and IPS configurations"""
        # Check if security profiles exist
        has_av_profile = 'antivirus' in self.config
        has_ips_profile = 'ips' in self.config
        
        if not has_av_profile:
            self._add_finding(
                "Security Profiles",
                Severity.MEDIUM,
                "No Antivirus Profiles Configured",
                "No antivirus profiles found in configuration.",
                "config antivirus profile",
                "Create and apply antivirus profiles to firewall policies protecting critical assets."
            )
        
        if not has_ips_profile:
            self._add_finding(
                "Security Profiles",
                Severity.MEDIUM,
                "No IPS Sensors Configured",
                "No IPS sensors found in configuration.",
                "config ips sensor",
                "Create and apply IPS sensors to firewall policies for threat prevention."
            )
    
    def _check_ha_settings(self):
        """Check High Availability settings"""
        system = self.config.get('system', {})
        ha = system.get('ha', {})
        
        if ha:
            # Check encryption
            password = ha.get('password', '')
            if not password:
                self._add_finding(
                    "High Availability",
                    Severity.HIGH,
                    "HA Password Not Set",
                    "High Availability cluster does not have a password configured.",
                    "config system ha",
                    "Set a strong password for HA cluster authentication."
                )
            
            # Check heartbeat encryption
            hb_encrypt = ha.get('hb-encrypt', 'disable')
            if hb_encrypt == 'disable':
                self._add_finding(
                    "High Availability",
                    Severity.MEDIUM,
                    "HA Heartbeat Not Encrypted",
                    "HA heartbeat traffic is not encrypted.",
                    "config system ha",
                    "Enable heartbeat encryption to protect cluster communication."
                )
    
    def _check_logging(self):
        """Check logging configurations"""
        log = self.config.get('log', {})
        
        # Check for remote logging
        syslogd = log.get('syslogd', {}).get('setting', {})
        if not syslogd or syslogd.get('status') == 'disable':
            self._add_finding(
                "Logging",
                Severity.MEDIUM,
                "Remote Syslog Not Configured",
                "No remote syslog server configured for log retention.",
                "config log syslogd setting",
                "Configure remote syslog server for centralized logging and compliance."
            )
        
        # Check disk logging
        disk = log.get('disk', {}).get('setting', {})
        if disk:
            full_action = disk.get('full-final-warning-threshold', '95')
            if int(full_action) > 90:
                self._add_finding(
                    "Logging",
                    Severity.LOW,
                    "Disk Full Warning Threshold High",
                    f"Disk full warning threshold is {full_action}%",
                    "config log disk setting",
                    "Set disk full warning threshold to 80-85% for timely alerts."
                )
    
    def _check_snmp_settings(self):
        """Check SNMP configurations"""
        system = self.config.get('system', {})
        snmp = system.get('snmp', {})
        
        if not snmp:
            return
        
        # Check SNMP version
        community = snmp.get('community', {})
        if 'entries' in community:
            for comm_name, comm_config in community['entries'].items():
                # Check for default community strings
                if comm_name.lower() in ['public', 'private']:
                    self._add_finding(
                        "SNMP Configuration",
                        Severity.HIGH,
                        f"Default SNMP Community String: '{comm_name}'",
                        f"SNMP is using default community string '{comm_name}'",
                        "config system snmp community",
                        "Change default SNMP community strings to unique, complex values or use SNMPv3."
                    )
                
                # Check for SNMPv1/v2c without host restrictions
                hosts = comm_config.get('hosts', '')
                if not hosts or hosts == '0.0.0.0 0.0.0.0':
                    self._add_finding(
                        "SNMP Configuration",
                        Severity.HIGH,
                        f"SNMP Community '{comm_name}': No Host Restriction",
                        f"SNMP community {comm_name} allows access from any host.",
                        f"config system snmp community -> edit {comm_name}",
                        "Restrict SNMP access to specific management stations only."
                    )
        
        # Recommend SNMPv3
        sysinfo = snmp.get('sysinfo', {})
        if not snmp.get('user') and community:
            self._add_finding(
                "SNMP Configuration",
                Severity.MEDIUM,
                "SNMPv3 Not Configured",
                "Device is using SNMPv1/v2c instead of SNMPv3.",
                "config system snmp user",
                "Migrate to SNMPv3 for encrypted authentication and data privacy."
            )
    
    def _check_routing(self):
        """Check routing configurations"""
        router = self.config.get('router', {})
        static = router.get('static', {})
        
        if 'entries' in static:
            # Check for default route
            has_default = False
            for route_id, route_config in static['entries'].items():
                dst = route_config.get('dst', '')
                if dst == '0.0.0.0 0.0.0.0' or dst == '0.0.0.0/0':
                    has_default = True
                    
                    # Check if default route has distance configured
                    distance = route_config.get('distance', '10')
                    if distance == '1':
                        self._add_finding(
                            "Routing",
                            Severity.LOW,
                            "Default Route Uses Default Distance",
                            "Default route uses administrative distance of 1.",
                            f"config router static -> edit {route_id}",
                            "Consider adjusting route distance for proper failover behavior."
                        )
            
            if not has_default:
                self._add_finding(
                    "Routing",
                    Severity.INFO,
                    "No Default Route Configured",
                    "No default route (0.0.0.0/0) found in static routing table.",
                    "config router static",
                    "Ensure default route is configured if Internet access is required."
                )
    
    def _check_dns_settings(self):
        """Check DNS configurations"""
        system = self.config.get('system', {})
        dns = system.get('dns', {})
        
        if not dns:
            self._add_finding(
                "DNS Configuration",
                Severity.MEDIUM,
                "DNS Servers Not Configured",
                "No DNS servers configured on the device.",
                "config system dns",
                "Configure primary and secondary DNS servers for name resolution."
            )
            return
        
        primary = dns.get('primary', '')
        secondary = dns.get('secondary', '')
        
        if not primary:
            self._add_finding(
                "DNS Configuration",
                Severity.MEDIUM,
                "Primary DNS Not Set",
                "Primary DNS server is not configured.",
                "config system dns",
                "Configure a primary DNS server."
            )
        
        if not secondary:
            self._add_finding(
                "DNS Configuration",
                Severity.LOW,
                "Secondary DNS Not Set",
                "Secondary DNS server is not configured for redundancy.",
                "config system dns",
                "Configure a secondary DNS server for redundancy."
            )
    
    def _check_ntp_settings(self):
        """Check NTP configurations"""
        system = self.config.get('system', {})
        ntp = system.get('ntp', {})
        
        if not ntp or ntp.get('type') == 'manual':
            self._add_finding(
                "NTP Configuration",
                Severity.MEDIUM,
                "NTP Not Configured",
                "NTP time synchronization is not configured.",
                "config system ntp",
                "Configure NTP servers for accurate time synchronization (critical for logging and certificates)."
            )
            return
        
        # Check for multiple NTP servers
        ntpserver = ntp.get('ntpserver', {})
        if 'entries' in ntpserver:
            if len(ntpserver['entries']) < 2:
                self._add_finding(
                    "NTP Configuration",
                    Severity.LOW,
                    "Single NTP Server Configured",
                    "Only one NTP server configured - no redundancy.",
                    "config system ntp",
                    "Configure at least 2-3 NTP servers for redundancy."
                )
    
    def _calculate_summary(self):
        """Calculate findings summary and security score"""
        self.analysis.summary = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0,
            'TOTAL': len(self.analysis.findings)
        }
        
        # Count by severity
        for finding in self.analysis.findings:
            self.analysis.summary[finding.severity.value] += 1
        
        # Calculate score (100 - deductions)
        score = 100
        score -= self.analysis.summary['CRITICAL'] * 15
        score -= self.analysis.summary['HIGH'] * 8
        score -= self.analysis.summary['MEDIUM'] * 3
        score -= self.analysis.summary['LOW'] * 1
        
        self.analysis.score = max(0, score)
    
    def generate_report(self, output_format='text') -> str:
        """Generate analysis report"""
        if output_format == 'text':
            return self._generate_text_report()
        elif output_format == 'json':
            return self._generate_json_report()
        elif output_format == 'html':
            return self._generate_html_report()
        else:
            return self._generate_text_report()
    
    def _generate_text_report(self) -> str:
        """Generate text format report"""
        report = []
        report.append("=" * 80)
        report.append("FORTIGATE CONFIGURATION ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"\nConfiguration File: {self.config_file}")
        report.append(f"Analysis Date: {self._get_timestamp()}")
        report.append(f"\nSecurity Score: {self.analysis.score}/100")
        
        # Summary
        report.append("\n" + "-" * 80)
        report.append("FINDINGS SUMMARY")
        report.append("-" * 80)
        report.append(f"Total Findings: {self.analysis.summary['TOTAL']}")
        report.append(f"  CRITICAL: {self.analysis.summary['CRITICAL']}")
        report.append(f"  HIGH:     {self.analysis.summary['HIGH']}")
        report.append(f"  MEDIUM:   {self.analysis.summary['MEDIUM']}")
        report.append(f"  LOW:      {self.analysis.summary['LOW']}")
        report.append(f"  INFO:     {self.analysis.summary['INFO']}")
        
        # Detailed findings
        report.append("\n" + "=" * 80)
        report.append("DETAILED FINDINGS")
        report.append("=" * 80)
        
        # Group by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            findings = [f for f in self.analysis.findings if f.severity == severity]
            if not findings:
                continue
            
            report.append(f"\n{'*' * 80}")
            report.append(f"{severity.value} SEVERITY FINDINGS ({len(findings)})")
            report.append('*' * 80)
            
            for i, finding in enumerate(findings, 1):
                report.append(f"\n[{severity.value}-{i}] {finding.title}")
                report.append(f"Category: {finding.category}")
                report.append(f"Location: {finding.location}")
                if finding.current_value:
                    report.append(f"Current Value: {finding.current_value}")
                report.append(f"\nDescription:")
                report.append(f"  {finding.description}")
                report.append(f"\nRecommendation:")
                report.append(f"  {finding.recommendation}")
                report.append("-" * 80)
        
        # Best practices summary
        report.append("\n" + "=" * 80)
        report.append("BEST PRACTICES RECOMMENDATIONS")
        report.append("=" * 80)
        report.append(self._get_best_practices())
        
        return "\n".join(report)
    
    def _generate_json_report(self) -> str:
        """Generate JSON format report"""
        report_data = {
            'config_file': self.config_file,
            'analysis_date': self._get_timestamp(),
            'security_score': self.analysis.score,
            'summary': self.analysis.summary,
            'findings': [
                {
                    'category': f.category,
                    'severity': f.severity.value,
                    'title': f.title,
                    'description': f.description,
                    'location': f.location,
                    'recommendation': f.recommendation,
                    'current_value': f.current_value
                }
                for f in self.analysis.findings
            ]
        }
        return json.dumps(report_data, indent=2)
    
    def _generate_html_report(self) -> str:
        """Generate HTML format report"""
        severity_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#17a2b8',
            'INFO': '#6c757d'
        }
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>FortiGate Configuration Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .score {{ font-size: 48px; font-weight: bold; color: {'#28a745' if self.analysis.score >= 80 else '#ffc107' if self.analysis.score >= 60 else '#dc3545'}; text-align: center; margin: 20px 0; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .summary-card {{ padding: 15px; border-radius: 5px; text-align: center; color: white; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid; background-color: #f8f9fa; }}
        .finding-header {{ font-weight: bold; font-size: 18px; margin-bottom: 10px; }}
        .finding-meta {{ color: #666; font-size: 14px; margin: 5px 0; }}
        .recommendation {{ background-color: #e7f3ff; padding: 10px; margin-top: 10px; border-radius: 3px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #007bff; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ FortiGate Configuration Analysis Report</h1>
        <p><strong>Configuration File:</strong> {self.config_file}</p>
        <p><strong>Analysis Date:</strong> {self._get_timestamp()}</p>
        
        <div class="score">Security Score: {self.analysis.score}/100</div>
        
        <h2>Findings Summary</h2>
        <div class="summary">
            <div class="summary-card" style="background-color: {severity_colors['CRITICAL']}">
                <div style="font-size: 32px;">{self.analysis.summary['CRITICAL']}</div>
                <div>CRITICAL</div>
            </div>
            <div class="summary-card" style="background-color: {severity_colors['HIGH']}">
                <div style="font-size: 32px;">{self.analysis.summary['HIGH']}</div>
                <div>HIGH</div>
            </div>
            <div class="summary-card" style="background-color: {severity_colors['MEDIUM']}">
                <div style="font-size: 32px;">{self.analysis.summary['MEDIUM']}</div>
                <div>MEDIUM</div>
            </div>
            <div class="summary-card" style="background-color: {severity_colors['LOW']}">
                <div style="font-size: 32px;">{self.analysis.summary['LOW']}</div>
                <div>LOW</div>
            </div>
            <div class="summary-card" style="background-color: {severity_colors['INFO']}">
                <div style="font-size: 32px;">{self.analysis.summary['INFO']}</div>
                <div>INFO</div>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
"""
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            findings = [f for f in self.analysis.findings if f.severity == severity]
            if findings:
                html += f"<h3>{severity.value} Severity ({len(findings)})</h3>"
                for finding in findings:
                    html += f"""
        <div class="finding" style="border-left-color: {severity_colors[severity.value]}">
            <div class="finding-header">{finding.title}</div>
            <div class="finding-meta"><strong>Category:</strong> {finding.category}</div>
            <div class="finding-meta"><strong>Location:</strong> {finding.location}</div>
            """
                    if finding.current_value:
                        html += f'<div class="finding-meta"><strong>Current Value:</strong> {finding.current_value}</div>'
                    html += f"""
            <p>{finding.description}</p>
            <div class="recommendation">
                <strong>💡 Recommendation:</strong> {finding.recommendation}
            </div>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        return html
    
    def _get_best_practices(self) -> str:
        """Get best practices recommendations"""
        practices = [
            "1. Change all default passwords and usernames",
            "2. Enable two-factor authentication for all administrative accounts",
            "3. Restrict administrative access to trusted IP addresses only",
            "4. Use strong encryption for VPN tunnels (AES-256, SHA-256+)",
            "5. Apply security profiles (AV, IPS, Web Filter, App Control) to policies",
            "6. Enable logging on all firewall policies for audit and compliance",
            "7. Follow the principle of least privilege in firewall rules",
            "8. Configure remote syslog for centralized log management",
            "9. Keep FortiOS firmware up to date with latest patches",
            "10. Implement HA for critical deployments",
            "11. Use SNMPv3 instead of SNMPv1/v2c for monitoring",
            "12. Configure NTP for accurate time synchronization",
            "13. Regularly review and audit firewall policies",
            "14. Document all configuration changes",
            "15. Implement regular backup procedures for configurations"
        ]
        return "\n".join(practices)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def main():
    """Main execution function"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python fortigate_config_analyzer.py <config_file> [output_format]")
        print("Output formats: text (default), json, html")
        print("\nExample:")
        print("  python fortigate_config_analyzer.py config.conf")
        print("  python fortigate_config_analyzer.py config.conf html")
        sys.exit(1)
    
    config_file = sys.argv[1]
    output_format = sys.argv[2] if len(sys.argv) > 2 else 'text'
    
    if output_format not in ['text', 'json', 'html']:
        print(f"Error: Invalid output format '{output_format}'")
        print("Valid formats: text, json, html")
        sys.exit(1)
    
    print(f"Loading configuration from: {config_file}")
    analyzer = FortiGateConfigAnalyzer(config_file)
    
    if not analyzer.load_config():
        print("\n❌ Failed to load configuration file!")
        print("\nTroubleshooting:")
        print("1. Check if the file exists and is readable")
        print("2. Verify the file contains valid FortiGate configuration")
        print("3. Ensure the file is not corrupted or empty")
        print("4. Try with the sample_config.txt file to test the tool")
        sys.exit(1)
    
    print("Configuration loaded successfully!")
    print("\nAnalyzing configuration...\n")
    
    # Run analysis
    analysis = analyzer.analyze()
    
    # Check if analysis was successful
    if analysis.summary.get('TOTAL', 0) == 0 and not analysis.findings:
        print("⚠️  Warning: No findings generated. This could mean:")
        print("   - The configuration is perfect (unlikely)")
        print("   - The parser couldn't recognize the config format")
        print("   - The file structure is different than expected")
        print("\nConfiguration structure found:")
        if analyzer.config:
            print(f"   Top-level sections: {list(analyzer.config.keys())}")
    
    # Generate and display report
    report = analyzer.generate_report(output_format)
    
    # Save report to file
    output_file = f"fortigate_analysis_report.{output_format if output_format in ['json', 'html'] else 'txt'}"
    with open(output_file, 'w') as f:
        f.write(report)
    
    print(f"\n✅ Analysis complete! Report saved to: {output_file}")
    
    if output_format == 'text':
        print("\n" + report)
    elif output_format == 'html':
        print(f"\nOpen {output_file} in your web browser to view the report")
    elif output_format == 'json':
        print(f"\nJSON report saved. Parse it with your favorite JSON tool")
    
    # Print summary
    print("\n" + "="*80)
    print("QUICK SUMMARY")
    print("="*80)
    print(f"Security Score: {analysis.score}/100")
    print(f"Total Findings: {analysis.summary.get('TOTAL', 0)}")
    print(f"  CRITICAL: {analysis.summary.get('CRITICAL', 0)}")
    print(f"  HIGH:     {analysis.summary.get('HIGH', 0)}")
    print(f"  MEDIUM:   {analysis.summary.get('MEDIUM', 0)}")
    print(f"  LOW:      {analysis.summary.get('LOW', 0)}")
    print(f"  INFO:     {analysis.summary.get('INFO', 0)}")
    print("="*80)


if __name__ == "__main__":
    main()
