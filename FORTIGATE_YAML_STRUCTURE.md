# FortiGate YAML Configuration Structure Guide

## Overview

FortiGate supports two YAML formats depending on the FortiOS version:

### Format 1: FortiGate 7.2+ Official YAML Format

Starting with FortiOS 7.2.0, FortiGate can export configurations in YAML format using:
```bash
execute backup yaml-config tftp filename.yaml server_ip
```

**Structure:**
```yaml
vdom:
  - root:                    # VDOM name
      global:                # Global configurations
        system_global:       # System global settings
          hostname: "FortiGate-301E"
          timezone: "04"
          vdom-mode: "multi-vdom"
        
        system_accprofile:   # System access profiles
          - prof_admin:
              secfabgrp: "read-write"
              ftviewgrp: "read-write"
        
        system_admin:        # Administrator accounts
          - admin:
              accprofile: "super_admin"
              password: "ENC xxxxx"
        
        firewall_policy:     # Firewall policies
          - 261:             # Policy ID
              uuid: "xxxxx"
              srcintf: "port1"
              dstintf: "port2"
              srcaddr: ["addr1", "addr2"]  # Note: List format
              dstaddr: ["addr3"]
              action: "accept"
              service: ["HTTP", "HTTPS"]  # Note: List format
```

**Key Characteristics:**
- **Top level:** Always starts with `vdom:`
- **VDOM structure:** List of VDOMs, each as a dictionary
- **Section naming:** Uses underscores (e.g., `system_global`, `firewall_policy`)
- **List handling:** Multiple values become YAML lists with brackets `[...]`
- **Policy IDs:** Numeric IDs in quotes (e.g., `"261":`)

### Format 2: CLI-Parsed or Custom YAML

Converted from FortiGate CLI format or older exports:

**Structure:**
```yaml
system:
  global:
    hostname: "FortiGate"
    admintimeout: "480"
    timezone: "04"
  
  admin:
    entries:
      admin:
        accprofile: "super_admin"
        vdom: "root"
        password: "ENC xxxxx"
        trusthost1: "0.0.0.0 0.0.0.0"
  
  interface:
    entries:
      port1:
        ip: "192.168.1.1 255.255.255.0"
        role: "wan"

firewall:
  policy:
    entries:
      "1":
        name: "Allow-All"
        srcintf: "port2"
        dstintf: "port1"
        srcaddr: "all"
        dstaddr: "all"
        service: "ALL"
```

**Key Characteristics:**
- **Top level:** Direct section names (`system`, `firewall`, `router`)
- **Sub-sections:** Uses `entries:` for lists of items
- **Flat structure:** No vdom wrapper
- **Naming:** May use hyphens (e.g., `pre-login-banner`)

## Common YAML Issues from FortiGate Exports

### Issue 1: Multiple Quoted Values

**Problem:**
FortiGate CLI format uses space-separated quoted strings which don't parse correctly in YAML:

```yaml
# WRONG - Invalid YAML
srcaddr: "addr1" "addr2" "addr3"
service: "HTTP" "HTTPS"
domain-name-suffix: "domain1.com" "domain2.com"
```

**Correct YAML:**
```yaml
srcaddr: ["addr1", "addr2", "addr3"]
service: ["HTTP", "HTTPS"]
domain-name-suffix: ["domain1.com", "domain2.com"]
```

**Our Fixer:** `fix_fortigate_yaml.py` automatically converts these

### Issue 2: Escaped Quotes

**Problem:**
Single quotes escaped with backslash inside double-quoted strings:

```yaml
# WRONG - Invalid YAML
description: "An administrator\'s session"
comment: "User\'s profile"
```

**Correct YAML:**
```yaml
description: "An administrator's session"
comment: "User's profile"
```

**Our Fixer:** `fix_fortigate_yaml.py` automatically removes unnecessary escapes

### Issue 3: List Syntax Variations

FortiGate 7.2+ sometimes exports multi-value fields inconsistently:

```yaml
# Version A - Space-separated strings (INVALID)
srcaddr: "addr1" "addr2"

# Version B - Already in list format (VALID)
srcaddr: ["addr1", "addr2"]

# Version C - Flow style (VALID but uncommon)
srcaddr: [addr1, addr2]
```

## Configuration Mapping

### CLI → YAML (7.2+) Mapping

| CLI Command | YAML Path |
|------------|-----------|
| `config system global` | `vdom[0].root.global.system_global` |
| `config system admin` | `vdom[0].root.global.system_admin` |
| `config system interface` | `vdom[0].root.global.system_interface` |
| `config firewall policy` | `vdom[0].root.global.firewall_policy` |
| `config firewall address` | `vdom[0].root.global.firewall_address` |
| `config router static` | `vdom[0].root.global.router_static` |
| `config vpn ipsec phase1-interface` | `vdom[0].root.global.vpn_ipsec_phase1_interface` |

### CLI → Flat YAML Mapping

| CLI Command | YAML Path |
|------------|-----------|
| `config system global` | `system.global` |
| `config system admin` | `system.admin.entries` |
| `config system interface` | `system.interface.entries` |
| `config firewall policy` | `firewall.policy.entries` |
| `config router static` | `router.static.entries` |

## Data Type Conversions

### Booleans
```yaml
# CLI
set switch-controller enable

# YAML (7.2+)
switch-controller: enable  # String, not boolean

# Flat YAML
switch-controller: "enable"
```

### Numbers
```yaml
# CLI
set admintimeout 480

# YAML (7.2+)
admintimeout: 480  # Can be number or string

# Flat YAML
admintimeout: "480"  # Usually string
```

### IP Addresses with Netmask
```yaml
# CLI
set ip 192.168.1.1 255.255.255.0

# YAML
ip: "192.168.1.1 255.255.255.0"  # Single string

# Alternative (rarely used)
ip:
  address: "192.168.1.1"
  netmask: "255.255.255.0"
```

### Lists
```yaml
# CLI
set srcaddr "addr1" "addr2" "addr3"

# YAML (Correct)
srcaddr: ["addr1", "addr2", "addr3"]

# YAML (Also valid)
srcaddr:
  - "addr1"
  - "addr2"
  - "addr3"
```

## Analyzer Compatibility

Our `fortigate_config_analyzer.py` supports:

✅ **FortiGate 7.2+ YAML format** (with vdom structure)
✅ **Flat/CLI-parsed YAML format** (without vdom)
✅ **FortiGate CLI format** (original .conf files)
✅ **Mixed/hybrid formats**

The analyzer automatically detects the format and adjusts parsing accordingly.

## Best Practices

### For Configuration Exports

1. **Use CLI format when possible:**
   - More reliable
   - No conversion issues
   - Directly supported by FortiGate
   - Extension: `.conf`

2. **If using YAML (7.2+):**
   ```bash
   # Export command
   execute backup yaml-config tftp config.yaml 192.168.1.100
   ```
   - Validate with our diagnostic tool
   - Run through our fixer if needed

3. **For Ansible/Automation:**
   - Use Ansible FortiOS collection modules
   - Don't manually edit YAML exports
   - Use Jinja2 templates for generation

### For YAML Files

1. **Always validate:**
   ```bash
   python yaml_diagnostic.py your_config.yaml
   ```

2. **Fix common issues:**
   ```bash
   python fix_fortigate_yaml.py your_config.yaml
   ```

3. **Check structure:**
   - Look for `vdom:` at top level → FortiGate 7.2+ format
   - Look for `system:` at top level → Flat/CLI format

## Common Sections Reference

### System Sections
```yaml
system_global         # Global settings (hostname, timezone, etc.)
system_admin          # Administrator accounts
system_interface      # Network interfaces
system_dns            # DNS configuration
system_ntp            # NTP configuration
system_snmp           # SNMP settings
system_ha             # High availability
system_accprofile     # Access profiles
```

### Firewall Sections
```yaml
firewall_policy       # Security policies
firewall_address      # Address objects
firewall_addrgrp      # Address groups
firewall_service_custom   # Custom services
firewall_service_group    # Service groups
firewall_ippool       # IP pools
firewall_vip          # Virtual IPs
```

### VPN Sections
```yaml
vpn_ipsec_phase1_interface  # IPsec phase 1
vpn_ipsec_phase2_interface  # IPsec phase 2
vpn_ssl_settings            # SSL VPN settings
vpn_certificate_local       # Local certificates
```

### Router Sections
```yaml
router_static         # Static routes
router_policy         # Policy routes
router_bgp            # BGP configuration
router_ospf           # OSPF configuration
```

### Log Sections
```yaml
log_syslogd_setting   # Syslog configuration
log_fortianalyzer_setting  # FortiAnalyzer settings
log_disk_setting      # Local disk logging
```

## Troubleshooting YAML Files

### Symptom: Parser Error on Line X

**Diagnosis:**
```bash
python yaml_diagnostic.py your_file.yaml
```

**Common Causes:**
1. Multiple quoted values without list syntax
2. Escaped quotes (`\'`)
3. Tab characters instead of spaces
4. Inconsistent indentation
5. Missing colons

**Solution:**
```bash
python fix_fortigate_yaml.py your_file.yaml
```

### Symptom: Config Loads but No Findings

**Possible Causes:**
1. Wrong YAML structure expected by analyzer
2. Section names don't match expected format
3. Empty configuration

**Diagnosis:**
Check what the parser found:
```bash
python yaml_diagnostic.py your_file.yaml
# Look for "Top-level keys" output
```

### Symptom: Some Checks Don't Run

**Cause:** The analyzer looks for specific section names

**Check:**
- FortiGate 7.2+ format: Sections under `vdom[0].<vdom_name>.global.<section_name>`
- Flat format: Sections under `<section_name>`

## Version Differences

| Feature | CLI Format | Flat YAML | FortiGate 7.2+ YAML |
|---------|-----------|-----------|---------------------|
| File Extension | `.conf` | `.yaml` | `.conf.yaml` |
| Top-level | `config` | Section names | `vdom:` |
| Multi-value | Space-separated | Lists `[...]` | Lists `[...]` |
| Escaping | Quotes for spaces | YAML escaping | YAML escaping |
| Sections | Nested with `config` | Nested dicts | Under `global` |
| Editing | CLI or text editor | Text editor + validator | Limited - use CLI |

## References

- [FortiGate 7.2.0 YAML Backup/Restore](https://docs.fortinet.com/document/fortigate/7.2.0/new-features/787595/backing-up-and-restoring-configuration-files-in-yaml-format)
- [FortiGate Administration Guide](https://docs.fortinet.com/product/fortigate)
- [Ansible FortiOS Collection](https://docs.ansible.com/ansible/latest/collections/fortinet/fortios/index.html)

## Quick Reference

```bash
# Check if YAML is valid
python yaml_diagnostic.py config.yaml

# Fix YAML syntax issues
python fix_fortigate_yaml.py config.yaml

# Analyze configuration
python fortigate_config_analyzer.py config_fixed.yaml html

# If file is CLI format
python fortigate_config_analyzer.py config.conf html
```

**Remember:** The analyzer works with ALL three formats automatically! 🎉
