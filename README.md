# FortiGate Configuration Analyzer - Quick Start Guide

## What This Tool Does
Analyzes FortiGate firewall configurations offline to identify:
- Security vulnerabilities
- Misconfigurations
- Best practice violations
- Compliance issues

## Quick Start (3 Steps)

### 1. Install Python Dependencies
```bash
pip install pyyaml
```

### 2. Run the Analyzer
```before running the script, run chmod to make the pythong file executable
chmond +x fortigate_config_analyzer.py
```
```bash
python fortigate_config_analyzer.py your_config_file.conf
```

### 3. Review the Report
The tool will generate `fortigate_analysis_report.txt` with:
- Security score (0-100)
- Categorized findings by severity
- Specific recommendations for each issue

## Common Use Cases

### Generate Different Report Formats
```bash
# Text report (default)
python fortigate_config_analyzer.py config.conf

# HTML report (visual, color-coded)
python fortigate_config_analyzer.py config.conf html

# JSON report (for automation/CI/CD)
python fortigate_config_analyzer.py config.conf json
```

### Example with Sample Config
Try it immediately with the included sample:
```bash
python fortigate_config_analyzer.py sample_config.txt html
```
Then open `fortigate_analysis_report.html` in your browser.

## Understanding Your Score

| Score Range | Status | Action Required |
|------------|--------|-----------------|
| 90-100 | Excellent ✅ | Maintain current security posture |
| 80-89 | Good 👍 | Address minor findings |
| 70-79 | Fair ⚠️ | Several improvements needed |
| 60-69 | Poor ⛔ | Significant security gaps |
| 0-59 | Critical 🚨 | Immediate remediation required |

## Finding Severity Guide

- **CRITICAL** (Red): Immediate security risk - fix now
- **HIGH** (Orange): Significant concern - fix within days
- **MEDIUM** (Yellow): Important improvement - fix within weeks
- **LOW** (Blue): Minor enhancement - address as time permits
- **INFO** (Gray): Informational - no action required

## Most Common Issues Found

1. Default admin credentials
2. Management access from WAN
3. Missing two-factor authentication
4. Overly permissive firewall rules
5. Weak VPN encryption
6. Missing security profiles
7. No traffic logging
8. Default SNMP community strings

## Where to Get Your Config File

### From FortiGate Web GUI:
1. Login to FortiGate
2. Go to **System > Configuration > Backup**
3. Select "Configuration" (not "Firmware")
4. Save the file

### From FortiGate CLI:
```bash
# Via SSH
show full-configuration

# Or export to file
execute backup config management-station <filename>
```

## What Gets Checked

### Security Areas (60+ checks):
- ✅ Administrative access controls
- ✅ Firewall policy configuration
- ✅ Interface security
- ✅ VPN encryption strength
- ✅ System hardening
- ✅ Logging and monitoring
- ✅ SNMP security
- ✅ High availability
- ✅ Network services (DNS, NTP)
- ✅ UTM profiles

## Automation & CI/CD Integration

### Check if config meets security standards:
```bash
python fortigate_config_analyzer.py config.conf json > results.json

# Parse JSON and check score
SCORE=$(python -c "import json; print(json.load(open('results.json'))['security_score'])")

if [ $SCORE -lt 80 ]; then
    echo "Security score too low: $SCORE"
    exit 1
fi
```

### In Python Scripts:
```python
from fortigate_config_analyzer import FortiGateConfigAnalyzer

analyzer = FortiGateConfigAnalyzer("config.conf")
analyzer.load_config()
result = analyzer.analyze()

if result.score < 80:
    print(f"FAIL: Score {result.score}/100")
    for finding in result.findings:
        if finding.severity.value in ['CRITICAL', 'HIGH']:
            print(f"- {finding.title}")
    exit(1)
```

## Interpreting Results

### Example Finding:
```
[HIGH-2] Two-Factor Authentication Not Enabled for 'admin'
Category: Administrative Access
Location: config system admin -> edit admin

Description:
  Administrator 'admin' does not have 2FA enabled.

Recommendation:
  Enable two-factor authentication (TOTP, RADIUS, or LDAP with 2FA)
  for all admin accounts.
```

**What this means:**
- **Severity**: HIGH - Important to fix soon
- **Location**: Shows exact config path
- **Fix**: The recommendation tells you exactly what to do

### How to Fix:
```bash
# Login to FortiGate CLI
config system admin
    edit admin
        set two-factor fortitoken
    end
```

## Tips for Best Results

1. **Use latest config**: Export fresh config before analysis
2. **Review all findings**: Even LOW severity items improve security
3. **Prioritize CRITICAL/HIGH**: Fix these first
4. **Document changes**: Track what you've fixed
5. **Re-scan after fixes**: Verify improvements
6. **Regular audits**: Run monthly or after changes

## Getting Help

### Configuration Not Loading?
- Ensure file is UTF-8 encoded
- Check for special characters
- Verify it's a valid FortiGate config

### Unexpected Results?
- Review the finding location
- Check if custom configurations are present
- Some findings may be environment-specific

### False Positives?
- Review the recommendation context
- Some alerts may not apply to your setup
- Document exceptions for compliance

## File Structure

```
fortigate_config_analyzer/
├── fortigate_config_analyzer.py  # Main tool
├── README.md                     # Full documentation
├── QUICKSTART.md                 # This file
├── sample_config.txt             # Example config
└── fortigate_analysis_report.*   # Generated reports
```

## Next Steps

1. ✅ Run the tool on your FortiGate config
2. ✅ Review CRITICAL and HIGH findings
3. ✅ Create remediation plan
4. ✅ Apply fixes to production
5. ✅ Re-scan to verify improvements
6. ✅ Schedule regular audits

## Support Resources

- Full documentation: See README.md
- Sample config: sample_config.txt
- Example reports: fortigate_analysis_report.*
- Fortinet docs: https://docs.fortinet.com

---

**Ready to start?**
```bash
python fortigate_config_analyzer.py your_config.conf html
```

Your security audit will be ready in seconds!
