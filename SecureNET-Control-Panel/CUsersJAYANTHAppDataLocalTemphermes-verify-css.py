import sys

path = r"C:\Users\JAYANTH\OneDrive\Desktop\SecureNET-Toolkit--main\SecureNET-Toolkit--main\SecureNET-Control-Panel\static\css\components.css"

with open(path, 'r') as f:
    content = f.read()

errors = []

# 1. Check all required component sections exist
sections = [
    "TOOL CARDS",
    "SEVERITY BADGES",
    "STATUS INDICATORS",
    "BUTTONS",
    "INPUT FIELDS",
    "TOGGLE SWITCHES",
    "ALERT CARDS",
    "TABLES",
    "MODALS",
    "TOAST NOTIFICATIONS",
    "NAVIGATION TABS",
    "LOADING SPINNERS",
    "TERMINAL-STYLE OUTPUT BOXES",
]

for section in sections:
    if section not in content:
        errors.append(f"Missing section: {section}")
    else:
        print(f"  OK Section found: {section}")

# 2. Check CSS syntax basics - balanced braces
open_braces = content.count('{')
close_braces = content.count('}')
if open_braces != close_braces:
    errors.append(f"Unbalanced braces: {open_braces} open vs {close_braces} close")
else:
    print(f"  OK Braces balanced: {open_braces} pairs")

# 3. Check for common CSS properties
checks = {
    "grid-template-columns": "Tool card grid",
    "@keyframes pulse-dot": "Status dot pulse animation",
    "@keyframes spin": "Spinner animation",
    "@keyframes toastIn": "Toast animation",
    "@keyframes shimmer": "Skeleton shimmer",
    "@keyframes blink": "Terminal cursor blink",
    "--color-primary": "CSS custom properties",
    ".btn": "Button classes",
    ".severity-badge": "Severity badges",
    ".toggle": "Toggle switches",
    ".modal-overlay": "Modal overlay",
    ".toast-container": "Toast container",
    ".tabs": "Navigation tabs",
    ".spinner": "Spinners",
    ".terminal": "Terminal output",
    ".data-table": "Data tables",
    ".alert-card": "Alert cards",
}

for pattern, desc in checks.items():
    if pattern in content:
        print(f"  OK Contains: {desc}")
    else:
        errors.append(f"Missing pattern: {desc} ({pattern})")

# 4. Check severity badge variants
for sev in ["critical", "high", "medium", "low", "good"]:
    if f"severity-badge--{sev}" in content:
        print(f"  OK Severity badge: {sev}")
    else:
        errors.append(f"Missing severity badge: {sev}")

# 5. Check button variants
for variant in ["primary", "secondary", "ghost", "danger"]:
    if f"btn--{variant}" in content:
        print(f"  OK Button variant: {variant}")
    else:
        errors.append(f"Missing button variant: {variant}")

# 6. Check status dot states
for state in ["running", "stopped", "starting", "disabled"]:
    if f"status-dot--{state}" in content:
        print(f"  OK Status dot: {state}")
    else:
        errors.append(f"Missing status dot: {state}")

# 7. Check file size is reasonable
if len(content) < 1000:
    errors.append("File suspiciously small")
elif len(content) > 100000:
    errors.append("File suspiciously large")
else:
    print(f"  OK File size reasonable: {len(content)} bytes")

print(f"\n{'='*50}")
if errors:
    print(f"VERIFICATION FAILED - {len(errors)} error(s):")
    for e in errors:
        print(f"  ERR: {e}")
    sys.exit(1)
else:
    print("VERIFICATION PASSED - all checks green")
    sys.exit(0)
