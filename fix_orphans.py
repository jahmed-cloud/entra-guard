#!/usr/bin/env python3
"""
Fix the orphaned dict fragment lines left by the previous patcher.
These look like:
    return {
        ...
    },
            "risk_description": "Could not ...",
            "remediation_steps": "Ensure ...",
            "estimated_effort": "Low"}

The }, at the end of the return dict followed by orphaned lines is the problem.
"""
import re, subprocess, sys, time

CONTAINER = "entra-guard-worker"
REMOTE    = "/app/app/tasks.py"
LOCAL     = "/tmp/tasks_current.py"
FIXED     = "/tmp/tasks_fixed2.py"

print("Pulling tasks.py from container...")
r = subprocess.run(["docker","cp",f"{CONTAINER}:{REMOTE}",LOCAL], capture_output=True, text=True)
if r.returncode != 0:
    print(f"ERROR: {r.stderr}"); sys.exit(1)

with open(LOCAL) as f:
    content = f.read()

print(f"Lines before fix: {content.count(chr(10))}")

# The pattern we need to remove:
# A return dict that ends with    },\n
# followed by indented "risk_description":... or "remediation_steps":... or "estimated_effort":...
# These are the leftover lines from the old error handler that weren't cleaned up

# Pattern: find lines that:
# 1. Are at deep indentation (16+ spaces)  
# 2. Start with "risk_description", "remediation_steps", or "estimated_effort"
# 3. Appear AFTER a line that ends with "},"  (the closing of a return dict)
# 4. Are NOT inside a try block's return (they're orphaned after the except return)

# More specific: the orphaned lines always come after a line matching:
#   "        },"  (8 spaces + },)
# and before either a blank line or a function definition

lines = content.split('\n')
new_lines = []
i = 0
removed = 0

while i < len(lines):
    line = lines[i]
    
    # Check if this line is an orphaned fragment
    # These have 16-24 spaces of indentation and contain specific keys
    stripped = line.lstrip()
    indent = len(line) - len(stripped)
    
    # Orphaned lines have indent >= 16 and match these patterns
    if indent >= 16 and (
        stripped.startswith('"risk_description"') or
        stripped.startswith('"remediation_steps"') or  
        stripped.startswith('"estimated_effort"')
    ):
        # Check if the previous non-empty line ended with "}," 
        # (meaning we're after a return statement, not inside one)
        prev_code_line = ""
        for j in range(len(new_lines)-1, -1, -1):
            if new_lines[j].strip():
                prev_code_line = new_lines[j].rstrip()
                break
        
        if prev_code_line.rstrip().endswith('},') or prev_code_line.rstrip().endswith('}'):
            # This is an orphaned line - check it's not inside a normal dict
            # Orphaned lines appear right after a closing }, of a return dict
            # The return dict's closing }  or }, is at indent 8
            prev_stripped = prev_code_line.lstrip()
            prev_indent = len(prev_code_line) - len(prev_stripped)
            
            if prev_stripped in ('},', '}') and prev_indent == 8:
                # This is definitely orphaned
                removed += 1
                # Also skip the closing } or } of this orphaned fragment if next
                # Check if this line ends the orphaned block
                if stripped.endswith('}') or stripped.endswith('"}'):
                    i += 1
                    continue
                i += 1
                continue
    
    new_lines.append(line)
    i += 1

content = '\n'.join(new_lines)
print(f"Removed {removed} orphaned lines")
print(f"Lines after fix: {content.count(chr(10))}")

# Now do a more targeted fix using regex
# Find the specific pattern and remove it
import re

# Pattern: "        }," followed by lines with 16+ space indent containing risk/remediation/effort
pattern = re.compile(
    r'(        \},\n)'           # the closing }, at 8 spaces
    r'(?:[ \t]{16,}"(?:risk_description|remediation_steps|estimated_effort)"[^\n]*\n)+',
    re.MULTILINE
)

def replacer(m):
    return m.group(1)  # keep the }, but remove the orphaned lines

fixed, count = pattern.subn(replacer, content)
print(f"Regex removed {count} orphaned blocks")

# Verify it compiles
import py_compile, tempfile, os
tmp = tempfile.mktemp(suffix='.py')
with open(tmp, 'w') as f:
    f.write(fixed)
    
try:
    py_compile.compile(tmp, doraise=True)
    print("✓ Syntax OK!")
    with open(FIXED, 'w') as f:
        f.write(fixed)
    ok = True
except py_compile.PyCompileError as e:
    print(f"✗ Syntax error: {e}")
    # Try to find where
    import subprocess as sp
    r2 = sp.run(['python3', '-m', 'py_compile', tmp], capture_output=True, text=True)
    print(r2.stderr)
    ok = False
finally:
    os.unlink(tmp)

if ok:
    print("\nDeploying...")
    for ct in ["entra-guard-worker","entra-guard-scheduler"]:
        r = subprocess.run(["docker","cp",FIXED,f"{ct}:{REMOTE}"], capture_output=True, text=True)
        print(f"  {'✓' if r.returncode==0 else '✗'} {ct}")
    
    r = subprocess.run(["docker","restart","entra-guard-worker","entra-guard-scheduler"], capture_output=True, text=True)
    print(f"Restarted: {r.stdout.strip()}")
    time.sleep(6)
    r = subprocess.run(["docker","logs","entra-guard-worker","--tail=5"], capture_output=True, text=True)
    print("\nWorker log:")
    print(r.stdout or r.stderr)
else:
    print("\nNOT deployed - fix the syntax error first")
    print("Saved fixed attempt to:", FIXED)
