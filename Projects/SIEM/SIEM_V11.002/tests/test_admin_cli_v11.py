import sys, tempfile
from pathlib import Path
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parents[1]/"src"))
from core import admin_cli

tmp = tempfile.mkdtemp()
db = Path(tmp)/"accounts.db"
STRONG="Tr0ub4dour-Quux-Vault-71!"

# Simulate create-admin
prompts = iter(["root"])
secrets = iter([STRONG, STRONG])
out=[]
rc = admin_cli.cmd_create_admin(db, prompt=lambda p: next(prompts),
    secret=lambda p: next(secrets), out=out.append)
print("create-admin rc:", rc)
print("output:", out[-1])
assert rc==0

# Try create-admin again -> must refuse (sealed)
prompts = iter(["root2"]); secrets = iter([STRONG, STRONG]); out2=[]
rc2 = admin_cli.cmd_create_admin(db, prompt=lambda p: next(prompts),
    secret=lambda p: next(secrets), out=out2.append)
print("second create-admin rc:", rc2, "->", out2[-1])
assert rc2==1

# Reset with correct confirmation phrase
STRONG2="Zephyr9-Marmot-Lantern-Q2#"
prompts = iter(["root", "RESET ADMIN PASSWORD"])
secrets = iter([STRONG2, STRONG2]); out3=[]
rc3 = admin_cli.cmd_reset_admin_password(db, prompt=lambda p: next(prompts),
    secret=lambda p: next(secrets), out=out3.append)
print("reset rc:", rc3, "->", out3[-1])
assert rc3==0

# Reset with wrong confirmation phrase -> refuse
prompts = iter(["root", "wrong phrase"])
secrets = iter([STRONG, STRONG]); out4=[]
rc4 = admin_cli.cmd_reset_admin_password(db, prompt=lambda p: next(prompts),
    secret=lambda p: next(secrets), out=out4.append)
print("reset wrong-confirm rc:", rc4, "->", out4[-1])
assert rc4==1

print("\n  Results: 4 passed, 0 failed")
