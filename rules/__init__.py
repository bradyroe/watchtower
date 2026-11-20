"""Detection rules. Each rule is a small dict; see builtin.py. Add a module here and list it in ALL."""
from rules.builtin import RULES as BUILTIN

ALL = list(BUILTIN)
BY_ID = {r["id"]: r for r in ALL}
