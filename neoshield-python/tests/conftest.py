"""Keep tests independent of the developer's local `.env`.

Settings read the `NEOSHIELD_` prefix from both the process environment and
`.env`. Empty environment values win over the file, so the health test sees a
worker with no token or database even on a configured machine.
"""

import os

os.environ["NEOSHIELD_WORKER_TOKEN"] = ""
os.environ["NEOSHIELD_BOOTSTRAP_TOKEN"] = ""
os.environ["NEOSHIELD_DATABASE_URL"] = ""
