"""NeoShield scanning service.

The Python service owns scanning and integrations. It never owns the database
schema: Drizzle (in the web app) is the only migration authority.
"""

__version__ = "0.1.0"
