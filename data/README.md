# E-Rakshak Data & Schema Storage

This directory manages database schemas, index mappings, seed data, and persistent fixtures used across the E-Rakshak platform.

---

## Directory Organization

```
data/
├── schemas/
│   ├── postgres/
│   │   └── schema.sql                 # Canonical PostgreSQL relational database schema
│   └── elasticsearch/
│       └── case_index_mapping.json    # Elasticsearch case and IoC search index mapping
└── fixtures/                          # Test fixtures and baseline evaluation datasets
```

---

## Persistent Stores

1. **PostgreSQL Relational Store**:
   - Manages sample submissions, dynamic analysis task queues, case metadata, user accounts, and audit log histories.
   - Initialized using [`data/schemas/postgres/schema.sql`](schemas/postgres/schema.sql).
   - In development and CI environments, SQLite or in-memory Postgres can be used for zero-dependency execution.

2. **Elasticsearch / Opensearch Search Index**:
   - Indexes cases, extracted strings, network indicators (IPs, domains, URLs), and MITRE technique annotations for fast full-text search and correlation.
   - Configured via [`data/schemas/elasticsearch/case_index_mapping.json`](schemas/elasticsearch/case_index_mapping.json).

---

## Schema Initialization

To apply the database schema against a running PostgreSQL instance:
```bash
psql -h localhost -U postgres -d erakshak -f data/schemas/postgres/schema.sql
```
To verify database connectivity:
```bash
python scripts/maintenance/verify_neon.py
```
