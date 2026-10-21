-- Owner-run metadata only. No business rows, function bodies or credentials.
-- Before using this recipe, the OWNER binds a nonsecret project label in the
-- session's backup_capacity.source_id setting (1-64 letters/digits/_.-).
-- No setting is discovered or changed here; a missing/invalid label means
-- complete=false. Labels are supplied provenance, NOT authenticated identity.
-- All-database pg_database_size sum matches collector_storage_preflight.SQL.
-- Physical sizes remain live observations, not an atomic MVCC size snapshot.
-- Capture polling is local: this query does not attribute polling to DB writes.
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '10s';
SET LOCAL lock_timeout = '2s';
SET LOCAL search_path = pg_catalog;
SET LOCAL timezone = 'UTC';

WITH started AS MATERIALIZED (
  SELECT clock_timestamp() AS at,
    current_setting('backup_capacity.source_id', true) AS supplied_source
), inventory AS MATERIALIZED (
  SELECT d.oid, d.datname,
    has_database_privilege(d.oid, 'CONNECT') OR
      pg_has_role('pg_read_all_stats', 'USAGE') AS visible
  FROM pg_database d CROSS JOIN started
), coverage AS MATERIALIZED (
  SELECT count(*) AS database_count,
    count(*) BETWEEN 1 AND 64 AND bool_and(visible) AND
    coalesce((SELECT supplied_source ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'
      FROM started), false) AS complete
  FROM inventory
), sizes AS MATERIALIZED (
  SELECT oid, datname,
    CASE WHEN (SELECT complete FROM coverage) THEN pg_database_size(oid)
         ELSE NULL END AS bytes
  FROM inventory
  WHERE (SELECT database_count <= 64 FROM coverage)
), targets(schema_name, relation_name) AS (VALUES
  ('quant_app', 'mf_nav'), ('quant_app', 'market_quotes'),
  ('quant_app', 'universe_membership'), ('quant_app', 'universe_membership_versions'),
  ('quant_app', 'scanner_observations'), ('equity_research', 'outcomes'),
  ('quant_app', 'evidence_ledger_events'), ('quant_app', 'market_daily_volumes')
), relations AS MATERIALIZED (
  SELECT t.schema_name, t.relation_name, c.oid, c.relkind, c.relfilenode,
    -- Partition-parent storage excludes children: mark attribution unsupported.
    CASE WHEN c.relkind='r' THEN pg_total_relation_size(c.oid) ELSE NULL END AS total_bytes,
    CASE WHEN c.relkind='r' THEN pg_table_size(c.oid) ELSE NULL END AS table_bytes,
    CASE WHEN c.relkind='r' THEN pg_indexes_size(c.oid) ELSE NULL END AS indexes_bytes
  FROM targets t LEFT JOIN pg_namespace n ON n.nspname=t.schema_name
  LEFT JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=t.relation_name
    AND c.relkind IN ('r','p')
), payload AS MATERIALIZED (
  SELECT jsonb_build_object(
    'format','backup-capacity-sample-v1',
    'metric','pg_database_size:all_databases:v1',
    'current_metric','pg_database_size:current_database:v1',
    'source_id',CASE WHEN s.supplied_source ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'
                     THEN s.supplied_source ELSE NULL END,
    'started_at',s.at,
    'server_major',current_setting('server_version_num')::int/10000,
    'database_name',current_database(),
    'database_oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
    'database_count',v.database_count,
    'databases',CASE WHEN v.database_count<=64 THEN
      (SELECT jsonb_agg(jsonb_build_object('oid',oid::bigint,'name',datname,'bytes',bytes)
         ORDER BY oid) FROM sizes) ELSE NULL END,
    'complete',v.complete,
    'current_database_bytes',CASE WHEN v.complete THEN
      (SELECT bytes FROM sizes WHERE datname=current_database())
      ELSE pg_database_size(current_database()) END,
    'cluster_database_bytes',CASE WHEN v.complete THEN
      (SELECT sum(bytes) FROM sizes) ELSE NULL END,
    'relations',(SELECT jsonb_agg(jsonb_build_object(
      'schema',schema_name,'name',relation_name,'present',oid IS NOT NULL,
      'kind',relkind,'oid',oid::bigint,'relfilenode',relfilenode::bigint,
      'size_complete',coalesce(relkind='r',false),
      'total_bytes',total_bytes,'table_bytes',table_bytes,'indexes_bytes',indexes_bytes)
      ORDER BY schema_name,relation_name) FROM relations),
    'business_rows_read',0) AS value
  FROM started s CROSS JOIN coverage v
)
SELECT value || jsonb_build_object('finished_at',clock_timestamp()) AS capacity_sample
FROM payload;
ROLLBACK;
