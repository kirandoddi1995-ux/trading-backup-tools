"""Synthetic pure capacity assessment; no real DB, capture, credentials or files written."""
from __future__ import annotations

import ast
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest

# Load ONLY this sibling stdlib module, without application/conftest imports.
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('backup_capacity_assessment', ROOT / 'backup_capacity_assessment.py')
capacity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capacity)
NOW = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)


def sample(size=345_000_000, at=NOW, *, complete=True):
    relations = [dict(schema=schema, name=name, present=True, kind='r', oid=100+i,
        relfilenode=200+i, size_complete=True, total_bytes=8192, table_bytes=8192,
        indexes_bytes=0) for i, (schema, name) in enumerate(capacity.TARGETS)]
    return dict(format=capacity.FORMAT, metric=capacity.METRIC,
        current_metric=capacity.CURRENT_METRIC, source_id='synthetic-project-a',
        started_at=at.isoformat(), finished_at=at.isoformat(), server_major=17,
        database_name='postgres', database_oid=5, database_count=2,
        databases=[dict(oid=5, name='postgres', bytes=size-1_000_000 if complete else None),
                   dict(oid=1, name='template1', bytes=1_000_000 if complete else None)],
        complete=complete, current_database_bytes=size-1_000_000,
        cluster_database_bytes=size if complete else None, relations=relations,
        business_rows_read=0)


def history():
    return [sample(300_000_000, NOW-timedelta(hours=24)),
            sample(306_000_000, NOW-timedelta(hours=12)), sample(318_000_000)]


class CapacityTests(unittest.TestCase):
    def assess(self, samples, now=NOW):
        return capacity.assess(samples, now=now)

    def test_single_point_has_capacity_but_never_forecast(self):
        facts = sample()
        original = deepcopy(facts)
        result = self.assess([facts])
        self.assertEqual(result['status'], 'OBSERVED')
        self.assertEqual(result['nominal_headroom_bytes'], 155_000_000)
        self.assertEqual(result['trend_status'], 'INSUFFICIENT_SAMPLES')
        self.assertIsNone(result['diagnostic_seconds_to_floor'])
        self.assertIsNone(result['max_positive_observed_bytes_per_day_ceiling'])
        self.assertEqual(facts, original)
        for field in ('forecast_is_guaranteed', 'authenticated_inputs_verified',
                      'physical_disk_free_verified', 'backup_verified',
                      'write_admission_authorized', 'approval_authority'):
            self.assertIs(result[field], False)
        for field in ('notifications_sent', 'writes', 'network_calls', 'credential_reads'):
            self.assertEqual(result[field], 0)

    def test_threshold_boundaries_are_decimal_bytes(self):
        for headroom, expected in ((64_000_001, 'OBSERVED'), (64_000_000, 'WARNING'),
                (63_999_999, 'WARNING'), (24_000_001, 'WARNING'),
                (24_000_000, 'WARNING'), (23_999_999, 'FLOOR_BREACHED'),
                (0, 'FLOOR_BREACHED'), (-1, 'FLOOR_BREACHED')):
            with self.subTest(headroom=headroom):
                result = self.assess([sample(capacity.QUOTA_BYTES-headroom)])
                self.assertEqual(result['status'], expected)
                self.assertEqual(result['nominal_headroom_bytes'], headroom)
                self.assertIsNone(result['diagnostic_seconds_to_floor'])

    def test_three_complete_samples_use_maximum_positive_interval_rate(self):
        result = self.assess(history())
        self.assertEqual(result['trend_status'], 'POSITIVE_OBSERVED_DIAGNOSTIC')
        self.assertEqual(result['observed_span_seconds'], 86400)
        self.assertEqual(result['last_interval_microseconds'], 43_200_000_000)
        self.assertEqual(result['max_positive_observed_bytes_per_day_ceiling'], 24_000_000)
        self.assertEqual(result['observed_delta_bytes'], 12_000_000)
        self.assertEqual(result['diagnostic_seconds_to_floor'], 568800)
        self.assertFalse(result['forecast_is_guaranteed'])

    def test_two_points_or_less_than_one_day_has_no_forecast(self):
        cases = [history()[::2], [sample(300_000_000, NOW-timedelta(hours=23)),
            sample(301_000_000, NOW-timedelta(hours=12)), sample(302_000_000)]]
        for samples in cases:
            result = self.assess(samples)
            self.assertIsNone(result['diagnostic_seconds_to_floor'])
            self.assertIsNone(result['max_positive_observed_bytes_per_day_ceiling'])

    def test_flat_and_negative_do_not_imply_infinite_runway(self):
        for sizes in ((345_000_000,)*3, (347_000_000,346_000_000,345_000_000)):
            samples = [sample(size, NOW-timedelta(hours=24-12*i)) for i,size in enumerate(sizes)]
            result = self.assess(samples)
            self.assertEqual(result['trend_status'], 'NO_POSITIVE_OBSERVED_GROWTH')
            self.assertIsNone(result['diagnostic_seconds_to_floor'])
            self.assertIsNone(result['max_positive_observed_bytes_per_day_ceiling'])

    def test_positive_burst_is_not_erased_by_later_shrinkage(self):
        samples = [sample(300_000_000,NOW-timedelta(hours=24)),
                   sample(312_000_000,NOW-timedelta(hours=12)), sample(299_000_000)]
        result = self.assess(samples)
        self.assertEqual(result['max_positive_observed_bytes_per_day_ceiling'],24_000_000)
        self.assertEqual(result['observed_delta_bytes'],-13_000_000)

    def test_exact_freshness_boundary_and_aware_timezone(self):
        self.assertEqual(self.assess([sample(at=NOW-timedelta(hours=24))])['status'],'OBSERVED')
        alternate = NOW.astimezone(timezone(timedelta(hours=5,minutes=30)))
        self.assertEqual(self.assess([sample(at=alternate)])['status'],'OBSERVED')

    def test_stale_future_overlapping_and_out_of_order_are_unknown(self):
        cases = [[sample(at=NOW-timedelta(hours=24,microseconds=1))],
                 [sample(at=NOW+timedelta(microseconds=1))],
                 [sample(),sample()], list(reversed(history()))]
        overlapping = history()
        overlapping[1]['started_at'] = (NOW-timedelta(hours=24,seconds=1)).isoformat()
        overlapping[1]['finished_at'] = (NOW-timedelta(hours=24)+timedelta(seconds=1)).isoformat()
        cases.append(overlapping)
        for samples in cases:
            with self.subTest(samples=samples):
                result=self.assess(samples)
                self.assertEqual(result['status'],'UNKNOWN')
                self.assertIsNone(result['diagnostic_seconds_to_floor'])

    def test_latest_window_start_defines_freshness(self):
        facts=sample(at=NOW-timedelta(hours=24,seconds=1))
        facts['finished_at']=(NOW-timedelta(hours=24)+timedelta(seconds=1)).isoformat()
        self.assertEqual(self.assess([facts])['reasons'],['CURRENT_SAMPLE_STALE'])

    def test_partial_current_or_history_cannot_forecast(self):
        self.assertEqual(self.assess([sample(complete=False)])['status'],'UNKNOWN')
        samples=history()
        samples[0]=sample(300_000_000,NOW-timedelta(hours=24),complete=False)
        result=self.assess(samples)
        self.assertEqual(result['reasons'],['HISTORY_INCOMPLETE'])
        self.assertIsNone(result['diagnostic_seconds_to_floor'])
        missing_label=sample(complete=False)
        missing_label['source_id']=None
        self.assertEqual(self.assess([missing_label])['status'],'UNKNOWN')

    def test_invalid_metric_sizes_counts_shapes_and_types_block(self):
        mutations = [('metric','current_database'), ('current_metric','cluster'),
            ('format','old-format'),('cluster_database_bytes',True),
            ('current_database_bytes',False),('database_count',True),('complete',1),
            ('cluster_database_bytes',1.5),('cluster_database_bytes',-1),
            ('cluster_database_bytes',2**63),('business_rows_read',True),
            ('source_id','https://private.invalid'),('source_id',None),('server_major',True)]
        for field,value in mutations:
            facts=sample()
            facts[field]=value
            with self.subTest(field=field,value=value):
                self.assertEqual(self.assess([facts])['status'],'UNKNOWN')
        for mutation in ('extra','missing','bad_sum','missing_db','duplicate_db','too_many'):
            facts=sample()
            if mutation=='extra': facts['extra']=0
            elif mutation=='missing': del facts['relations']
            elif mutation=='bad_sum': facts['databases'][0]['bytes']+=1
            elif mutation=='missing_db': facts['databases'][0]['oid']=10
            elif mutation=='duplicate_db': facts['databases'][1]=deepcopy(facts['databases'][0])
            else: facts['database_count']=65
            self.assertEqual(self.assess([facts])['status'],'UNKNOWN')

    def test_source_and_inventory_mismatch_no_cross_cluster_growth(self):
        for field,value in (('source_id','synthetic-project-b'),('database_oid',6),
                            ('database_name','different_database')):
            samples=history()
            samples[0][field]=value
            if field=='database_oid': samples[0]['databases'][0]['oid']=value
            if field=='database_name': samples[0]['databases'][0]['name']=value
            self.assertEqual(self.assess(samples)['reasons'],['SAMPLE_SOURCE_OR_INVENTORY_MISMATCH'])
        samples=history()
        samples[0]['databases'][1]['oid']=42
        self.assertEqual(self.assess(samples)['status'],'UNKNOWN')

    def test_database_overflow_partial_shape_is_explicit(self):
        facts=sample(complete=False)
        facts.update(database_count=65,databases=None)
        capacity.validate_sample(facts)
        self.assertEqual(self.assess([facts])['status'],'UNKNOWN')

    def test_relation_pair_growth_is_observed_not_global_attribution(self):
        samples=history()[1:]
        samples[1]['relations'][0]['total_bytes']+=12
        result=self.assess(samples)
        self.assertEqual(len(result['relation_growth']),8)
        row=result['relation_growth'][0]
        self.assertTrue(row['comparable'])
        self.assertEqual(row['delta_bytes'],12)
        self.assertEqual(row['observed_bytes_per_day_ceiling'],24)
        self.assertIsNone(result['diagnostic_seconds_to_floor'])

    def test_missing_partition_and_recreated_relations_are_not_zero_growth(self):
        for kind in ('missing','partition','recreated'):
            samples=history()
            row=samples[-1]['relations'][0]
            if kind=='recreated': row['relfilenode']+=1
            else:
                row.update(size_complete=False,total_bytes=None,table_bytes=None,indexes_bytes=None)
                if kind=='missing': row.update(present=False,kind=None,oid=None,relfilenode=None)
                else: row.update(kind='p',relfilenode=0)
            result=self.assess(samples)
            self.assertEqual(result['trend_status'],'POSITIVE_OBSERVED_DIAGNOSTIC')
            self.assertFalse(result['relation_growth'][0]['comparable'])
            self.assertIsNone(result['relation_growth'][0]['delta_bytes'])

    def test_duplicate_or_boolean_relation_metadata_rejected(self):
        for kind in ('duplicate','size','present'):
            facts=sample()
            if kind=='duplicate': facts['relations'][1]=deepcopy(facts['relations'][0])
            elif kind=='size': facts['relations'][0]['total_bytes']=True
            else: facts['relations'][0]['present']=1
            self.assertEqual(self.assess([facts])['status'],'UNKNOWN')

    def test_invalid_inventory_clock_or_unbounded_window(self):
        for samples in (None,{},[],[sample()]*(capacity.MAX_SAMPLES+1)):
            self.assertEqual(self.assess(samples)['status'],'UNKNOWN')
        self.assertEqual(self.assess([sample()],NOW.replace(tzinfo=None))['reasons'],['CLOCK_INVALID'])
        for end in (NOW+timedelta(seconds=61),NOW-timedelta(microseconds=1)):
            facts=sample()
            facts['finished_at']=end.isoformat()
            self.assertEqual(self.assess([facts])['reasons'],['SAMPLE_WINDOW_INVALID'])

    def test_unknown_history_retains_known_current_floor_breach(self):
        samples=[sample(complete=False,at=NOW-timedelta(hours=24)),sample(476_000_001)]
        result=self.assess(samples)
        self.assertEqual(result['status'],'UNKNOWN')
        self.assertEqual(result['capacity_status'],'FLOOR_BREACHED')
        self.assertEqual(result['nominal_headroom_bytes'],23_999_999)
        self.assertIsNone(result['diagnostic_seconds_to_floor'])

    def test_exact_fractional_rate_rounding_and_floor_forecast(self):
        samples=[sample(475_999_996,NOW-timedelta(hours=24)),
                 sample(475_999_999,NOW-timedelta(hours=12)),sample(476_000_001)]
        result=self.assess(samples)
        self.assertEqual(result['capacity_status'],'FLOOR_BREACHED')
        self.assertEqual(result['max_positive_observed_bytes_per_day_ceiling'],6)
        self.assertEqual(result['diagnostic_seconds_to_floor'],0)

    def test_no_discovery_io_or_application_imports(self):
        tree=ast.parse((ROOT/'backup_capacity_assessment.py').read_text())
        imports=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import): imports.extend(a.name for a in node.names)
            if isinstance(node,ast.ImportFrom): imports.append(node.module)
        self.assertEqual(set(imports),{'__future__','datetime','fractions','re','typing'})
        calls={n.func.id for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)}
        self.assertTrue({'open','eval','exec','__import__','print'}.isdisjoint(calls))

    def test_sql_catalog_only_bounded_json_and_null_partial_contract(self):
        raw=(ROOT/'sql/backup_capacity_sample_read_only.sql').read_text()
        sql=re.sub(r'--[^\n]*','',raw).strip()
        self.assertTrue(sql.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'))
        self.assertTrue(sql.endswith('ROLLBACK;'))
        for required in ("statement_timeout = '10s'","lock_timeout = '2s'",
            'BETWEEN 1 AND 64','bool_and(visible)',"pg_has_role('pg_read_all_stats', 'USAGE')",
            'has_database_privilege', 'CASE WHEN (SELECT complete FROM coverage) THEN pg_database_size(oid)',
            'sum(bytes)', 'jsonb_build_object', "'backup-capacity-sample-v1'", capacity.METRIC,
            capacity.CURRENT_METRIC, "'business_rows_read',0", 'ELSE NULL END'):
            self.assertIn(required,sql)
        for forbidden in ('pg_authid','rolpassword','pg_get_functiondef','pg_read_file',
                          'pg_ls_dir','pg_ls_waldir','quant_app.','equity_research.'):
            self.assertNotIn(forbidden,sql)
        self.assertIsNone(re.search(r'\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|COPY|CALL|DO|GRANT|REVOKE|COMMIT)\b',sql,re.I))
        self.assertEqual(sql.count("('quant_app',"),7)
        self.assertEqual(sql.count("('equity_research',"),1)
        self.assertIn("CASE WHEN c.relkind='r' THEN pg_total_relation_size",sql)
        self.assertIn('LEFT JOIN pg_class',sql)
        for key in capacity.SAMPLE_KEYS:
            self.assertIn("'"+key+"'",sql)

    def test_exact_sql_json_in_existing_in_memory_pglite(self):
        node=shutil.which('node')
        module=Path(os.environ.get('EQUITY_TEST_PGLITE_MODULE',
            str(ROOT/'tests/sql-harness/node_modules/@electric-sql/pglite'))).resolve()
        if node is None or not (module/'package.json').is_file():
            self.skipTest('Existing optional PGlite unavailable; no install or hosted query')
        self.assertEqual(json.loads((module/'package.json').read_text())['version'],'0.3.14')
        script=r'''
const fs=require('node:fs');
const {PGlite}=require(process.argv[1]);
(async()=>{
 const db=new PGlite();
 try {
  await db.exec('CREATE SCHEMA quant_app; CREATE TABLE quant_app.mf_nav(id integer);');
  const sql=fs.readFileSync(process.argv[2],'utf8');
  const capture=async(recipe=sql)=>{
   const results=await db.exec(recipe);
   return results.flatMap(x=>x.rows).find(x=>x.capacity_sample).capacity_sample;
  };
  const unlabelled=await capture();
  await db.exec("SET backup_capacity.source_id='synthetic-project-a';");
  const complete=await capture();
  // PGlite catalog privilege mutation is not native acceptance. Force only the
  // visibility predicate to exercise the null-size branch, not an actual role.
  const invisible=await capture(sql.replace(/has_database_privilege\(d\.oid, 'CONNECT'\) OR\s+pg_has_role\('pg_read_all_stats', 'USAGE'\)/,'false'));
  await db.exec('CREATE TABLE quant_app.market_quotes(id integer) PARTITION BY RANGE(id); CREATE TABLE quant_app.synthetic_child PARTITION OF quant_app.market_quotes FOR VALUES FROM(0) TO(10);');
  const partition=await capture();
  process.stdout.write(JSON.stringify({unlabelled,complete,invisible,partition}));
 } finally { await db.close(); }
})().catch(()=>{process.stdout.write(JSON.stringify({error:'SYNTHETIC_SQL_FAILED'}));process.exitCode=1;});
'''
        env={k:v for k,v in os.environ.items() if k.upper() in ('PATH','SYSTEMROOT','WINDIR','TMP','TEMP')}
        result=subprocess.run([node,'-e',script,str(module),str(ROOT/'sql/backup_capacity_sample_read_only.sql')],
            env=env,capture_output=True,text=True,timeout=45,check=False)
        self.assertEqual(result.returncode,0,'Synthetic SQL recipe failed')
        self.assertLess(len(result.stdout),65536)
        values=json.loads(result.stdout)
        for value in values.values():
            capacity.validate_sample(value)
        self.assertTrue(values['complete']['complete'])
        self.assertEqual(type(values['complete']['database_oid']),int)
        self.assertFalse(values['unlabelled']['complete'])
        self.assertFalse(values['invisible']['complete'])
        self.assertIsNone(values['invisible']['cluster_database_bytes'])
        self.assertTrue(all(row['bytes'] is None for row in values['invisible']['databases']))
        self.assertEqual(len(values['complete']['relations']),8)
        partition=next(row for row in values['partition']['relations'] if row['name']=='market_quotes')
        self.assertEqual(partition['kind'],'p')
        self.assertFalse(partition['size_complete'])
        self.assertIsNone(partition['total_bytes'])
        now=datetime.fromisoformat(values['complete']['finished_at'])
        self.assertEqual(self.assess([values['complete']],now)['status'],'OBSERVED')


if __name__=='__main__':
    unittest.main()
