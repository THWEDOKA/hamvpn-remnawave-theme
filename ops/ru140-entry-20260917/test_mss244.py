"""Offline scope, ownership and no-write checks; never changes host firewall."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import mss244 as m


def complete_fixture():
    entries = [{'table': {'family': 'ip', 'name': m.TABLE}}]
    for name, hook in [('incoming', 'input'), ('outgoing', 'output')]:
        entries.append({'chain': {'name': name, 'hook': hook, 'prio': -150}})
        entries.append({'rule': {'chain': name, 'expr': [{'mangle': {'value': 1200}}]}})
    return {'nftables': entries}


class MSS244Tests(unittest.TestCase):
    def test_scope_both_directions_and_never_increase_mss(self):
        self.assertIn('create table ip ham_entry244_mss', m.RULES)
        for interface, address, port, hook in [('iifname', 'daddr', 'dport', 'input'), ('oifname', 'saddr', 'sport', 'output')]:
            self.assertIn(f'{interface} "enp0s3" ip {address} 193.233.222.244 tcp {port} 443', m.RULES)
            self.assertIn('hook ' + hook + ' priority -150', m.RULES)
        self.assertEqual(m.RULES.count('tcp flags & syn == syn'), 2)
        self.assertEqual(m.RULES.count('tcp option maxseg size > 1200 tcp option maxseg size set 1200'), 2)
        for prohibited in ['flush', 'iptables', 'forward', 'dport 22 ', 'sport 22 ', '2222', 'dport 80 ', 'sport 80 ']:
            self.assertNotIn(prohibited, m.RULES)
        self.assertEqual(m.DELETE, 'delete table ip ham_entry244_mss\n')

    def test_check_only_has_no_writes_or_systemctl(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(m, 'UNIT', Path(temporary) / 'unit'), patch.object(m, 'guard'), \
                 patch.object(m, 'verified_current', return_value=None), patch.object(m, 'save') as save, \
                 patch.object(m, 'run') as run:
                m.operate('apply', check_only=True, persist=True)
                run.assert_called_once_with('nft', '-c', '-f', '-', data=m.RULES)
                save.assert_not_called()
                self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_root_and_entry_identity_guards(self):
        with patch.object(m.os, 'geteuid', return_value=1000, create=True), patch.object(m, 'run') as run:
            with self.assertRaises(RuntimeError): m.guard()
            run.assert_not_called()
        with patch.object(m.os, 'geteuid', return_value=0, create=True), \
             patch.object(m, 'run', return_value=json.dumps([{'addr_info': [{'local': '127.0.0.1'}]}])):
            with self.assertRaises(RuntimeError): m.guard()

    def test_ownership_ignores_only_kernel_handles(self):
        table = {'nftables': [{'metainfo': {'version': 'test'}}, {'table': {'family': 'ip', 'name': m.TABLE, 'handle': 1}},
                             {'rule': {'handle': 2, 'expr': [{'match': {'right': 1200}}]}}]}
        changed_handles = copy.deepcopy(table); changed_handles['nftables'][1]['table']['handle'] = 9
        self.assertEqual(m.normalized(table), m.normalized(changed_handles))
        changed_rule = copy.deepcopy(table); changed_rule['nftables'][2]['rule']['expr'][0]['match']['right'] = 1400
        self.assertNotEqual(m.normalized(table), m.normalized(changed_rule))

    def test_refuse_existing_table_without_record_or_with_extra_rule(self):
        table = {'nftables': [{'table': {'family': 'ip', 'name': m.TABLE}}]}
        with tempfile.TemporaryDirectory() as temporary, patch.object(m, 'STATE', Path(temporary)), \
             patch.object(m, 'current', return_value=table):
            with self.assertRaises(RuntimeError): m.verified_current()
            m.save('owned.json', {'spec': hashlib.sha256(m.RULES.encode()).hexdigest(), 'table': table})
            self.assertEqual(m.verified_current(), table)
            table['nftables'].append({'rule': {'unexpected': True}})
            with self.assertRaises(RuntimeError): m.verified_current()

    def test_refuse_modified_spec_even_with_same_table(self):
        table = {'nftables': []}
        with tempfile.TemporaryDirectory() as temporary, patch.object(m, 'STATE', Path(temporary)), \
             patch.object(m, 'current', return_value=table):
            m.save('owned.json', {'spec': 'different-version', 'table': table})
            with self.assertRaises(RuntimeError): m.verified_current()

    def test_owned_apply_is_idempotent_and_does_not_restore_global_backup(self):
        table = complete_fixture()
        with tempfile.TemporaryDirectory() as temporary, patch.object(m, 'UNIT', Path(temporary) / 'unit'), \
             patch.object(m, 'guard'), patch.object(m, 'verified_current', return_value=table), \
             patch.object(m, 'save') as save, patch.object(m, 'run', return_value='{}') as run, patch.object(m.os, 'umask'):
            m.operate('apply')
            calls = [call.args for call in run.call_args_list]
            self.assertEqual(calls, [('nft', '-c', '-f', '-'), ('nft', '-j', 'list', 'ruleset')])
            self.assertEqual(save.call_count, 1)

    def test_backup_precedes_apply_and_record_is_saved(self):
        events = []; table = complete_fixture()
        def command(*args, data=None):
            events.append(('run', args, data)); return '{}'
        with tempfile.TemporaryDirectory() as temporary, patch.object(m, 'UNIT', Path(temporary) / 'unit'), \
             patch.object(m, 'guard'), patch.object(m, 'verified_current', side_effect=[None, table]), \
             patch.object(m, 'current', return_value=table), patch.object(m.os, 'umask'), \
             patch.object(m, 'run', side_effect=command), \
             patch.object(m, 'save', side_effect=lambda name, value: events.append(('save', name, value))):
            m.operate('apply')
        backup = next(i for i, e in enumerate(events) if e[0] == 'save' and e[1].startswith('before-'))
        mutation = next(i for i, e in enumerate(events) if e[0] == 'run' and e[1] == ('nft', '-f', '-'))
        self.assertLess(backup, mutation)
        self.assertTrue(any(e[0] == 'save' and e[1] == 'owned.json' for e in events))

    def test_rollback_deletes_only_verified_table(self):
        table = {'nftables': []}
        with tempfile.TemporaryDirectory() as temporary, patch.object(m, 'UNIT', Path(temporary) / 'unit'), \
             patch.object(m, 'guard'), patch.object(m, 'verified_current', return_value=table), \
             patch.object(m, 'current', return_value=None), patch.object(m, 'save'), \
             patch.object(m, 'run', return_value='{}') as run, patch.object(m.os, 'umask'):
            m.operate('rollback')
            writes = [call for call in run.call_args_list if call.args == ('nft', '-f', '-')]
            self.assertEqual(len(writes), 1); self.assertEqual(writes[0].kwargs['data'], m.DELETE)

    def test_foreign_table_blocks_before_backup_or_mutation(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(m, 'UNIT', Path(temporary) / 'unit'), \
             patch.object(m, 'guard'), patch.object(m, 'verified_current', side_effect=RuntimeError('unowned')), \
             patch.object(m, 'save') as save, patch.object(m, 'run') as run:
            with self.assertRaises(RuntimeError): m.operate('rollback')
            save.assert_not_called(); run.assert_not_called()

    def test_optional_unit_only_invokes_scoped_apply(self):
        unit = m.unit_text()
        self.assertIn('mss244.py apply\n', unit)
        self.assertNotIn('--persist', unit)
        for forbidden in ['ExecStop', 'nginx', 'xray', 'ssh.service', 'flush']:
            self.assertNotIn(forbidden, unit)

    def test_foreign_unit_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(m, 'UNIT', Path(temporary) / 'unit'), \
             patch.object(m, 'guard'), patch.object(m, 'run') as run:
            m.UNIT.write_text('foreign')
            with self.assertRaises(RuntimeError): m.operate('apply', persist=True)
            self.assertEqual(m.UNIT.read_text(), 'foreign'); run.assert_not_called()

    def test_complete_table_rejects_empty_table_missing_chain_or_assignment(self):
        m.complete_table(complete_fixture())
        broken = [ {'nftables': [{'table': {'name': m.TABLE}}]} ]
        value = complete_fixture(); value['nftables'].pop(); broken.append(value)
        value = complete_fixture(); value['nftables'][2]['rule']['expr'] = []; broken.append(value)
        for value in broken:
            with self.assertRaises(RuntimeError): m.complete_table(value)

    def test_explicit_chain_and_rule_commands_follow_exclusive_table_creation(self):
        lines = m.RULES.splitlines()
        self.assertTrue(lines[0].startswith('create table ip '))
        self.assertEqual(sum(s.startswith('add chain ip ') for s in lines), 2)
        self.assertEqual(sum(s.startswith('add rule ip ') for s in lines), 2)


if __name__ == '__main__': unittest.main()
