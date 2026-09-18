from copy import deepcopy
import unittest
from unittest.mock import patch
import panel as p


class FakePath:
    def __init__(self, name=''): self.name = name
    def __truediv__(self, name): return FakePath(name)
    def exists(self): return self.name in ['entry-candidate.json', 'wanted-binding.json']


class Tests(unittest.TestCase):
    def fixture(self):
        old_binding = {'activeConfigProfileUuid': p.XP, 'activeInbounds': ['legacy']}
        before = {'profiles': {p.EP: {'config': {'old_entry': True}}, p.XP: {'config': {'old_exit': True}}},
                  'nodes': {p.EXIT_NODE: {'configProfile': deepcopy(old_binding)}}}
        state = {'panel-before': before, 'plan': {'exit': {'new_exit': True}},
                 'entry-candidate': {'new_entry': True},
                 'wanted-binding': {'activeConfigProfileUuid': p.XP, 'activeInbounds': ['backend', 'legacy']}}
        live = {p.EP: {'config': state['entry-candidate']}, p.XP: {'config': state['plan']['exit']},
                p.EXIT_NODE: {'configProfile': state['wanted-binding']}}
        writes = []
        def api(method, path, body=None):
            if method == 'GET': return deepcopy(live[path.rsplit('/', 1)[1]])
            writes.append(deepcopy(body))
            if 'config' in body: live[body['uuid']]['config'] = body['config']
            else: live[body['uuid']]['configProfile'] = body['configProfile']
        return state, live, writes, api

    def test_entry_restored_before_exit(self):
        state, live, writes, api = self.fixture()
        with patch.object(p, 'read', side_effect=lambda name: deepcopy(state[name])), patch.object(p, 'STATE', FakePath()), \
             patch.object(p, 'client', return_value=(api, None)), patch.object(p, 'save'):
            p.rollback()
        self.assertEqual([w['uuid'] for w in writes], [p.EP, p.EXIT_NODE, p.XP])
        self.assertEqual(live[p.EP]['config'], state['panel-before']['profiles'][p.EP]['config'])

    def test_concurrent_entry_change_refuses_overwrite(self):
        state, live, writes, api = self.fixture(); live[p.EP]['config'] = {'external_change': True}
        with patch.object(p, 'read', side_effect=lambda name: deepcopy(state[name])), patch.object(p, 'STATE', FakePath()), \
             patch.object(p, 'client', return_value=(api, None)), patch.object(p, 'save'):
            with self.assertRaises(RuntimeError): p.rollback()
        self.assertEqual(writes, [])


if __name__ == '__main__': unittest.main()
