from copy import deepcopy
import unittest
from unittest.mock import patch
import panel as p


class FakePath:
    def __init__(self, name=''): self.name = name
    def __truediv__(self, name): return FakePath(name)
    def exists(self): return self.name in ['entry-candidate.json', 'wanted-binding.json', 'objects.json']


class Tests(unittest.TestCase):
    def fixture(self):
        old_binding = {'activeConfigProfileUuid': p.XP, 'activeInbounds': ['legacy']}
        before = {'profiles': {p.EP: {'config': {'old_entry': True}}, p.XP: {'config': {'shared': True}}},
                  'nodes': {p.EXIT_NODE: {'configProfile': deepcopy(old_binding)}},
                  'squads': [{'uuid': 'squad'}]}
        state = {'panel-before': before, 'plan': {'exit': {'clone': True}},
                 'entry-candidate': {'new_entry': True},
                 'objects': {'profile': 'clone', 'mapping': {'legacy': 'cloned-legacy'}},
                 'wanted-binding': {'activeConfigProfileUuid': 'clone', 'activeInbounds': ['backend', 'cloned-legacy']}}
        live = {p.EP: {'config': state['entry-candidate']}, p.XP: {'config': {'shared': True}},
                'clone': {'config': {'clone': True}, 'nodes': []},
                p.EXIT_NODE: {'configProfile': state['wanted-binding']}}
        squads = [{'uuid': 'squad', 'inbounds': [{'uuid': x} for x in ['legacy', 'cloned-legacy', 'unrelated-new']]}]
        writes = []
        def api(method, path, body=None):
            if method == 'GET':
                if path == '/api/internal-squads/': return {'internalSquads': deepcopy(squads)}
                return deepcopy(live[path.rsplit('/', 1)[1]])
            writes.append(deepcopy(body))
            if 'config' in body: live[body['uuid']]['config'] = body['config']
            elif 'configProfile' in body: live[body['uuid']]['configProfile'] = body['configProfile']
        return state, live, writes, api

    def run_rollback(self, state, api):
        with patch.object(p, 'read', side_effect=lambda name: deepcopy(state[name])), patch.object(p, 'STATE', FakePath()), \
             patch.object(p, 'client', return_value=(api, None)), patch.object(p, 'save'):
            p.rollback()

    def test_restore_entry_before_binding_never_write_shared(self):
        state, live, writes, api = self.fixture(); self.run_rollback(state, api)
        self.assertEqual([w['uuid'] for w in writes], [p.EP, p.EXIT_NODE, 'squad'])
        self.assertEqual(writes[-1]['inbounds'], ['legacy', 'unrelated-new'])
        self.assertEqual(live[p.XP]['config'], {'shared': True})

    def test_concurrent_entry_change_refuses_overwrite(self):
        state, live, writes, api = self.fixture(); live[p.EP]['config'] = {'external': True}
        with self.assertRaises(RuntimeError): self.run_rollback(state, api)
        self.assertEqual(writes, [])

    def test_clone_unexpected_consumer_refuses_rights_removal(self):
        state, live, writes, api = self.fixture(); live['clone']['nodes'] = [{'uuid': 'other'}]
        with self.assertRaises(RuntimeError): self.run_rollback(state, api)
        self.assertEqual([w['uuid'] for w in writes], [p.EP, p.EXIT_NODE])


if __name__ == '__main__': unittest.main()
