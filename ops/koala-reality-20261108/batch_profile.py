"""Dedicated-profile compatibility changes with per-node automatic rollback."""
import importlib.util
import json
from pathlib import Path
import sys

RELEASE=Path('/root/ham-koala-batch-release-20261108')

if __name__=='__main__':
    node=Path(__file__).stem if Path(__file__).parent==RELEASE else Path(__file__).parent.name.removeprefix('ham-koala-batch-profile-')
    policy=json.loads((RELEASE/(node+'.json')).read_text())
    spec=importlib.util.spec_from_file_location('profile',RELEASE/'profile_compat.py')
    profile=importlib.util.module_from_spec(spec);spec.loader.exec_module(profile)
    profile.NODE=policy['node'];profile.PROFILE=policy['profile'];profile.HOST=policy['host'];profile.TAG=policy['tag']
    profile.STATE=Path('/root/ham-koala-batch-profile-'+node)
    profile.UNIT='ham-koala-batch-profile-'+node
    profile.__file__=__file__
    profile.main(sys.argv[1])
