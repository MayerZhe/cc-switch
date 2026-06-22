#!/usr/bin/env python3
import json, sys
with open('src-tauri/tauri.conf.json') as f:
    d = json.load(f)
if 'plugins' in d and 'updater' in d['plugins']:
    del d['plugins']['updater']
with open('src-tauri/tauri.conf.json', 'w') as f:
    json.dump(d, f, indent=2)
