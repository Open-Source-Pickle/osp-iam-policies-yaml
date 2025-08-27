from __future__ import annotations
import json, sys, pathlib
import yaml
from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parents[1]
YAML_FILE = ROOT / 'policies' / 'iam-policies.yaml'
SCHEMA_FILE = ROOT / 'schemas' / 'policy.schema.json'
OUT_JSON = ROOT / 'dist' / 'iam-policies.json'

def load_yaml(path):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def validate_schema(data, schema):
    v = Draft202012Validator(schema)
    errors = sorted(v.iter_errors(data), key=lambda e: e.path)
    if errors:
        print('Schema validation failed:')
        for e in errors:
            path = '.'.join(str(p) for p in e.path) or '<root>'
            print(f' - {path}: {e.message}')
        sys.exit(1)

def main():
    try:
        policy = load_yaml(YAML_FILE)
        schema = load_json(SCHEMA_FILE)
        validate_schema(policy, schema)
        cloned = json.loads(json.dumps(policy))
        for role in cloned.get('roles', []):
            if role.get('name') == 'support_engineer':
                for perm in role.get('permissions', []):
                    actions = perm.get('actions', [])
                    perm['actions'] = [a for a in actions if a != 'delete']
        out = OUT_JSON
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(cloned, f, indent=2)
        print(f'Wrote {out}')
    except Exception as e:
        print(f'Error: {type(e).__name__}: {e}')
        sys.exit(1)

if __name__ == '__main__':
    main()
