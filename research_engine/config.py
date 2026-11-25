from pathlib import Path
import os, yaml
ROOT=Path(__file__).resolve().parents[1]
def load_config():
 p=ROOT/"config.yaml"
 return yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {}
def resolve_path(value): return (ROOT/Path(value)).resolve()
