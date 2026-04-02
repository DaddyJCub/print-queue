import json


def read_json(path, default=None):
    try:
        with open(path, "r") as fh:
            return json.loads(fh.read())
    except Exception:
        return default


def write_json(path, data):
    with open(path, "w") as fh:
        fh.write(json.dumps(data))


def delete_file(path):
    try:
        import os

        os.remove(path)
    except Exception:
        pass


def append_ring(path, value, limit=10):
    state = read_json(path, default={}) or {}
    ring = state.get("last_cmd_ids", [])
    ring.append(value)
    ring = ring[-limit:]
    state["last_cmd_ids"] = ring
    write_json(path, state)


def in_ring(path, value):
    state = read_json(path, default={}) or {}
    ring = state.get("last_cmd_ids", [])
    return value in ring
