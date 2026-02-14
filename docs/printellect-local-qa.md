# Printellect Local QA

## 1) Start backend locally

```bash
bash scripts/start_printellect_local.sh
```

## 2) Run smoke flow

In another terminal:

```bash
export DB_PATH=$PWD/local_data/app.db
export BASE_URL=http://127.0.0.1:3000
export ADMIN_PASSWORD=admin
python3 scripts/printellect_local_smoke.py
```

Expected ending line:

```text
PASS: Printellect local smoke test completed
```

## 2.1) Enable feature flag access for your test user

Printellect user routes are gated by feature flag `printellect_device_control`.
Assign access in admin features before manual testing:

```bash
bash scripts/assign_printellect_feature.sh your-test-email@example.com
```

## 3) Manual pages

- Owner pages:
  - `/printellect/add-device`
  - `/printellect/devices`
- Admin pages:
  - `/admin/printellect/devices`
  - `/admin/printellect/releases`
