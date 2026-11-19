"""Offline checks for the read-only WAS diagnostic and its shareable output."""

import json

import httpx

from scripts.diagnose_was import diagnose


VULN = "1790eedf-2118-45ea-abff-bcaf3d9d1e0a"
INVENTORY_ID = "240ae95d-3830-498e-8598-d44097ec64cf"


def test_documented_responses_probe_mapping_without_leaking_evidence():
    requests = []

    def handler(request):
        requests.append(request)
        path = request.url.path
        if path.endswith("/properties"):
            data = {"data": [{"key": "finding_detection_id"}]}
        elif path.endswith("inventory/findings/search"):
            assert json.loads(request.content)["filters"] == [
                {"property": "sensor_type", "operator": "=", "value": ["WAS"]}
            ]
            data = {"pagination": {"total": 1}, "data": [
                {"id": INVENTORY_ID, "extra_properties": {
                    "finding_detection_id": VULN, "sensor_type": "WAS",
                    "asset_name": "https://private.example/?token=SECRET",
                }}
            ]}
        elif path.endswith("vulnerabilities/search"):
            data = {"items": [{"vuln_id": VULN}], "pagination": {"total": 1}}
        elif path.endswith(VULN):
            data = {"vuln_id": VULN, "plugin_id": 98123,
                    "uri": "https://private.example/?token=SECRET",
                    "details": {"proof": "PRIVATE_PROOF", "payload": "PRIVATE_PAYLOAD",
                                "request": {"headers": "Cookie: SECRET"},
                                "response": {"body": "PRIVATE_BODY"}}}
        elif path.endswith(INVENTORY_ID):
            return httpx.Response(404, text="PRIVATE_ERROR")
        elif path.endswith("plugins/98123"):
            data = {"plugin_id": 98123, "description": "Description", "solution": "Fix"}
        else:
            raise AssertionError(path)
        return httpx.Response(200, json=data)

    with httpx.Client(base_url="https://cloud.tenable.com", transport=httpx.MockTransport(handler)) as client:
        report = diagnose(client)
    encoded = json.dumps(report)
    for forbidden in ("SECRET", "PRIVATE_", "private.example"):
        assert forbidden not in encoded
    assert report["inventory_total"] == 1
    assert report["was_total"] == 1
    assert report["id_probes"][0]["was_instance_id_confirmed"] is False
    assert report["id_probes"][1]["was_instance_id_confirmed"] is True
    assert report["plugins"]["98123"]["fields"]["solution"]["characters"] == 3
    # Cached detail lookup is reused for the ID probe.
    assert sum(r.url.path.endswith(VULN) for r in requests) == 1
    assert all(r.method == "GET" or r.url.path.endswith("/search") for r in requests)


def test_permission_errors_produce_diagnostics_without_response_bodies():
    with httpx.Client(base_url="https://cloud.tenable.com", transport=httpx.MockTransport(
        lambda request: httpx.Response(403, text="PRIVATE_ERROR_BODY")
    )) as client:
        report = diagnose(client)
    assert len(report["requests"]) == 3
    assert all(call["http_status"] == 403 for call in report["requests"])
    assert "PRIVATE_ERROR_BODY" not in json.dumps(report)


def test_rate_limit_stops_further_requests():
    with httpx.Client(base_url="https://cloud.tenable.com", transport=httpx.MockTransport(
        lambda request: httpx.Response(429)
    )) as client:
        report = diagnose(client)
    assert report["rate_limited"] is True
    assert len(report["requests"]) == 1


def test_numeric_detection_id_is_only_a_plugin_candidate():
    def handler(request):
        path = request.url.path
        if path.endswith("inventory/findings/search"):
            return httpx.Response(200, json={"data": [{"id": INVENTORY_ID,
                                  "extra_properties": {"finding_detection_id": "98123"}}]})
        if path.endswith("plugins/98123"):
            return httpx.Response(200, json={"plugin_id": 98123, "solution": "Fix"})
        if path.endswith(INVENTORY_ID):
            return httpx.Response(404)
        return httpx.Response(200, json={})

    with httpx.Client(base_url="https://cloud.tenable.com", transport=httpx.MockTransport(handler)) as client:
        report = diagnose(client)
    assert report["plugins"]["98123"]["id_confirmed"] is True
    assert not any(p.get("was_instance_id_confirmed") for p in report["id_probes"])


def test_cli_loads_env_and_writes_report(tmp_path, monkeypatch, capsys):
    from scripts import diagnose_was

    env_file = tmp_path / ".env"
    env_file.write_text("TENABLE_ACCESS_KEY=file-access\nTENABLE_SECRET_KEY=file-secret\n")
    output = tmp_path / "diagnostic.json"
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "exported-access")
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    monkeypatch.setenv("CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr("sys.argv", ["diagnose_was.py", "--env-file", str(env_file),
                                    "--out", str(output)])

    def handler(request):
        assert request.headers["X-ApiKeys"] == "accessKey=exported-access;secretKey=file-secret"
        return httpx.Response(200, json={"data": [], "items": [], "pagination": {"total": 0}})

    real_client = httpx.Client
    monkeypatch.setattr(diagnose_was.httpx, "Client", lambda **kwargs: real_client(
        **kwargs, transport=httpx.MockTransport(handler)))
    diagnose_was.main()
    captured = capsys.readouterr()
    assert "total=0, sampled=0" in captured.out
    assert "Saved diagnostic:" in captured.err
    assert len(json.loads(output.read_text())["requests"]) == 3
    for secret in ("file-access", "file-secret", "exported-access"):
        assert secret not in captured.out + captured.err + output.read_text()
