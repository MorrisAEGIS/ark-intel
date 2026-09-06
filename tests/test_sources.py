import pytest

from arkintel import sources


@pytest.mark.asyncio
async def test_usgs_normalization_has_provenance(monkeypatch):
    async def fake_json(_client, _source):
        return {
            "features": [
                {
                    "id": "eq-1",
                    "geometry": {"type": "Point", "coordinates": [-102.0, 32.0, 4.2]},
                    "properties": {
                        "title": "M 2.0 - test",
                        "time": 1_700_000_000_000,
                        "mag": 2.0,
                        "place": "test",
                        "url": "https://earthquake.usgs.gov/earthquakes/eventpage/eq-1",
                        "type": "earthquake",
                    },
                }
            ]
        }

    monkeypatch.setattr(sources, "_get_json", fake_json)
    source = sources.SOURCE_INDEX["usgs-earthquakes"]
    rows = await sources._usgs(None, source)
    assert rows[0]["geometry"]["type"] == "Point"
    props = rows[0]["properties"]
    assert props["source_id"] == "usgs-earthquakes"
    assert props["synthetic"] is False
    assert props["truth_class"] == "observed"
    assert props["raw_sha256"]
    assert props["evidence_pointer"].startswith("arkintel://events/")


def test_risky_upstream_sources_fail_closed_in_catalog():
    catalog = {row["id"]: row for row in sources.source_catalog()}
    assert catalog["osiris-cctv"]["availability"] == "policy_disabled"
    assert catalog["osiris-submarine-cables"]["availability"] == "provenance_pending"
    assert catalog["global-fishing-watch"]["availability"] == "credential_required"
