from ca_gap_analyzer.checks import ca08_trusted_locations as check
from conftest import make_location, make_snapshot


def test_passes_with_small_office_range():
    assert check.run(make_snapshot(locations=[make_location(cidrs=["203.0.113.0/29"])])) == []


def test_passes_at_exactly_slash_16():
    assert check.run(make_snapshot(locations=[make_location(cidrs=["198.18.0.0/16"])])) == []


def test_fails_with_slash_8():
    findings = check.run(make_snapshot(locations=[make_location(name="Office-HQ", cidrs=["20.0.0.0/8"])]))
    assert len(findings) == 1
    assert "16,777,216" in findings[0].detail
    assert findings[0].affected == ["Office-HQ"]


def test_ignores_untrusted_locations():
    loc = make_location(cidrs=["20.0.0.0/8"], trusted=False)
    assert check.run(make_snapshot(locations=[loc])) == []


def test_ignores_country_locations():
    country = {"@odata.type": "#microsoft.graph.countryNamedLocation", "displayName": "US", "countriesAndRegions": ["US"]}
    assert check.run(make_snapshot(locations=[country])) == []


def test_flags_broad_ipv6_range():
    loc = make_location(cidrs=["2001:db8::/32"])
    assert len(check.run(make_snapshot(locations=[loc]))) == 1


def test_skips_malformed_cidr():
    assert check.run(make_snapshot(locations=[make_location(cidrs=["not-an-ip"])])) == []
