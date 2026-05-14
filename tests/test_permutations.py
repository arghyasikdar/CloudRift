from cloudrift.discovery.permutations import BucketPermutationGenerator


def test_generates_realistic_candidates() -> None:
    candidates = BucketPermutationGenerator().generate("target.com", limit=50)
    names = {candidate.name for candidate in candidates}

    assert "target-assets" in names
    assert "target-backups" in names
    assert "cdn-target" in names
