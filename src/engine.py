from __future__ import annotations
import csv
import json
from pathlib import Path

SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}

def load_findings(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def prioritise(findings: list[dict]) -> list[dict]:
    ranked = []
    for f in findings:
        sev = (f.get("severity") or "medium").lower()
        cvss = float(f.get("cvss") or 0)
        epss = float(f.get("epss") or 0)
        item = dict(f)
        item["priority_score"] = round(SEVERITY_WEIGHT.get(sev, 10) + cvss * 4 + epss * 30, 2)
        ranked.append(item)
    return sorted(ranked, key=lambda x: x["priority_score"], reverse=True)

def summarise(ranked: list[dict]) -> dict:
    return {
        "finding_count": len(ranked),
        "top_5": ranked[:5],
        "critical_high": sum(1 for r in ranked if r.get("severity", "").lower() in {"critical", "high"}),
        "mean_priority": round(sum(r["priority_score"] for r in ranked) / max(len(ranked), 1), 2),
    }

def run(data_dir: Path, out_dir: Path) -> dict:
    ranked = prioritise(load_findings(data_dir / "findings.csv"))
    summary = summarise(ranked)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "prioritised_findings.json").write_text(json.dumps(ranked, indent=2), encoding="utf-8")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary
