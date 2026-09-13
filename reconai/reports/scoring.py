"""Risk Scoring Engine.

Calculates a quantitative risk score for a target based on its attack surface and findings.
"""
from __future__ import annotations

from reconai.core.database.manager import DatabaseManager


class RiskScoringEngine:
    """Calculates risk scores for targets based on findings and exposure."""

    def __init__(self, db: DatabaseManager, scan_id: str):
        self.db = db
        self.scan_id = scan_id

    def calculate_score(self) -> dict:
        """Calculate the risk score from 0 to 100 (100 being critical risk)."""
        findings = self.db.get_findings(self.scan_id)
        ports = self.db.get_ports(self.scan_id)
        
        # Base severity weights
        weights = {
            "critical": 25,
            "high": 15,
            "medium": 5,
            "low": 1,
            "info": 0
        }
        
        # Confidence modifiers
        conf_mods = {
            "verified": 1.0,
            "likely": 0.8,
            "potential": 0.5,
            "info": 0.1
        }
        
        score = 0.0
        
        # Findings score
        for f in findings:
            base = weights.get(f["severity"].lower(), 0)
            mod = conf_mods.get(f["confidence"].lower(), 0.5)
            score += (base * mod)
            
        # Attack surface penalty (exposure)
        exposed_ports = len([p for p in ports if p["port"] not in (80, 443)])
        score += (exposed_ports * 0.5)
        
        # Cap at 100
        final_score = min(score, 100.0)
        
        # Determine grade
        grade = "A"
        if final_score > 80:
            grade = "F"
        elif final_score > 60:
            grade = "D"
        elif final_score > 40:
            grade = "C"
        elif final_score > 20:
            grade = "B"
            
        return {
            "score": round(final_score, 1),
            "grade": grade,
            "exposure_penalty": exposed_ports * 0.5,
            "findings_count": len(findings)
        }
