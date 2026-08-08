"""Controlled validation, evidence gates, and independent criticism."""

from budobugs.validation.critic import AdversarialCritic
from budobugs.validation.gates import EvidenceGate, GateReceipt

__all__ = ["AdversarialCritic", "EvidenceGate", "GateReceipt"]
