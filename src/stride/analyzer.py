"""
STRIDE threat analyzer with pluggable LLM backends.
Supports: Anthropic Claude, Ollama (local), Groq, Google Gemini, OpenAI, rule-based (no LLM).
"""

import json
import os
from typing import Dict, List, Optional

from src.vulnerabilities.database import (
    STRIDE,
    get_threats_for_components,
    get_stride_summary,
    get_severity_counts,
)

AVAILABLE_BACKENDS = ["rule_based", "ollama", "groq", "gemini", "openai", "anthropic"]


# ── Backend implementations ────────────────────────────────────────────────────

def _call_anthropic(prompt: str, api_key: str, model: str = "claude-sonnet-4-6") -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)
    msg = client.messages.create(
        model=model, max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text


def _call_ollama(prompt: str, model: str = "llama3.2", base_url: str = "http://localhost:11434") -> str:
    import urllib.request
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 4096},
    }).encode()
    req = urllib.request.Request(
        f"{base_url}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())["response"]


def _call_groq(prompt: str, api_key: str, model: str = "llama-3.3-70b-versatile") -> str:
    from groq import Groq
    client = Groq(api_key=api_key)
    chat = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=4096,
        temperature=0.3,
    )
    return chat.choices[0].message.content


def _call_gemini(prompt: str, api_key: str, model: str = "gemini-2.0-flash") -> str:
    import google.generativeai as genai
    genai.configure(api_key=api_key)
    m = genai.GenerativeModel(model)
    resp = m.generate_content(prompt)
    return resp.text


def _call_openai(prompt: str, api_key: str, model: str = "gpt-4o-mini",
                 base_url: Optional[str] = None) -> str:
    from openai import OpenAI
    kwargs = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    client = OpenAI(**kwargs)
    chat = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        max_tokens=4096,
        temperature=0.3,
    )
    return chat.choices[0].message.content


# ── Rule-based fallback (no LLM) ──────────────────────────────────────────────

def _rule_based_analysis(component_types: List[str], threats_by_component: dict,
                          severity_counts: dict) -> dict:
    """
    Generates a structured STRIDE report using only the knowledge base.
    No LLM required.
    """
    total_threats = sum(len(v) for v in threats_by_component.values())
    critical = severity_counts.get("Critical", 0)
    high = severity_counts.get("High", 0)

    if critical > 0:
        risk = "Critical"
    elif high >= 3:
        risk = "High"
    elif high > 0:
        risk = "Medium"
    else:
        risk = "Low"

    # executive summary
    comp_list = ", ".join(c.replace("_", " ").title() for c in component_types)
    summary = (
        f"The analyzed architecture contains {len(component_types)} component type(s): {comp_list}. "
        f"A total of {total_threats} threats were identified across all STRIDE categories, "
        f"including {critical} Critical and {high} High severity findings. "
        f"The overall risk level is assessed as **{risk}**.\n\n"
        f"Immediate attention is required for the Critical and High severity threats identified below. "
        f"Security controls should be implemented starting with the highest-impact countermeasures "
        f"listed in the detailed threat analysis section."
    )

    # per-component STRIDE breakdown (rule-based)
    stride_full = {
        "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
        "I": "Information Disclosure", "D": "Denial of Service", "E": "Elevation of Privilege",
    }
    comp_analyses = []
    for ctype in component_types:
        threats = threats_by_component.get(ctype, [])
        stride_map = {cat: [] for cat in stride_full}
        for t in threats:
            stride_map[t["stride_category"]].append(t["threat_name"])
        highest = max(threats, key=lambda t: {"Critical":4,"High":3,"Medium":2,"Low":1}.get(t["severity"],0),
                      default=None)
        comp_analyses.append({
            "component": ctype,
            "trust_boundary": f"{ctype.replace('_',' ').title()} boundary — verify authentication and authorization",
            "stride_threats": {
                cat: (", ".join(names) if names else "No specific threat identified")
                for cat, names in stride_map.items()
            },
            "highest_risk_threat": highest["threat_name"] if highest else "N/A",
        })

    # data flow threats (inferred from component pairs)
    flow_pairs = [
        ("user", "firewall", "S", "Credential spoofing at entry point", "High",
         "Enforce MFA and certificate pinning"),
        ("firewall", "load_balancer", "T", "Packet injection bypassing firewall rules", "High",
         "Enable deep packet inspection"),
        ("load_balancer", "web_server", "D", "DDoS amplification through LB to backends", "High",
         "Rate-limit per backend; enable auto-scaling"),
        ("web_server", "database", "T", "SQL injection via application layer", "Critical",
         "Use parameterized queries; apply DB firewall"),
        ("web_server", "cache", "I", "Sensitive data leaked through cache keys", "Medium",
         "Namespace cache keys; encrypt cached values"),
        ("api_gateway", "web_server", "S", "API key forgery granting unauthorized access", "High",
         "Rotate API keys; validate JWT signatures"),
        ("web_server", "message_queue", "T", "Malicious payload injection into queue", "High",
         "Sign messages with HMAC; validate schemas"),
        ("cdn", "user", "I", "Sensitive response cached and served to other users", "High",
         "Set Cache-Control: no-store on authenticated responses"),
        ("mobile_app", "api_gateway", "S", "Reverse-engineering app to extract API secrets", "High",
         "Use certificate pinning; store keys in secure enclave"),
        ("web_server", "external_service", "T", "Supply chain attack via compromised third-party", "High",
         "Validate all external responses; use circuit breakers"),
    ]
    data_flow_threats = [
        {"flow": f"{src} → {dst}", "stride_category": cat, "threat": threat,
         "severity": sev, "countermeasure": cm}
        for src, dst, cat, threat, sev, cm in flow_pairs
        if src in component_types and dst in component_types
    ]

    # recommendations (prioritized by severity)
    recs = []
    priority = 1
    for ctype, threats in threats_by_component.items():
        for t in sorted(threats, key=lambda x: {"Critical":0,"High":1,"Medium":2,"Low":3}.get(x["severity"],4)):
            if t["severity"] in ("Critical", "High") and priority <= 8:
                recs.append({
                    "priority": priority,
                    "action": t["countermeasures"][0] if t["countermeasures"] else "Review and harden",
                    "rationale": f"[{ctype.replace('_',' ').title()}] {t['threat_name']} — {t['severity']} severity",
                    "effort": "Medium",
                    "impact": "High" if t["severity"] == "Critical" else "Medium",
                })
                priority += 1

    return {
        "executive_summary": summary,
        "overall_risk_level": risk,
        "component_analyses": comp_analyses,
        "data_flow_threats": data_flow_threats,
        "recommendations": recs,
    }


# ── Prompt builder ─────────────────────────────────────────────────────────────

def _build_prompt(component_types, component_counts, threats_by_component) -> str:
    threats_summary = [
        {"component": comp, "stride": t["stride_category"],
         "threat": t["threat_name"], "severity": t["severity"]}
        for comp, threats in threats_by_component.items()
        for t in threats
    ]
    return f"""You are an expert security architect specializing in threat modeling using the STRIDE methodology.

A software architecture diagram was analyzed by a YOLOv8 computer vision model and the following components were detected:

**Detected Components:**
{json.dumps(component_counts, indent=2)}

**Pre-identified STRIDE Threats (from knowledge base):**
{json.dumps(threats_summary, indent=2)}

**STRIDE Categories:**
S=Spoofing, T=Tampering, R=Repudiation, I=Information Disclosure, D=Denial of Service, E=Elevation of Privilege

Return ONLY a valid JSON object (no markdown, no explanation) with this exact structure:

{{
  "executive_summary": "2-3 paragraph security posture summary highlighting critical risks",
  "overall_risk_level": "Critical|High|Medium|Low",
  "component_analyses": [
    {{
      "component": "component_name",
      "trust_boundary": "trust boundary context",
      "stride_threats": {{"S":"spoofing risk","T":"tampering risk","R":"repudiation risk","I":"info disclosure risk","D":"DoS risk","E":"privilege escalation risk"}},
      "highest_risk_threat": "single highest risk threat name"
    }}
  ],
  "data_flow_threats": [
    {{"flow":"ComponentA -> ComponentB","threat":"description","stride_category":"S|T|R|I|D|E","severity":"Critical|High|Medium|Low","countermeasure":"specific fix"}}
  ],
  "recommendations": [
    {{"priority":1,"action":"specific action","rationale":"why top priority","effort":"Low|Medium|High","impact":"Low|Medium|High"}}
  ]
}}"""


def _normalize_risk_level(value: str) -> str:
    for level in ("Critical", "High", "Medium", "Low"):
        if level.lower() in value.lower():
            return level
    return "High"


def _parse_llm_response(raw: str) -> dict:
    raw = raw.strip()
    if "```" in raw:
        parts = raw.split("```")
        for part in parts:
            part = part.strip()
            if part.startswith("json"):
                part = part[4:]
            try:
                return json.loads(part.strip())
            except Exception:
                continue
    return json.loads(raw)


# ── Main analyzer class ────────────────────────────────────────────────────────

class StrideAnalyzer:
    def __init__(
        self,
        backend: str = "rule_based",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        ollama_model: str = "llama3.2",
        ollama_url: str = "http://localhost:11434",
        openai_base_url: Optional[str] = None,
    ):
        """
        Args:
            backend: "rule_based" | "ollama" | "groq" | "gemini" | "openai" | "anthropic"
            api_key: API key for cloud backends (not needed for rule_based/ollama)
            model: override default model for the chosen backend
            ollama_model: model name for Ollama (e.g. "llama3.2", "mistral", "qwen2.5")
            ollama_url: Ollama server URL
            openai_base_url: custom base URL for OpenAI-compatible APIs (LM Studio, etc.)
        """
        self.backend = backend
        self.api_key = api_key
        self.ollama_model = ollama_model
        self.ollama_url = ollama_url
        self.openai_base_url = openai_base_url

        # default models per backend
        self.default_models = {
            "anthropic": "claude-sonnet-4-6",
            "groq":      "llama-3.3-70b-versatile",
            "gemini":    "gemini-2.0-flash",
            "openai":    "gpt-4o-mini",
        }
        self.model = model or self.default_models.get(backend)

    def analyze(self, detection_result) -> dict:
        component_types   = detection_result.component_types
        component_counts  = detection_result.component_counts
        threats_by_comp   = get_threats_for_components(component_types)
        stride_summary    = get_stride_summary(threats_by_comp)
        severity_counts   = get_severity_counts(threats_by_comp)

        if self.backend == "rule_based":
            ai_output = _rule_based_analysis(component_types, threats_by_comp, severity_counts)
        else:
            prompt = _build_prompt(component_types, component_counts, threats_by_comp)
            try:
                raw = self._call_llm(prompt)
                ai_output = _parse_llm_response(raw)
                # normalize risk level in case LLM returns format string
                ai_output["overall_risk_level"] = _normalize_risk_level(
                    ai_output.get("overall_risk_level", "High")
                )
            except Exception as e:
                print(f"[WARN] LLM call failed ({e}), falling back to rule-based analysis.")
                ai_output = _rule_based_analysis(component_types, threats_by_comp, severity_counts)

        return {
            "components":           component_types,
            "component_counts":     component_counts,
            "threats_by_component": threats_by_comp,
            "stride_summary":       stride_summary,
            "severity_counts":      severity_counts,
            "ai_analysis":          ai_output.get("executive_summary", ""),
            "component_analyses":   ai_output.get("component_analyses", []),
            "data_flow_threats":    ai_output.get("data_flow_threats", []),
            "recommendations":      ai_output.get("recommendations", []),
            "risk_level":           ai_output.get("overall_risk_level", "Medium"),
        }

    def _call_llm(self, prompt: str) -> str:
        if self.backend == "anthropic":
            return _call_anthropic(prompt, self.api_key, self.model)
        elif self.backend == "ollama":
            return _call_ollama(prompt, self.ollama_model, self.ollama_url)
        elif self.backend == "groq":
            return _call_groq(prompt, self.api_key, self.model)
        elif self.backend == "gemini":
            return _call_gemini(prompt, self.api_key, self.model)
        elif self.backend == "openai":
            return _call_openai(prompt, self.api_key, self.model, self.openai_base_url)
        else:
            raise ValueError(f"Unknown backend: {self.backend}")
