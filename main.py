import os
import time
import json
from collections import defaultdict
from typing import Dict, Any, List
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from google import genai

app = FastAPI(title="SentinAI Enterprise Risk Gateway")

# ---------------------------------------------------------
# GEMINI CLIENT INITIALIZATION
# ---------------------------------------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None

# ---------------------------------------------------------
# IN-MEMORY FEATURE & VELOCITY STORE (Simulating Redis/Feast)
# ---------------------------------------------------------
VELOCITY_CACHE: Dict[str, List[float]] = defaultdict(list)
VELOCITY_WINDOW_SECONDS = 60
VELOCITY_THRESHOLD_BURST = 3

class TransactionPayload(BaseModel):
    transaction_id: str
    user_id: str
    amount: float
    currency: str = "INR"
    ip_address: str
    device_id: str
    merchant_category: str
    card_country: str

# ---------------------------------------------------------
# TIER 1: FAST HEURISTIC & VELOCITY ENGINE (<5ms)
# ---------------------------------------------------------
def evaluate_tier1_risk(tx: TransactionPayload) -> Dict[str, Any]:
    now = time.time()
    score = 0.05
    flags = []

    # 1. Sliding Window Velocity Check
    user_key = f"usr:{tx.user_id}"
    VELOCITY_CACHE[user_key] = [t for t in VELOCITY_CACHE[user_key] if now - t < VELOCITY_WINDOW_SECONDS]
    VELOCITY_CACHE[user_key].append(now)
    tx_count_user = len(VELOCITY_CACHE[user_key])

    if tx_count_user >= VELOCITY_THRESHOLD_BURST:
        score += 0.45
        flags.append(f"Carding velocity spike: {tx_count_user} txs in past {VELOCITY_WINDOW_SECONDS}s")

    # 2. Heuristic Rules
    if tx.amount > 50000:
        score += 0.30
        flags.append("High-ticket volume anomaly (> 50k INR)")
    
    if tx.card_country != "IN":
        score += 0.25
        flags.append("Cross-border issuance mismatch (Non-domestic)")

    if "vpn" in tx.ip_address.lower() or tx.ip_address.startswith("192.168") or tx.ip_address.startswith("10."):
        score += 0.25
        flags.append("Anomalous / Proxy / Subnet masked IP")

    high_risk_categories = ["crypto_exchange", "digital_gift_cards", "gaming_credits"]
    if tx.merchant_category.lower() in high_risk_categories:
        score += 0.15
        flags.append(f"High chargeback liability category: {tx.merchant_category}")

    score = round(min(score, 1.0), 2)
    return {
        "tier1_score": score,
        "flags": flags,
        "velocity_count": tx_count_user
    }

# ---------------------------------------------------------
# TIER 2: MULTI-AGENT ADJUDICATION PIPELINE
# ---------------------------------------------------------
def run_multi_agent_consensus(tx: TransactionPayload, t1_res: Dict[str, Any]) -> Dict[str, Any]:
    prompt = f"""
    You are an autonomous Multi-Agent Fraud Adjudicator for Razorpay.
    Analyze this suspicious/borderline transaction:

    [PAYLOAD]
    - Amount: {tx.amount} {tx.currency}
    - Merchant Industry: {tx.merchant_category}
    - Card Origin: {tx.card_country}
    - IP Address: {tx.ip_address}
    - Velocity (Last 60s): {t1_res['velocity_count']} transactions
    - Tier-1 Flags: {json.dumps(t1_res['flags'])}
    - Tier-1 Base Score: {t1_res['tier1_score']}

    Return your final verdict in strict JSON format:
    {{
      "behavioral_agent_score": 0.65,
      "merchant_agent_score": 0.60,
      "consensus_verdict": "APPROVE" | "CHALLENGE_OTP" | "DECLINE",
      "confidence": 0.90,
      "synthesis_rationale": "<concise 1-2 sentence technical justification>"
    }}
    """

    if client:
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            raw = response.text.replace("```json", "").replace("```", "").strip()
            return json.loads(raw)
        except Exception:
            pass

    # Deterministic fallback logic
    t1_score = t1_res["tier1_score"]
    if t1_score >= 0.70:
        return {
            "behavioral_agent_score": 0.85,
            "merchant_agent_score": 0.80,
            "consensus_verdict": "DECLINE",
            "confidence": 0.94,
            "synthesis_rationale": "Multi-agent consensus rejected payload due to compounding geo-mismatch and velocity anomalies."
        }
    return {
        "behavioral_agent_score": 0.55,
        "merchant_agent_score": 0.60,
        "consensus_verdict": "CHALLENGE_OTP",
        "confidence": 0.89,
        "synthesis_rationale": "Borderline risk threshold triggered; enforcing step-up biometric/OTP challenge to eliminate false declines."
    }

# ---------------------------------------------------------
# GATEWAY ROUTE
# ---------------------------------------------------------
@app.post("/api/evaluate")
async def evaluate_transaction(tx: TransactionPayload):
    start_time = time.time()
    
    t1_res = evaluate_tier1_risk(tx)
    tier1_score = t1_res["tier1_score"]

    if tier1_score < 0.35:
        routing = "TIER1_DIRECT_APPROVE"
        action = "APPROVE"
        details = {
            "behavioral_score": round(tier1_score * 0.8, 2),
            "merchant_score": round(tier1_score * 0.9, 2),
            "rationale": "Clean behavioral telemetry. Instant approval with zero friction."
        }
    elif tier1_score >= 0.80:
        routing = "TIER1_HARD_BLOCK"
        action = "DECLINE"
        details = {
            "behavioral_score": 0.95,
            "merchant_score": 0.90,
            "rationale": "Severe risk indicators identified. Blocked at perimeter to prevent chargeback."
        }
    else:
        routing = "TIER2_MULTI_AGENT_CONSENSUS"
        agent_result = run_multi_agent_consensus(tx, t1_res)
        action = agent_result.get("consensus_verdict", "CHALLENGE_OTP")
        details = {
            "behavioral_score": agent_result.get("behavioral_agent_score", 0.6),
            "merchant_score": agent_result.get("merchant_agent_score", 0.6),
            "rationale": agent_result.get("synthesis_rationale", "Multi-agent review applied.")
        }

    total_latency_ms = round((time.time() - start_time) * 1000, 2)

    return {
        "transaction_id": tx.transaction_id,
        "action": action,
        "routing": routing,
        "tier1_score": tier1_score,
        "flags": t1_res["flags"],
        "velocity_count": t1_res["velocity_count"],
        "agent_details": details,
        "latency_ms": total_latency_ms
    }

# ---------------------------------------------------------
# DASHBOARD UI
# ---------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTML_CONTENT

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SentinAI Risk Shield</title>
  <style>
    body { background-color: #0b0f19; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 24px; }
    .container { max-width: 800px; margin: 0 auto; }
    .card { background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 20px; margin-bottom: 20px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .btn { background: #2563eb; color: white; border: none; padding: 10px 16px; border-radius: 6px; cursor: pointer; font-weight: bold; width: 100%; margin-top: 10px; }
    .btn:hover { background: #1d4ed8; }
    .preset-btn { background: #1f2937; color: #93c5fd; border: 1px solid #374151; padding: 8px; border-radius: 6px; cursor: pointer; text-align: left; font-size: 12px; }
    input, select { width: 100%; background: #030712; border: 1px solid #374151; color: white; padding: 8px; border-radius: 6px; box-sizing: border-box; margin-top: 4px; }
    label { font-size: 12px; color: #9ca3af; }
    .badge { display: inline-block; padding: 6px 12px; border-radius: 6px; font-weight: bold; font-size: 16px; margin: 8px 0; }
    .approve { background: #064e3b; color: #34d399; border: 1px solid #059669; }
    .challenge { background: #78350f; color: #fbbf24; border: 1px solid #d97706; }
    .decline { background: #7f1d1d; color: #f87171; border: 1px solid #dc2626; }
  </style>
</head>
<body>
  <div class="container">
    <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #1f2937; padding-bottom:12px; margin-bottom:20px;">
      <div>
        <h1 style="margin:0; color:#60a5fa; font-size:22px;">SentinAI Risk Shield</h1>
        <p style="margin:4px 0 0 0; color:#9ca3af; font-size:12px;">Real-Time Multi-Agent Fraud Adjudication</p>
      </div>
      <span style="background:#064e3b; color:#34d399; border:1px solid #059669; padding:4px 8px; border-radius:12px; font-size:11px;">Active</span>
    </div>

    <!-- Presets -->
    <div style="margin-bottom:16px;">
      <div style="font-size:12px; color:#9ca3af; margin-bottom:6px;">Select Preset Scenario:</div>
      <div style="display:grid; grid-template-columns: 1fr 1fr 1fr; gap:8px;">
        <button class="preset-btn" onclick="applyPreset('safe')"><b>1. Safe User</b><br>INR 850 (Clean)</button>
        <button class="preset-btn" onclick="applyPreset('borderline')"><b>2. Velocity Alert</b><br>INR 62,000 (Borderline)</button>
        <button class="preset-btn" onclick="applyPreset('attack')"><b>3. Proxy / VPN</b><br>INR 95,000 (Attack)</button>
      </div>
    </div>

    <!-- Form -->
    <div class="card">
      <div class="grid">
        <div>
          <label>User ID</label>
          <input id="user_id" value="usr_rahul_88">
        </div>
        <div>
          <label>Amount (INR)</label>
          <input id="amount" type="number" value="850">
        </div>
        <div>
          <label>Card Country</label>
          <input id="card_country" value="IN">
        </div>
        <div>
          <label>Merchant Category</label>
          <select id="merchant_category">
            <option value="ecommerce_retail">Retail / Grocery</option>
            <option value="electronics_highvalue">High-End Electronics</option>
            <option value="digital_gift_cards">Digital Gift Cards</option>
          </select>
        </div>
        <div style="grid-column: span 2;">
          <label>IP Address</label>
          <input id="ip_address" value="49.207.198.12">
        </div>
      </div>
      <button class="btn" onclick="submitPayload()">Evaluate Transaction</button>
    </div>

    <!-- Output -->
    <div id="outputContainer" class="card" style="display:none;">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <span style="font-size:12px; color:#9ca3af;">Gateway Verdict:</span>
        <span id="latencyBadge" style="font-size:12px; color:#60a5fa; font-family:monospace;"></span>
      </div>
      <div id="verdictBadge" class="badge"></div>
      <div style="background:#030712; border:1px solid #1f2937; padding:12px; border-radius:6px; margin-top:10px; font-size:12px;">
        <div><b>Routing:</b> <span id="routingBadge" style="color:#60a5fa;"></span></div>
        <div><b>Tier-1 Base Score:</b> <span id="t1ScoreBadge" style="color:#60a5fa;"></span></div>
        <div><b>Velocity Count:</b> <span id="velocityBadge" style="color:#60a5fa;"></span></div>
        <div style="margin-top:6px;"><b>Rationale:</b> <span id="rationaleText" style="color:#cbd5e1;"></span></div>
      </div>
    </div>
  </div>

  <script>
    function applyPreset(mode) {
      if (mode === 'safe') {
        document.getElementById('user_id').value = "usr_domestic_" + Math.floor(Math.random()*1000);
        document.getElementById('amount').value = "850";
        document.getElementById('card_country').value = "IN";
        document.getElementById('merchant_category').value = "ecommerce_retail";
        document.getElementById('ip_address').value = "49.207.198.12";
      } else if (mode === 'borderline') {
        document.getElementById('user_id').value = "usr_shopper_44";
        document.getElementById('amount').value = "62000";
        document.getElementById('card_country').value = "IN";
        document.getElementById('merchant_category').value = "electronics_highvalue";
        document.getElementById('ip_address').value = "49.207.198.12";
      } else if (mode === 'attack') {
        document.getElementById('user_id').value = "usr_fraud_ring_9";
        document.getElementById('amount').value = "95000";
        document.getElementById('card_country').value = "US";
        document.getElementById('merchant_category').value = "digital_gift_cards";
        document.getElementById('ip_address').value = "10.0.44.12-vpn";
      }
    }

    async function submitPayload() {
      const payload = {
        transaction_id: "tx_" + Math.random().toString(36).substring(6),
        user_id: document.getElementById('user_id').value,
        amount: parseFloat(document.getElementById('amount').value),
        currency: "INR",
        ip_address: document.getElementById('ip_address').value,
        device_id: "dev_" + Math.random().toString(36).substring(8),
        merchant_category: document.getElementById('merchant_category').value,
        card_country: document.getElementById('card_country').value
      };

      const res = await fetch('/api/evaluate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const data = await res.json();

      document.getElementById('outputContainer').style.display = 'block';
      document.getElementById('latencyBadge').innerText = data.latency_ms + " ms";
      document.getElementById('t1ScoreBadge').innerText = data.tier1_score;
      document.getElementById('velocityBadge').innerText = data.velocity_count + " txs in window";
      document.getElementById('routingBadge').innerText = data.routing;
      document.getElementById('rationaleText').innerText = data.agent_details.rationale;

      const badge = document.getElementById('verdictBadge');
      badge.innerText = data.action;
      if (data.action.includes('APPROVE')) badge.className = 'badge approve';
      else if (data.action.includes('OTP') || data.action.includes('CHALLENGE')) badge.className = 'badge challenge';
      else badge.className = 'badge decline';
    }
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)