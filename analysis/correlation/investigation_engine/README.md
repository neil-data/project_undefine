# Phase 10 — AI Investigation Engine

## Overview

The AI Investigation Engine is a comprehensive workflow that processes all collected evidence from malware analysis and generates a detailed investigation report for law enforcement investigators.

## Architecture

The investigation engine follows a sequential workflow:

```
Load All Evidence
       ↓
Generate Timeline
       ↓
Explain Malware
       ↓
Explain Victim Impact
       ↓
Explain Exfiltration
       ↓
Generate Recommendations
       ↓
Generate Summary
```

## Components

### 1. Load All Evidence
- Collects and validates all evidence from the orchestrator state
- Ensures static analysis, dynamic analysis, MITRE techniques, and capability tags are available

### 2. Generate Timeline
- Creates a chronological timeline of malware behavior
- Categorizes events by type: static, dynamic, network, file, registry, process
- Assigns severity levels: info, warning, critical

### 3. Explain Malware
- Uses AI (Groq) to generate plain-language explanations of malware behavior
- Falls back to template-based explanations if AI is unavailable
- Identifies capabilities and provides technical details

### 4. Explain Victim Impact
- Analyzes data accessed by the malware
- Identifies privacy, financial, and device integrity risks
- Provides overall impact assessment (low, medium, high, critical)

### 5. Explain Exfiltration
- Analyzes data exfiltration patterns
- Identifies data types, destinations, and timing patterns
- Assesses encryption status and estimated volume

### 6. Generate Recommendations
- Creates actionable recommendations for investigators
- Prioritizes by: immediate, high, medium, low
- Categorizes by: containment, evidence, investigation, victim

### 7. Generate Summary
- Produces final investigation summary with:
  - Executive summary
  - Key findings
  - Timeline summary
  - Risk assessment
  - Next steps

### 8. Chain Verification ⭐ NEW
- Cryptographic verification of evidence integrity
- Hash-based chain linking for tamper detection
- HMAC signature verification for chain of custody
- Ensures all analysis steps are present and unmodified
- Provides verification status for legal proceedings

## Integration with LangGraph Orchestrator

The investigation engine is integrated as a new node in the LangGraph orchestrator:

```python
from agents.investigation_engine.investigation_engine import run_investigation_workflow

def investigation_engine(state: OrchestratorState) -> OrchestratorState:
    """Phase 10: AI Investigation Engine."""
    # Convert orchestrator state to investigation state
    investigation_state = {...}
    
    # Run investigation workflow
    investigation_result = run_investigation_workflow(investigation_state)
    
    # Return results to orchestrator
    return {**state, "investigation_output": investigation_result}
```

The investigation engine runs after the narrative agent in the orchestrator graph.

## Usage

### Standalone Demo

Run the standalone demo with mock data:

```bash
cd agents/investigation_engine
python3 demo_investigation.py
```

This will display a complete investigation report using sample malware data.

### Integration with Orchestrator

The investigation engine is automatically integrated into the orchestrator graph. To use it:

```python
from agents.orchestrator.orchestrator import build_graph

app = build_graph()
final_state = app.invoke({
    "sample_id": "your_sample_id",
    "static_output": static_analysis_data,
    "dynamic_output": dynamic_analysis_data,
    # ... other state data
})

# Access investigation results
investigation_output = final_state.get("investigation_output")
```

### Direct Usage

```python
from agents.investigation_engine.investigation_engine import InvestigationEngine

engine = InvestigationEngine(groq_api_key="your_api_key")
result = engine.run_investigation(investigation_state)
```

### With Chain Verification

```python
from agents.investigation_engine.investigation_engine import InvestigationEngine

# With chain verification enabled (default)
engine = InvestigationEngine(secret_key="your_secret_key")
result = engine.run_investigation_with_verification(investigation_state, verify_chain=True)

# Access verification results
verification = result.get("chain_verification")
print(f"Chain valid: {verification['is_valid']}")
print(f"Status: {verification['status']}")
print(f"Verified links: {verification['verified_links']}/{verification['total_links']}")
```

### Chain Verification API

```python
from agents.investigation_engine.chain_verification import (
    ChainVerifier,
    verify_chain,
    verify_integrity,
)

# Verify a chain
verifier = ChainVerifier(secret_key="your_secret_key")
result = verifier.verify_chain(chain_links)

# Verify investigation integrity
result, chain = verify_integrity(investigation_state, secret_key="your_secret_key")
```

## Data Schema

### InvestigationState
The main state object that flows through the investigation workflow:

```python
class InvestigationState(TypedDict, total=False):
    sample_id: str
    static_output: Optional[dict]
    dynamic_output: Optional[dict]
    mitre_techniques: Optional[List[dict]]
    capability_tags: Optional[List[dict]]
    risk_score: Optional[int]
    
    # Investigation-specific state
    timeline_events: List[TimelineEvent]
    malware_explanation: Optional[MalwareExplanation]
    victim_impact: Optional[VictimImpact]
    exfiltration_analysis: Optional[ExfiltrationAnalysis]
    recommendations: List[Recommendation]
    investigation_summary: Optional[InvestigationSummary]
```

### Output Models

- **TimelineEvent**: Single event in the malware execution timeline
- **MalwareExplanation**: AI-generated explanation of malware behavior
- **VictimImpact**: Analysis of victim impact and risks
- **ExfiltrationAnalysis**: Analysis of data exfiltration patterns
- **Recommendation**: Actionable recommendation for investigators
- **InvestigationSummary**: Final investigation summary

### Chain Verification Models

- **ChainLink**: Single link in the investigation chain with cryptographic hashes
- **ChainLinkType**: Enum of analysis step types (static_analysis, dynamic_analysis, etc.)
- **VerificationStatus**: Enum of verification results (valid, invalid, tampered, incomplete)
- **VerificationResult**: Complete verification result with detailed status

## Dependencies

```
pydantic>=2.0.0
groq>=0.5.0
python-dotenv>=1.0.0
```

## Testing

Run the test suite:

```bash
cd agents/investigation_engine
pytest test_investigation_engine.py -v
```

The test suite includes:
- Evidence loading tests
- Timeline generation tests
- Malware explanation tests
- Victim impact analysis tests
- Exfiltration analysis tests
- Recommendation generation tests
- Summary generation tests
- Full workflow integration tests

## Configuration

The investigation engine uses the following environment variables:

- `GROQ_API_KEY`: API key for Groq LLM service (optional, fallback to template-based generation)
- `CHAIN_VERIFICATION_SECRET`: Secret key for HMAC chain signatures (optional, enables cryptographic verification)

## Features

### AI-Powered Analysis
- Uses Groq LLM for intelligent malware behavior explanation
- Graceful fallback to template-based generation when AI is unavailable
- Context-aware analysis based on all available evidence

### Comprehensive Timeline
- Chronological event tracking
- Severity-based prioritization
- Multi-source event correlation

### Risk Assessment
- Victim impact analysis
- Data exfiltration tracking
- Overall risk scoring

### Actionable Recommendations
- Prioritized action items
- Category-based organization
- Evidence-backed rationale

### Investigation-Ready Reports
- Plain-language summaries
- Key findings extraction
- Clear next steps

### Chain Verification ⭐ NEW
- **Cryptographic Integrity**: SHA256 hashing of all analysis steps
- **Tamper Detection**: Hash chain linking ensures any modification is detected
- **Chain of Custody**: HMAC signatures provide verifiable chain of custody
- **Comprehensive Validation**: Verifies all required analysis steps are present
- **Legal-Ready**: Provides court-verifiable evidence integrity
- **Flexible Operation**: Works with or without secret key (graceful degradation)

## Notes

- The investigation engine is designed to work with or without dynamic analysis data
- AI features are optional and will gracefully degrade if API keys are not available
- All analysis is performed in-memory with no external dependencies
- The engine follows the same patterns as other agents in the project
