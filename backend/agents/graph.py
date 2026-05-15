"""
AEGIS SOC — LangGraph StateGraph Wiring
Connects all 6 agents into a state machine with conditional edges.

Flow:
  START → triage → enrichment → investigation → decision
    → "auto_remediate"    → remediation → reporting → END
    → "request_approval"  → PAUSE (human input) → remediation → reporting → END
    → "monitor"           → reporting → END
"""
from langgraph.graph import StateGraph, END
from backend.agents.state import SOCState
from backend.agents.triage import triage_node
from backend.agents.enrichment import parallel_enrichment_node
from backend.agents.investigation import investigation_node
from backend.agents.decision import decision_node
from backend.agents.remediation import remediation_node
from backend.agents.reporting import reporting_node


def route_after_decision(state: SOCState) -> str:
    """Conditional edge: route based on decision agent output."""
    decision = state.get("decision", "monitor")
    if decision == "auto_remediate":
        return "remediation"
    elif decision == "request_approval":
        # Pipeline pauses here — will be resumed via API call
        return "awaiting_approval"
    else:
        # Monitor only — skip remediation, go straight to reporting
        return "reporting"


def build_graph() -> StateGraph:
    """Build and compile the AEGIS SOC agent pipeline graph."""
    graph = StateGraph(SOCState)

    # ── Add nodes (each is an agent function) ──
    graph.add_node("triage", triage_node)
    graph.add_node("enrichment", parallel_enrichment_node)
    graph.add_node("investigation", investigation_node)
    graph.add_node("decision_maker", decision_node)
    graph.add_node("remediation", remediation_node)
    graph.add_node("reporting", reporting_node)

    # ── Linear edges ──
    graph.set_entry_point("triage")
    graph.add_edge("triage", "enrichment")
    graph.add_edge("enrichment", "investigation")
    graph.add_edge("investigation", "decision_maker")

    # ── Conditional edge after decision ──
    graph.add_conditional_edges(
        "decision_maker",
        route_after_decision,
        {
            "remediation": "remediation",
            "reporting": "reporting",
            "awaiting_approval": END,  # Pauses — resumed manually
        }
    )

    # ── Final edges ──
    graph.add_edge("remediation", "reporting")
    graph.add_edge("reporting", END)

    return graph


def compile_graph():
    """Build, compile, and return the runnable graph."""
    graph = build_graph()
    return graph.compile()


# ── Pre-compiled graph singleton ──
compiled_graph = None


def get_graph():
    """Get or create the compiled graph singleton."""
    global compiled_graph
    if compiled_graph is None:
        compiled_graph = compile_graph()
    return compiled_graph
