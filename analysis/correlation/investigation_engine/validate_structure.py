"""
validate_structure.py — Validate the investigation engine structure without running it.

This script checks that all files are present and imports work correctly.
"""

import sys
from pathlib import Path

# Add repo root to path
_repo_root = str(Path(__file__).resolve().parents[2])
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)


def check_file_exists(filepath: str) -> bool:
    """Check if a file exists."""
    return Path(filepath).exists()


def check_module_import(module_path: str) -> bool:
    """Check if a module can be imported."""
    try:
        __import__(module_path)
        return True
    except ImportError as e:
        print(f"  ❌ Import failed: {e}")
        return False


def main():
    """Run validation checks."""
    print("=" * 80)
    print("Investigation Engine Structure Validation")
    print("=" * 80)
    
    base_path = Path(__file__).parent
    
    # Check required files
    print("\n📁 Checking required files...")
    required_files = [
        "__init__.py",
        "investigation_schema.py",
        "investigation_engine.py",
        "chain_verification.py",
        "requirements.txt",
        "test_investigation_engine.py",
        "test_chain_verification.py",
        "demo_investigation.py",
        "README.md",
    ]
    
    all_files_exist = True
    for filename in required_files:
        filepath = base_path / filename
        exists = check_file_exists(filepath)
        status = "✅" if exists else "❌"
        print(f"  {status} {filename}")
        if not exists:
            all_files_exist = False
    
    # Check module structure
    print("\n🔍 Checking module structure...")
    
    # Check if we can import (may fail due to missing dependencies)
    can_import = True
    try:
        import pydantic
    except ImportError:
        print("  ⚠️  pydantic not available - skipping import checks")
        can_import = False
    
    if can_import:
        # Check schema
        print("  Checking investigation_schema...")
        try:
            from agents.investigation_engine.investigation_schema import (
                InvestigationState,
                TimelineEvent,
                MalwareExplanation,
                VictimImpact,
                ExfiltrationAnalysis,
                Recommendation,
                InvestigationSummary,
            )
            print("  ✅ All schema classes imported successfully")
        except ImportError as e:
            print(f"  ❌ Schema import failed: {e}")
            all_files_exist = False
        
        # Check engine
        print("  Checking investigation_engine...")
        try:
            from agents.investigation_engine.investigation_engine import InvestigationEngine, run_investigation_workflow
            print("  ✅ InvestigationEngine imported successfully")
        except ImportError as e:
            print(f"  ❌ Engine import failed: {e}")
            all_files_exist = False
        
        # Check chain verification
        print("  Checking chain_verification...")
        try:
            from agents.investigation_engine.chain_verification import (
                ChainVerifier,
                ChainLink,
                VerificationResult,
                verify_chain,
                verify_integrity,
            )
            print("  ✅ Chain verification module imported successfully")
        except ImportError as e:
            print(f"  ❌ Chain verification import failed: {e}")
            all_files_exist = False
    else:
        print("  ⚠️  Skipping import checks (dependencies not installed)")
        print("  ℹ️  This is expected in externally-managed Python environments")
        print("  ℹ️  Install dependencies with: pip install -r agents/investigation_engine/requirements.txt")
    
    # Check orchestrator integration
    print("\n🔗 Checking orchestrator integration...")
    orchestrator_path = base_path.parent / "orchestrator" / "orchestrator.py"
    if check_file_exists(orchestrator_path):
        print("  ✅ orchestrator.py exists")
        # Check if investigation_engine is imported
        try:
            with open(orchestrator_path, 'r') as f:
                content = f.read()
                if "investigation_engine" in content:
                    print("  ✅ investigation_engine is referenced in orchestrator")
                else:
                    print("  ⚠️  investigation_engine might not be integrated")
        except Exception as e:
            print(f"  ⚠️  Could not read orchestrator.py: {e}")
    else:
        print("  ❌ orchestrator.py not found")
    
    # Check schema integration
    schema_path = base_path.parent / "orchestrator" / "schema.py"
    if check_file_exists(schema_path):
        print("  ✅ schema.py exists")
        try:
            with open(schema_path, 'r') as f:
                content = f.read()
                if "investigation_output" in content:
                    print("  ✅ investigation_output field added to OrchestratorState")
                else:
                    print("  ⚠️  investigation_output field might not be in schema")
        except Exception as e:
            print(f"  ⚠️  Could not read schema.py: {e}")
    else:
        print("  ❌ schema.py not found")
    
    # Summary
    print("\n" + "=" * 80)
    if all_files_exist:
        print("✅ All structure checks passed!")
        print("\nNote: To run the demo or tests, ensure dependencies are installed:")
        print("  pip install -r agents/investigation_engine/requirements.txt")
        print("\nOr use the Docker environment:")
        print("  docker-compose up backend")
    else:
        print("❌ Some structure checks failed. Please review the output above.")
    print("=" * 80)


if __name__ == "__main__":
    main()
