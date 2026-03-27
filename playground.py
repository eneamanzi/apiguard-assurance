from datetime import UTC, datetime

# --- IMPORTIAMO FISICAMENTE TUTTI E 7 I TUOI FILE ---
from src.config.schema import ToolConfig  # 1. schema.py
from src.core.client import SecurityClient  # 2. client.py
from src.core.context import ROLE_ADMIN, TargetContext, TestContext  # 3. context.py
from src.core.dag import DAGScheduler  # 4. dag.py
from src.core.evidence import EvidenceStore  # 5. evidence.py
from src.core.exceptions import SecurityClientError  # 6. exceptions.py
from src.core.models import (  # 7. models.py
    AttackSurface,
    EndpointRecord,
    EvidenceRecord,
    TestStrategy,
)


def main() -> None:
    print("--- INIZIO VERIFICA SISTEMA COMPLETO ---\n")

    # 1. Testiamo i Context (context.py)
    print("[1/6] Verifico i Context...")
    target = TargetContext(
        base_url="http://localhost:8000/",  # type: ignore[arg-type]
        openapi_spec_url="http://localhost:8000/api/swagger",  # type: ignore[arg-type]
        admin_api_url="http://localhost:8001",  # type: ignore[arg-type]
    )
    assert target.endpoint_base_url() == "http://localhost:8000", "Errore nello slash!"

    ctx = TestContext()
    ctx.set_token(ROLE_ADMIN, "super-secret-jwt-token")  # noqa: S106
    assert ctx.has_token(ROLE_ADMIN), "Il token non è stato salvato!"

    # 2. Testiamo l'Evidence Store (evidence.py e models.py)
    print("[2/6] Verifico l'Evidence Store...")
    store = EvidenceStore()
    record = EvidenceRecord(
        record_id="1.1_001",
        timestamp_utc=datetime.now(UTC),
        request_method="get",
        request_url=f"{target.endpoint_base_url()}/users",
        request_headers={"Authorization": "Bearer abc"},  # noqa: S106
        response_status_code=401,
        response_headers={},
        is_pinned=False,
    )
    store.add_fail_evidence(record)
    assert store.record_count == 1
    assert record.request_method == "GET", "Il validator del metodo non ha funzionato!"

    # 3. Testiamo il DAG Scheduler (dag.py)
    print("[3/6] Verifico il Motore DAG...")
    scheduler = DAGScheduler()
    deps: dict[str, list[str]] = {
        "Test_A": [],
        "Test_B": ["Test_A"],
        "Test_C": ["Test_A", "Test_B"],
    }
    active: set[str] = {"Test_A", "Test_B", "Test_C"}
    batches = scheduler.build_schedule(deps, active)
    assert len(batches) == 3

    # 4. Testiamo lo Schema di Configurazione (schema.py)
    print("[4/6] Verifico lo Schema Pydantic...")
    config_mock: dict[str, object] = {
        "target": {
            "base_url": "http://localhost:8000",
            "openapi_spec_url": "http://localhost:8000/swagger",
        },
        "execution": {"strategies": ["BLACK_BOX", "WHITE_BOX"]},
    }
    config = ToolConfig.model_validate(config_mock)
    assert TestStrategy.BLACK_BOX in config.execution.strategies

    # 5. Testiamo la nuova AttackSurface (models.py)
    print("[5/6] Verifico la nuova AttackSurface...")
    surface = AttackSurface(
        spec_title="Test API",
        endpoints=[
            EndpointRecord(path="/api/public", method="GET", requires_auth=False),
            EndpointRecord(path="/api/private", method="POST", requires_auth=True),
        ],
    )
    assert len(surface.get_public_endpoints()) == 1, "Il filtro public non va!"

    # 6. Testiamo il SecurityClient (client.py e exceptions.py)
    print("[6/6] Verifico il SecurityClient (Chiamata di Rete)...")
    try:
        with SecurityClient(
            base_url="http://localhost:9999",  # Porta inventata per farlo fallire apposta
            connect_timeout=0.1,
            max_retry_attempts=2,
        ) as client:
            print("      Tento di connettermi a una porta chiusa (mi aspetto un fallimento)...")
            client.request("GET", "/test", test_id="0.0")
            assert False, "Il client doveva fallire, ma non lo ha fatto!"

    except SecurityClientError as e:
        print(f"      ✅ Fallimento intercettato correttamente! Dettaglio: {e}")
        assert e.attempt_count == 2, "I tentativi di retry non sono stati 2!"

    print("\n✅ TUTTO VERDE! Ora abbiamo testato fisicamente TUTTI I FILE.")
    print("--- FINE VERIFICA ---")


if __name__ == "__main__":
    main()
