"""Waygate 백업/마이그레이션 API (Phase 3) — 사용자 JWT + 서버 소유권 검증.

export/import 모두 POST 다: 패스프레이즈를 받고 래핑된 시크릿을 방출/소비하므로 GET 이 아니다.
동일 prefix(/api/v1/waygate/servers)에 마운트되며 상대 경로 /{server_id}/export|import 로 겹치지 않는다.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from waygate.auth import require_token
from waygate.db import is_db_available
from waygate.models.schemas import WaygateExportRequest, WaygateImportRequest, WaygateImportResult
from waygate.services import waygate_db, waygate_migration
from waygate.services.migration import WaygateMigrationError

router = APIRouter()
_logger = logging.getLogger(__name__)


def _require_db() -> None:
    if not is_db_available():
        raise HTTPException(status_code=503, detail="DB를 사용할 수 없습니다")


async def _get_owned_server(project_id: str, server_id: str) -> dict:
    server = await waygate_db.get_server(project_id, server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Waygate 서버를 찾을 수 없습니다")
    return server


@router.post("/{server_id}/export")
async def export_waygate_server(
    server_id: str,
    body: WaygateExportRequest,
    token_info: dict = Depends(require_token),
):
    """서버의 클라이언트+네트워크 연결을 패스프레이즈로 래핑한 번들 JSON 으로 내보낸다.

    응답은 no-store 로 캐싱을 막는다(래핑됐지만 시크릿 파생 데이터 포함).
    """
    _require_db()
    project_id = token_info["project_id"]
    server = await _get_owned_server(project_id, server_id)
    try:
        bundle = await waygate_migration.export_bundle(project_id, server, body.passphrase)
    except WaygateMigrationError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail) from e
    filename = f"{server.get('name') or 'waygate'}-export.json"
    return JSONResponse(
        content=bundle,
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.post("/{server_id}/import", response_model=WaygateImportResult)
async def import_waygate_server(
    server_id: str,
    body: WaygateImportRequest,
    token_info: dict = Depends(require_token),
):
    """번들의 클라이언트를 (이미 프로비저닝된) 대상 서버로 재생성한다."""
    _require_db()
    project_id = token_info["project_id"]
    server = await _get_owned_server(project_id, server_id)
    try:
        bundle = waygate_migration.parse_bundle(body.bundle)
        result = await waygate_migration.import_bundle(project_id, server, bundle, body.passphrase)
    except WaygateMigrationError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail) from e
    return WaygateImportResult(**result)
