"""Authenticated current-native policy discovery, without a leaf admission gate."""

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel

from waygate import policy
from waygate.auth import require_token

router = APIRouter()


class PolicyCapabilities(BaseModel):
    service: str
    capabilities: list[str]
    actions: list[str]


@router.get("/capabilities", response_model=PolicyCapabilities)
def get_policy_capabilities(response: Response, token_info: dict = Depends(require_token)):
    response.headers["Cache-Control"] = "no-store"
    return policy.capabilities(token_info)
