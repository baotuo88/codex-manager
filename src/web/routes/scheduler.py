import logging
import asyncio
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ...config.settings import get_settings, update_settings

logger = logging.getLogger(__name__)
router = APIRouter()

class CPASchedulerConfig(BaseModel):
    check_enabled: bool
    check_interval: int
    test_url: str
    register_enabled: bool
    register_threshold: int
    register_batch_count: int

@router.get("/config")
async def get_cpa_scheduler_config():
    """获取CPA自动化配置"""
    settings = get_settings()
    return {
        "check_enabled": settings.cpa_auto_check_enabled,
        "check_interval": settings.cpa_auto_check_interval,
        "test_url": settings.cpa_auto_check_test_url,
        "register_enabled": settings.cpa_auto_register_enabled,
        "register_threshold": settings.cpa_auto_register_threshold,
        "register_batch_count": settings.cpa_auto_register_batch_count,
    }

@router.post("/config")
async def update_cpa_scheduler_config(request: CPASchedulerConfig):
    """保存CPA自动化配置"""
    update_settings(
        cpa_auto_check_enabled=request.check_enabled,
        cpa_auto_check_interval=request.check_interval,
        cpa_auto_check_test_url=request.test_url,
        cpa_auto_register_enabled=request.register_enabled,
        cpa_auto_register_threshold=request.register_threshold,
        cpa_auto_register_batch_count=request.register_batch_count,
    )
    return {"success": True, "message": "定时任务配置已保存"}

@router.post("/trigger")
async def trigger_cpa_scheduler_check():
    """手动触发一次 CPA 检查并返回结果日志"""
    from ...core.scheduler import check_cpa_services_job
    
    manual_logs = []
    try:
        loop = asyncio.get_event_loop()
        # We run it in executor, but wait for it.
        await loop.run_in_executor(None, check_cpa_services_job, manual_logs)
        return {"success": True, "logs": manual_logs, "message": "检查执行完毕！"}
    except Exception as e:
        return {"success": False, "logs": manual_logs, "message": str(e)}
