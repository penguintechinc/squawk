"""
Alias module for backward compatibility.
Re-exports IOCManager from ioc_ingestion_service.
"""

from ioc_ingestion_service import IOCManager

__all__ = ["IOCManager"]
