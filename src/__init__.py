"""
Core package for Apoliak Vitals.

Submodules are resolved lazily so that importing one layer does not drag in the others:
``from src import i18n`` must not execute the collector stack, and ``src.history`` — the only
module that may write outside an explicit export — stays isolable and opt-in.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

#: The single source of truth for the application version. main.py, gui.py and report.py all
#: read it from here; pyproject.toml and version_info.txt are checked against it by a test,
#: because a build file cannot import Python.
__version__ = "2.1.0"

#: Public name -> submodule that provides it.
_EXPORTS: dict[str, str] = {
    "analyze_pc": "analyzer",
    "MissingDependencyError": "analyzer",
    "get_system_info": "analyzer",
    "get_cpu_info": "analyzer",
    "get_ram_info": "analyzer",
    "get_disk_info": "analyzer",
    "get_partitions": "analyzer",
    "get_battery": "analyzer",
    "get_network": "analyzer",
    "get_process_count": "analyzer",
    "get_temp_size": "analyzer",
    "get_temp_locations": "analyzer",
    "get_uptime": "analyzer",
    "get_system_drive": "analyzer",
    "top_processes": "processes",
    "calculate_health_details": "health_score",
    "calculate_health_score": "health_score",
    "get_score_status": "health_score",
    "score_rules": "health_score",
    "generate_recommendations": "recommendations",
    "build_report": "report",
    "export_report": "report",
    "render": "exporters",
    "export": "exporters",
    "snapshot_to_dict": "exporters",
    "FORMATS": "exporters",
    "get_translator": "i18n",
    "detect_language": "i18n",
    "LANGUAGES": "i18n",
}

_SUBMODULES = (
    "analyzer",
    "exporters",
    "health_score",
    "history",
    "i18n",
    "models",
    "processes",
    "recommendations",
    "report",
    "utils",
    "win_registry",
)

if TYPE_CHECKING:  # Keeps editors and type checkers aware of the real names.
    from .analyzer import (  # noqa: F401
        MissingDependencyError,
        analyze_pc,
        get_battery,
        get_cpu_info,
        get_disk_info,
        get_network,
        get_partitions,
        get_process_count,
        get_ram_info,
        get_system_drive,
        get_system_info,
        get_temp_locations,
        get_temp_size,
        get_uptime,
    )
    from .exporters import FORMATS, export, render, snapshot_to_dict  # noqa: F401
    from .health_score import (  # noqa: F401
        calculate_health_details,
        calculate_health_score,
        get_score_status,
        score_rules,
    )
    from .i18n import LANGUAGES, detect_language, get_translator  # noqa: F401
    from .processes import top_processes  # noqa: F401
    from .recommendations import generate_recommendations  # noqa: F401
    from .report import build_report, export_report  # noqa: F401


def __getattr__(name: str) -> Any:
    from importlib import import_module

    if name in _SUBMODULES:
        return import_module(f".{name}", __name__)
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(import_module(f".{module_name}", __name__), name)


def __dir__() -> list[str]:
    return sorted({*_EXPORTS, *_SUBMODULES, "__version__"})


__all__ = [*sorted(_EXPORTS), *_SUBMODULES, "__version__"]
