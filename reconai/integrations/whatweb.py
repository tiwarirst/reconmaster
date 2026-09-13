"""WhatWeb adapter."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from reconai.core.executor.result import CommandResult
from reconai.integrations.base import ToolAdapter


class WhatWebAdapter(ToolAdapter):
    name = "whatweb"

    async def is_available(self) -> bool:
        avail, _ = await self.runner.check_tool(self.name)
        return avail

    def build_command(self, **kwargs: Any) -> list[str]:
        url = kwargs.get("url", "")
        # Use log-json output which is easier to parse
        self.tmp_out = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp_out.close()
        
        return ["whatweb", "--color=NEVER", f"--log-json={self.tmp_out.name}", "-a", "1", url]

    def parse(self, result: CommandResult) -> list[dict[str, Any]]:
        techs = []
        try:
            path = Path(self.tmp_out.name)
            if path.exists() and path.stat().st_size > 0:
                with open(path) as f:
                    data = json.load(f)
                    
                if isinstance(data, list) and len(data) > 0:
                    plugins = data[0].get("plugins", {})
                    for plugin_name, plugin_data in plugins.items():
                        # Skip generic plugins that don't indicate technology stack
                        if plugin_name in ("Country", "IP", "Title", "X-UA-Compatible", "Meta-Author"):
                            continue
                            
                        version = ""
                        if "version" in plugin_data:
                            versions = plugin_data["version"]
                            if isinstance(versions, list) and versions:
                                version = str(versions[0])
                        
                        techs.append({
                            "name": plugin_name,
                            "version": version,
                            "confidence": 100.0,
                        })
        except Exception:
            pass
        finally:
            path = Path(self.tmp_out.name)
            if hasattr(self, 'tmp_out') and path.exists():
                path.unlink(missing_ok=True)
                
        return techs
