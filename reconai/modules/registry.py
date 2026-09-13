"""Module registry for dynamic discovery and instantiation.

Modules register themselves using the @register_module decorator.
The orchestrator can then discover and run them without hardcoding dependencies.
"""
from __future__ import annotations

from typing import Type

from reconai.modules.base import ReconModule, ModuleConfig


class ModuleRegistry:
    """Central registry of all available modules."""

    _modules: dict[str, Type[ReconModule]] = {}

    @classmethod
    def register(cls, module_class: Type[ReconModule]) -> Type[ReconModule]:
        """Register a module class."""
        if not hasattr(module_class, "config") or not isinstance(module_class.config, ModuleConfig):
            raise ValueError(f"Module {module_class.__name__} must define a 'config' attribute of type ModuleConfig")

        name = module_class.config.name
        if name in cls._modules:
            raise ValueError(f"Module '{name}' is already registered")

        cls._modules[name] = module_class
        return module_class

    @classmethod
    def get(cls, name: str) -> Type[ReconModule]:
        """Get a module class by name."""
        if name not in cls._modules:
            raise KeyError(f"Module '{name}' not found in registry")
        return cls._modules[name]

    @classmethod
    def get_all(cls) -> dict[str, Type[ReconModule]]:
        """Get all registered modules."""
        return cls._modules.copy()

    @classmethod
    def get_by_category(cls, category: str) -> list[Type[ReconModule]]:
        """Get all modules in a specific category."""
        return [m for m in cls._modules.values() if m.config.category == category]


def register_module(module_class: Type[ReconModule]) -> Type[ReconModule]:
    """Decorator to register a module."""
    return ModuleRegistry.register(module_class)
