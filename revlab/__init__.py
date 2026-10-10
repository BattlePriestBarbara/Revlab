"""RevLab - an AI/MCP-driven reverse-engineering workbench.

RevLab wraps two mature engines behind one protocol-shaped interface:

* **Ghidra** (static: disassembly, decompilation, cross references) is used
  either through a long-lived MCP server process or through ``analyzeHeadless``;
* **Frida** (dynamic: hooks, tracing, memory access) is driven from the host
  through the Python binding.

Everything the tool learns is written to a *workspace* as JSON evidence, so a
report can be regenerated later instead of being retyped. The core package has
**no third-party dependency** (standard library only); the Frida, MCP and
PyGhidra integrations are optional adapters that report clearly when they are
missing.
"""

__version__ = "0.2.0"

__all__ = ["__version__"]
