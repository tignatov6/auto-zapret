# Auto-Zapret Project Context

## Project Overview

**Project Name:** Auto-Zapret (Адаптивная мультистратегическая маршрутизация)

**Purpose:** This project contains the conceptual design for an adaptive, self-configuring DPI circumvention system. Unlike static solutions (e.g., traditional Zapret configurations), this system automatically selects and applies optimal bypass strategies for each specific domain in real-time.

**Core Problem Addressed:**
- Current DPI bypass solutions work on static rules - users must manually select one strategy for all traffic
- Universal strategies may fail on specific sites or be too slow
- Manual configuration requires time and technical expertise when sites stop working

**Proposed Solution:** A three-module system that:
1. **Monitor** - Detects connection failures/timeouts for specific domains
2. **Analyzer** - Tests available strategies to find working ones for problematic domains
3. **Executor** - Dynamically applies the working strategy without service interruption

## Directory Contents

| File | Description |
|------|-------------|
| `idea.md` | Core concept document describing the adaptive multi-strategic routing architecture, problem statement, solution design, and user scenarios |
| `QWEN.md` | This context file for AI assistant interactions |

## Key Architectural Concepts

### System Requirements
1. **Strategy Independence** - Engine must handle multiple rules for different domain lists simultaneously (via `--new` in Zapret config)
2. **Hot Application** - Adding domains to running strategies without full service restart (e.g., HUP signal or API)
3. **Background Testing** - Strategy selection must not block internet or overload CPU

### Workflow
```
User visits blocked site → Monitor detects timeout → 
Analyzer tests strategies → Executor applies working rule → 
Site accessible (no user intervention needed)
```

## Development Status

**Current Phase:** Conceptual design / Documentation

**Next Steps (Inferred):**
- Implementation planning
- Technology stack selection
- Prototype development
- Integration with Zapret's nfqws/winws

## Usage

This directory serves as the documentation and design hub for the Auto-Zapret concept. The `idea.md` file contains the complete architectural specification including:
- Problem definition
- Solution architecture (Monitor, Analyzer, Executor modules)
- Implementation requirements
- User experience scenarios

## Related Technologies

- **Zapret** - DPI circumvention framework (base technology)
- **nfqws/winws** - Zapret components for strategy management
- **Hostlist management** - Dynamic domain-to-strategy mapping
