# JAVA CONTEXT PARSER LOGIC STRUCTURE

## 1. Global Header Extraction
- **Scope**: Lines 1 to ~50 (or until first class definition).
- **Target**: 
    - `package` declaration.
    - All `import` statements.
- **Reason**: Identifies external libraries and security frameworks.

## 2. Method Boundary Discovery
- **Input**: `target_line` (from Semgrep JSON).
- **Upward Search (Method Start)**:
    - Scan backwards from `target_line`.
    - Stop at the first line containing access modifiers (`public`, `private`, `protected`) + parentheses `()`.
    - Extract `method_signature`.
- **Downward Search (Method End)**:
    - Start at `method_signature` line.
    - Implement a "Brace Counter":
        - Increment for `{`, decrement for `}`.
        - Start at 0, stop when counter returns to 0 after first `{`.
    - Identify `end_line`.

## 3. Semantic Extraction Logic
- **Condition**: Calculate `method_length = end_line - start_line`.
- **Case A: Standard Method (length <= 100 lines)**:
    - Extract entire method block from `start_line` to `end_line`.
- **Case B: Extreme Method (length > 100 lines)**:
    - **Header**: Signature + first 10 lines of body.
    - **Separator**: Add `// ... [code skipped] ...` comment.
    - **Window**: 50 lines before `target_line` and 50 lines after.
    - **Footer**: Closing brace of the method.

## 4. Normalization & Tagging
- **Line Numbering**: Prefix every line with `NNN: ` for LLM referencing.
- **Vulnerability Marker**: Inject `>>` or `[VULNERABILITY]` tag at the specific `target_line`.
- **Formatting**: Wrap code in Markdown-style triple backticks (```java).

## 5. Final Output Object
- **JSON Structure**:
    - `meta`: CWE, Semgrep message, file path.
    - `global_context`: Imports and package info.
    - `code_context`: The processed method block.