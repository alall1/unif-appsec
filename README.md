# minisast

### scanner.py
- finds all files, recursively walking through directory if needed
- calls analyzer.py and aggregates file findings
- loads configs (when added)

### analyzer.py
- contains AST visitor and security analysis logic
- called by scanner.py -> returns findings for a file
- shouldn't walk directories or open files, just scan one file for vulnerabilities
