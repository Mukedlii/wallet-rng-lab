"""Traceback triage metadata; this module never changes source files."""
import re
FRAME=re.compile(r'File "([^"]+)", line (\d+), in ([^\n]+)')
def analyze_traceback(traceback_text):
    frames=[{"file":m.group(1),"line":int(m.group(2)),"function":m.group(3).strip()} for m in FRAME.finditer(traceback_text or "")]
    last=frames[-1] if frames else None
    return {"frames":frames,"affected_file":last["file"] if last else None,
            "affected_line":last["line"] if last else None,
            "affected_function":last["function"] if last else None,
            "patch_status":"manual_review_required","auto_apply":False}
