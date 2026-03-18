from dataclasses import dataclass


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    severity: str
    message: str

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
        }
