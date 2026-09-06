from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from .expressions import Expr

class Op(Enum):
    ASSIGN = auto()
    CALL = auto()
    RET = auto()
    UNKN = auto()

@dataclass
class IRInst:
    op: Op
    dst: Optional[Expr] = None
    src: Optional[Expr] = None
    target: Optional[int] = None
    args: list = field(default_factory=list)
    raw: Optional[str] = None

    def __str__(self) -> str:
        if self.op == Op.ASSIGN:
            return f"{self.dst} = {self.src}"
        if self.op == Op.CALL:
            args = ", ".join(str(a) for a in self.args)
            if self.dst is not None:
                return f"{self.dst} = CALL({hex(self.target)}, [{args}])"
            return f"CALL({hex(self.target)}, [{args}])"
        if self.op == Op.RET:
            if self.src is not None:
                return f"RET({self.src})"
            return "RET"
        return f"UNKN({self.raw})"