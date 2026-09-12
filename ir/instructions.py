from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from .expressions import Expr

class Op(Enum):
    ASSIGN = auto()
    CALL = auto()
    RET = auto()
    CMP = auto()
    BRANCH = auto()
    UNKN = auto()

@dataclass
class IRInst:
    op: Op
    dst: Optional[Expr] = None
    src: Optional[Expr] = None
    target: Optional[int] = None
    args: list = field(default_factory=list)
    raw: Optional[str] = None
    cond: Optional[Expr] = None
    indirect: Optional[Expr] = None
    addr: int = 0

    def __str__(self) -> str:
        if self.op == Op.ASSIGN:
            return f"{self.dst} = {self.src}"
        if self.op == Op.CALL:
            args = ", ".join(str(a) for a in self.args)
            if self.indirect is not None:
                callee = f"*({self.indirect})"
            else:
                callee = hex(self.target) if self.target is not None else "?"
            if self.dst is not None:
                return f"{self.dst} = CALL({callee}, [{args}])"
            return f"CALL({callee}, [{args}])"
        if self.op == Op.RET:
            if self.src is not None:
                return f"RET({self.src})"
            return "RET"
        if self.op == Op.CMP:
            return f"CMP {self.dst}, {self.src}"
        if self.op == Op.BRANCH:
            if self.cond is not None:
                return f"IF {self.cond} GOTO {hex(self.target)}"
            return f"GOTO {hex(self.target)}"
        return f"UNKN({self.raw})"