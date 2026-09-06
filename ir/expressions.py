from __future__ import annotations
from dataclasses import dataclass

class Expr:
    pass

@dataclass
class Var(Expr):
    name: str
    size: int = 32

    def __str__(self) -> str:
        return self.name

@dataclass
class Const(Expr):
    val: int
    size: int = 32

    def __str__(self) -> str:
        if self.val < 0:
            return hex(self.val & ((1 << self.size) - 1))
        return hex(self.val)

@dataclass
class BinOp(Expr):
    op: str
    lhs: Expr
    rhs: Expr
    size: int = 32

    def __str__(self) -> str:
        return f"({self.lhs} {self.op} {self.rhs})"

@dataclass
class Mem(Expr):
    addr: Expr
    size: int = 32

    def __str__(self) -> str:
        return f"*({self.addr})"