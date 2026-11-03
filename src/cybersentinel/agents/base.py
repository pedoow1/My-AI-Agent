from abc import ABC, abstractmethod
from typing import List, Dict, Any
from ..models import Finding

class Agent(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def run(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        """Execute the agent's security task on the target."""
        pass
