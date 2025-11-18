from typing import Protocol

from crete.atoms.detection import Detection
from crete.framework.test_generator.contexts import TestGenerationContext
from crete.framework.test_generator.models import TestGenerationResult


class TestGeneratorProtocol(Protocol):
    def generate(
        self, context: TestGenerationContext, detection: Detection
    ) -> TestGenerationResult | None: ...
