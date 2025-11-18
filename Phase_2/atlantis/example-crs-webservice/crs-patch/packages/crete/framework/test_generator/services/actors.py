from typing import List

from crete.atoms.detection import Detection
from crete.framework.test_generator.contexts import TestGenerationContext
from crete.framework.test_generator.models import TestGenerationResult
from crete.framework.test_generator.protocols import TestGeneratorProtocol


class TestGeneratorActor:
    def __init__(self, generators: List[TestGeneratorProtocol]):
        self.generators = generators

    def generate(
        self, context: TestGenerationContext, detection: Detection
    ) -> TestGenerationResult | None:
        for generator in self.generators:
            result = generator.generate(context, detection)
            if result and result.status == "success":
                return result
        else:
            return None
