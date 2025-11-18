from typing import Literal

from loguru import logger

from sarif.context import SarifCacheManager, SarifEnv
from sarif.models import CP, CodeLocation, Function, SarifInfo
from sarif.tools.introspector.core import _analyse_end_to_end
from sarif.utils.cache import cache_method_with_attrs
from sarif.validator.reachability.base import BaseReachabilityAnalyser


class IntrospectorReachabilityAnalyser(BaseReachabilityAnalyser):
    SUPPORTED_MODES = Literal["forward"]

    def __init__(self, cp: CP):
        super().__init__(cp)

        self.target_dir = SarifEnv().src_dir

        self.out_dir = SarifEnv().out_dir / "introspector"

        if not self.out_dir.exists():
            self.out_dir.mkdir(parents=True)

    @cache_method_with_attrs(mem=SarifCacheManager().memory, attr_names=["cp"])
    def get_all_reachable_funcs(self) -> list[Function]:
        introspector_project = _analyse_end_to_end(
            oss_fuzz_lang=self.cp.oss_fuzz_lang,
            target_dir=self.target_dir,
            out_dir=self.out_dir,
            harness_paths=[harness.path.as_posix() for harness in self.cp.harnesses],
            analyses_to_run=[],
        )

        proj_profile = introspector_project.proj_profile
        functions = proj_profile.get_all_functions()

        reachable_functions: list[Function] = []
        for name, func in functions.items():
            reachable_functions.append(
                # TODO: add reached_by_fuzzers??
                # ReachableFunction(
                #     func_name=name,
                #     file_name=func.function_source_file,
                #     reached_by_fuzzers=func.reached_by_fuzzers,
                # )
                Function(
                    func_name=name,
                    file_name=func.function_source_file,
                )
            )

        return reachable_functions

    def reachability_analysis(
        self,
        sink_location: CodeLocation,
        *,
        mode: SUPPORTED_MODES | None = None,
    ) -> bool:
        reachable_functions = self.get_all_reachable_funcs()

        return self._check_reachable(reachable_functions, sink_location.function)
