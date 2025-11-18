# from pathlib import Path

# import pytest

# from crete.atoms.action import HeadAction
# from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder


# @pytest.mark.skip(reason="h3-42515790 cp pr is in progress")
# def test_undefined_sanitizer(
#     detection_c_h3_42515790_cpv_0: tuple[Path, Path],
# ):
#     context, detection = AIxCCContextBuilder(
#         *detection_c_h3_42515790_cpv_0,
#     ).build(
#         previous_action=HeadAction(),
#     )

#     assert context["sanitizer_name"] == "undefined"
#     assert len(detection.blobs) == 1
#     assert detection.blobs[0].sanitizer_name == "undefined"
#     assert detection.blobs[0].harness_name == "fuzzerHierarchy"
#     assert detection.project_name == "aixcc/c/h3-42515790"

#     environment = context["pool"].use(context, "CLEAN")
#     assert environment is not None

#     environment.restore(context)
#     environment.build(context)

#     try:
#         _, _ = environment.run_pov(context, detection)
#         pytest.fail("run_pov should have raised an exception but it didn't")
#     except Exception as e:
#         assert "SUMMARY: UndefinedBehaviorSanitizer:" in str(e)
