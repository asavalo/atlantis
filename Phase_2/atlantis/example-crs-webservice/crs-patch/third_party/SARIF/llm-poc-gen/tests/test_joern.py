import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from vuli.common.setting import Setting
from vuli.joern import CPG, Joern, JoernServer

counter: int = 0
real_query = JoernServer.query


@patch.object(JoernServer, "query")
def test_set_cpg_fail(mock):

    def mock_query(*args, **kwargs) -> tuple[dict, bool]:
        global counter
        try:
            script: str = args[0]
            if "importCpg" in script:
                if counter == 0:
                    counter += 1
                    return (
                        {
                            "success": True,
                            "stdout": "\u001b[33mval\u001b[0m \u001b[36mres0\u001b[0m: \u001b[32mOption\u001b[0m[io.shiftleft.codepropertygraph.Cpg] = None\n",
                            "uuid": "13eb4187-7c29-4143-9a9a-94e7f6055332",
                        },
                        True,
                    )
                else:
                    return (
                        {
                            "success": True,
                            "stdout": "\u001b[33mval\u001b[0m \u001b[36mres0\u001b[0m: \u001b[32mOption\u001b[0m[io.shiftleft.codepropertygraph.Cpg] = Some(value = Cpg (Graph [1315999 nodes]))\n",
                            "uuid": "50547ada-c382-4318-82df-2923ffa95c60",
                        },
                        True,
                    )
            res = real_query(Joern()._server, *args, **kwargs)
            return res
        except Exception as e:
            raise e

    mock.side_effect = mock_query
    output_dir = tempfile.TemporaryDirectory()
    Setting().load(
        Path(os.getenv("JOERN_DIR")),
        Path(os.getenv("JOERN_DIR")),
        Path(output_dir.name),
        Path(__file__).parent.parent,
        True,
    )
    cpg = CPG(Setting().cpg_path)
    Joern().set_path(Setting().joern_cli_path)
    try:
        # If any exception raises here, test will fail.
        Joern().run_server(cpg, Setting().query_path, Setting().semantic_dir)
    finally:
        Joern().close_server()
