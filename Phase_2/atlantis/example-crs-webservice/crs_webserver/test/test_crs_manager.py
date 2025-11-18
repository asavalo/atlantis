import os
import sys
from my_crs.crs_manager.crs_manager import CRSManager
from my_crs.task_server.models.types import (
    Task,
    TaskType,
    TaskDetail,
)
from uuid import UUID

mgr = CRSManager()

proj = sys.argv[1]
post = sys.argv[2]
task_id = UUID("00000000-0000-0000-0000-00000000000" + post)
name = proj.split("/")[-1]
os.system(
    f"rm -rf /tarball-fs/test/repo.tar.gz; ln -s /tarball-fs/test/{name}.tar.gz /tarball-fs/test/repo.tar.gz"
)
detail = TaskDetail(
    deadline=0,
    focus="",
    harnesses_included=True,
    metadata={},
    project_name=proj,
    source=[],
    task_id=task_id,
    type=TaskType.TaskTypeFull,
)
msg_id = UUID("00000000-0000-0000-0000-00000000000" + post)
task = Task(message_id=msg_id, message_time=0, tasks=[detail])

mgr.process_task(task)
