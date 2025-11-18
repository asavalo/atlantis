#!/usr/bin/env python3

import os
from pathlib import Path
import subprocess
import sys
from dataclasses import dataclass
from argparse import ArgumentParser
from typing import Optional
import random
import time
import json
import shutil
import yaml # sorry Kevin
from jinja2 import Environment, FileSystemLoader

PASSTHROUGH_ENV_VARS = [
    # Otel env vars
    "AIXCC_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "CRS_TASK_METADATA_JSON",
    "CRS_ACTION_CATEGORY",
    "AIXCC_LITELLM_HOSTNAME",
]

def parse_args():
    parser = ArgumentParser()
    parser.add_argument("command", nargs="?", choices=["run", "clean", "build", "push"], default="run")
    parser.add_argument("target", nargs="?", default="aixcc/cpp/example-libpng")
    parser.add_argument("harness", nargs="?")
    parser.add_argument("sanitizer", nargs="?")
    parser.add_argument("--tag", nargs="?", default="latest")
    parser.add_argument("--registry", nargs="?", default="ghcr.io/team-atlanta/crs-userspace")
    parser.add_argument("--profile", "-p", nargs="?", choices=["development", "evaluation", "postmortem"], default="development")

    return parser.parse_args()

args = parse_args()
crs_target_name = args.target
harness_name = args.harness
profile = args.profile
node_num = int(os.environ.get('NODE_NUM', '4')) # simulate multiple nodes (crs_scratch_space) in docker compose
node_cpu_cores = int(os.environ.get('NODE_CPU_CORES', os.cpu_count() / node_num)) # simulate multiple nodes in one machine
root = Path(__file__).parent.resolve()
crs_oss_fuzz_path = Path(os.environ.get('CRS_OSS_FUZZ_PATH', root / 'oss_fuzz'))
crs_target_src_path = Path(os.environ.get('CRS_TARGET_SRC_PATH', root / 'cp_root' / crs_target_name.replace('/', '_')))
crs_scratch_space = Path(os.environ.get('CRS_SCRATCH_SPACE', root / 'crs_scratch'))
shared_crs_space = Path(os.environ.get('SHARED_CRS_SPACE', root / 'shared-crs-fs'))
atlantis_large_data = Path(os.environ.get('ATLANTIS_LARGE_DATA', root / '_large_data'))
atlantis_artifacts = Path(os.environ.get('ATLANTIS_ARTIFACTS', root / 'artifacts'))
crs_build_cp_image = os.environ.get('CRS_BUILD_CP_IMAGE', 'false').lower() in {'true', '1'}
docker_config = Path(os.environ.get('DOCKER_CONFIG', root / 'docker-config.json'))

@dataclass
class RepoContext:
    harnesses: list[str]
    sanitizers: list[str]

def relative_to_safe(p1: Path, p2: Path) -> Path:
    try:
        return p1.relative_to(p2)
    except ValueError:
        return p1


def clone_cp_repo(oss_fuzz_path: Path, repo_path: Path, target_name: str) -> RepoContext:
    config_yaml = oss_fuzz_path / 'projects' / target_name / '.aixcc/config.yaml'
    config_yaml_tmp = oss_fuzz_path / 'projects' / target_name / '.aixcc/config.yaml.tmp'
    if config_yaml_tmp.exists():
        config_yaml_tmp.rename(config_yaml)
    project_yaml = oss_fuzz_path / 'projects' / target_name / 'project.yaml'
        
    if not config_yaml.exists():
        raise ValueError(f'Could not find {config_yaml}')
    
    if not project_yaml.is_file():
        raise ValueError(f'{project_yaml} does not exist')

    with open(config_yaml) as f:
        config_dict = yaml.safe_load(f)

    assert "harness_files" in config_dict, f'Unable to find harness_files key in {config_yaml}'
    all_harnesses = [elt for elt in config_dict["harness_files"]]
    harness_names = [elt["name"] for elt in all_harnesses]

    with open(project_yaml) as f:
        project_dict = yaml.safe_load(f)

    assert "sanitizers" in project_dict, f'Unable to find sanitizers key in {project_yaml}'
    sanitizers = project_dict["sanitizers"]

    ret = RepoContext(harnesses=harness_names, sanitizers=sanitizers)

    if not repo_path.is_dir():
        assert "main_repo" in project_dict, f'Unable to find main_repo key in {project_yaml}'
        repo_url = project_dict["main_repo"]

        repo_path.mkdir(parents=True, exist_ok=True)
        subprocess.run(['git', 'clone', repo_url, str(repo_path)], check=True)

    if "delta_mode" in config_dict:
        prepatch_dir = root / "crs_scratch_0/prepatch"
        shutil.rmtree(prepatch_dir, ignore_errors=True)
        prepatch_dir.parent.mkdir(exist_ok=True)
        shutil.copytree(repo_path, prepatch_dir)
        commit = ""
        for thing in config_dict["delta_mode"]:
            if "base_commit" in thing:
                commit = thing["base_commit"]
                break
        if commit:
            subprocess.run(['git', 'checkout', commit], cwd=str(prepatch_dir))


    if "full_mode" not in config_dict or "base_commit" not in config_dict["full_mode"]:
        raise ValueError(f'Using main branch, unable to find base_commit key in {config_yaml}')

    commit = config_dict["full_mode"]["base_commit"]
    subprocess.run(['git', 'checkout', commit], cwd=str(repo_path))

    return ret

def build_cp(oss_fuzz_path: Path, target_name: str) -> None:
    # Build the CP image
    subprocess.run(
        [
            sys.executable,
            'infra/helper.py',
            'build_image',
            '--no-pull',
            target_name,
        ],
        cwd=oss_fuzz_path,
    )

def clone_oss_fuzz_repo():
    if not crs_oss_fuzz_path.is_dir():
        subprocess.run(['git', 'clone', 'git@github.com:Team-Atlanta/oss-fuzz.git', str(crs_oss_fuzz_path)])
        print(f'Cloned oss-fuzz benchmarks repo to {crs_oss_fuzz_path}.')

    if not (crs_oss_fuzz_path / 'projects' / crs_target_name).is_dir():
        print(f'\x1b[31m\n [!] CP {crs_target_name} not found in {crs_oss_fuzz_path} -- exiting.\x1b[0m\n')
        exit(-1)

def setup_dirs(fake_oss_fuzz: bool=False):
    dirs = [
        crs_scratch_space,
        shared_crs_space,
        atlantis_large_data,
        atlantis_artifacts,
    ]
    dirs += [crs_scratch_space.parent / f'crs_scratch_{i}' for i in range(node_num)] # TODO: make scratch directories for each fuzzer

    if fake_oss_fuzz:
        dirs += [crs_oss_fuzz_path]

    for d in dirs:
        if not d.is_dir():
            d.mkdir(exist_ok=True, parents=True)
            print(f'Directory {d} created.')

def setup_env(cp_context: RepoContext):
    # create fake multilang shared seeds directory
    guest_shared_seeds_dir = '/shared-crs-fs/shared'
    host_shared_seeds_dir = shared_crs_space / 'shared'
    guest_shared_reachability_dir = '/shared-crs-fs/reachability'
    host_shared_reachability_dir = shared_crs_space / 'reachability'
    guest_shared_sarif_dir = '/shared-crs-fs/sarif'
    host_shared_sarif_dir = shared_crs_space / 'sarif'

    for harness in cp_context.harnesses:
        multilang_shared_seeds = host_shared_seeds_dir / 'crs-multilang' / harness
        multilang_shared_seeds.mkdir(exist_ok=True, parents=True)
        print(f'Directory {multilang_shared_seeds} created.')

    host_shared_reachability_dir.mkdir(exist_ok=True, parents=True)
    print(f'Directory {host_shared_reachability_dir} created.')

    host_shared_sarif_dir.mkdir(exist_ok=True, parents=True)
    print(f'Directory {host_shared_sarif_dir} created.')

    # NOTE *_SERVER_ADDR set at the compose.yaml level
    #https://github.com/Team-Atlanta/Atlantis-AFC/issues/76
    crs_docker_mounts = (
        f'{crs_oss_fuzz_path}:/oss_fuzz;{crs_target_src_path}:/src;'
        f'{crs_scratch_space}:/crs_scratch;{shared_crs_space}:/shared-crs-fs;'
        f'{atlantis_large_data}:/large_data;{atlantis_artifacts}:/artifacts;'
        f'{docker_config}:/root/.docker/config.json'
    )
    launcher_env = {
        'CRS_TARGET_NAME': crs_target_name,
        'SEED_SHARE_DIR': guest_shared_seeds_dir,
        'REACHABILITY_SHARE_DIR': guest_shared_reachability_dir,
        'SARIF_SHARE_DIR': guest_shared_sarif_dir,
        'REGISTRY': 'ghcr.io/team-atlanta', # just hard-code this
        'USERSPACE_RUNTIME_REGISTRY': 'ghcr.io/team-atlanta/crs-userspace-runtime',
        'IN_K8S': 'false',
        'AIXCC_OTLP_ENDPOINT': 'http://jaeger:4317',
        'OTEL_EXPORTER_OTLP_PROTOCOL': 'grpc',
        'CRS_SERVICE_NAME': 'crs-userspace',
        'CRS_DOCKER_MOUNTS': crs_docker_mounts,
        'NODE_NUM': str(node_num),
        'NODE_CPU_CORES': str(node_cpu_cores),
    }
    for key in PASSTHROUGH_ENV_VARS:
        value = os.environ.get(key)
        if value is not None:
            launcher_env[key] = value
    Path('.env.launcher').write_text('\n'.join(f'{k}={v}' for k, v in launcher_env.items()))

    if not Path('.env.user').is_file():
        Path('.env.user').touch()

    host_env = {
        **os.environ,
        'CRS_OSS_FUZZ_PATH': str(crs_oss_fuzz_path),
        'CRS_TARGET_SRC_PATH': str(crs_target_src_path),
    }
    return host_env

def docker_config_failure():
    # print(f"{docker_config} is missing and could not be generated -- run `docker login ghcr.io` with your Github PAT")
    print(f'\x1b[31m\n [!] {docker_config} is missing and could not be generated -- run `docker login ghcr.io` with your Github PAT or set GHCR_AUTH\x1b[0m\n')
    exit(-1)

def setup_docker_config_from_user():
    if not docker_config.is_file():
        # clean up a previous improper mount
        if docker_config.is_dir():
            shutil.rmtree(docker_config)
            
        user_docker_config = Path.home() / ".docker/config.json"
        if not user_docker_config.is_file():
            docker_config_failure()
        
        with user_docker_config.open() as f:
            user_docker_config_contents = json.load(f)
            try:
                _ = user_docker_config_contents["auths"]["ghcr.io"]["auth"]
            except:
                docker_config_failure()
            
        shutil.copy(user_docker_config, docker_config)


def setup_docker_config():
    if not os.environ.get('GHCR_AUTH'):
        setup_docker_config_from_user()
    
    Path('docker-config.json').write_text(json.dumps({
        "auths": {
            "ghcr.io": {
                "auth": os.environ.get('GHCR_AUTH')
            }
        }
    }))

def stop(host_env: dict[str, str], prefix: str = "atlantis-afc"):
    # Stop and remove any existing containers for the specified profile
    print('==== stopping')
    subprocess.run(['docker', 'compose', '--project-name', 'atlantis-afc', '--profile', profile, 'stop'], env=host_env, check=True)

    print('==== stopping orphan containers and removing kafka')
    result = subprocess.run(['docker', 'ps', '--all', '--format', '{{.Names}}'], capture_output=True, text=True, check=True)
    containers = result.stdout.strip().split('\n')
    to_stop = []
    to_remove = []
    for container in containers:
        if container.startswith(prefix):
            to_stop.append(container)
        if container.startswith('atlantis-afc-kafka') or container.startswith('atlantis-afc-zookeeper'):
            to_remove.append(container)
    if to_stop:
        print(f'Stopping containers {", ".join(to_stop)}')
        subprocess.run(['docker', 'stop', *to_stop], check=True)
    if to_remove:
        print(f'Removing containers {", ".join(to_remove)}')
        subprocess.run(['docker', 'rm', '-f', *to_remove], check=True)

def clean(prefix: str = "atlantis-afc"):
    print('==== cleaning')
    dirs = [
        crs_oss_fuzz_path,
        crs_target_src_path.parent,
        crs_scratch_space,
        shared_crs_space,
        atlantis_large_data,
        atlantis_artifacts,
    ]
    dirs += [crs_scratch_space.parent / 'crs_scratch_*']

    # this sometimes happens when GHCR_AUTH is not set
    if docker_config.is_dir():
        dirs.append(docker_config)

    for d in dirs:
        subprocess.run([f'sudo rm -rf {str(d)}'], shell=True)
        print(f'Directory {d} removed.')

    print(f'==== removing all {prefix} containers')
    result = subprocess.run(['docker', 'ps', '--all', '--format', '{{.Names}}'], capture_output=True, text=True, check=True)
    containers = result.stdout.strip().split('\n')
    for container in containers:
        if container.startswith(prefix):
            print(f'Removing container {container}')
            subprocess.run(['docker', 'rm', '-f', container], check=True)

    volume_name = f"{Path.cwd().name.lower()}_esdata"
    print(f'==== removing volume {volume_name}')
    subprocess.run(['docker', 'volume', 'rm', volume_name])

    print(f'==== removing compose.yaml')
    compose_yaml_path = root / 'compose.yaml'
    if compose_yaml_path.is_file():
        compose_yaml_path.unlink()

def build_compose_yaml(host_env: dict[str, str], node_num: int):
    print('==== making compose.yaml')
    jinja_env = Environment(loader=FileSystemLoader(root))
    template = jinja_env.get_template('compose.yaml.j2')
    compose_yaml_path = root / 'compose.yaml'
    vars = {
        'node_num': node_num,
    }

    with compose_yaml_path.open('w') as f:
        f.write(template.render(vars))

def build(host_env: dict[str, str]=None):
    if host_env is None:
        host_env = {"CRS_OSS_FUZZ_PATH": str(crs_oss_fuzz_path), "CRS_TARGET_SRC_PATH": str(crs_target_src_path)} 
    if crs_build_cp_image:
        print('==== building CP image')
        build_cp(crs_oss_fuzz_path, crs_target_name)

    print('==== building')
    dependencies = ['microservice-base', 'microservice-slim']
    for container in dependencies:
        container_name = container.split('/')[-1]
        subprocess.run(['docker', 'build', '-f', f'microservices/{container}/Dockerfile', '.', '-t', f'{container_name}:latest'], env=host_env, cwd=root, check=True) # TODO: add versioning
    
    # the worker images are included in the manager compose file
    build_compose_yaml(host_env, 1)
    subprocess.run(['docker', 'compose', '--file', 'compose.yaml', '--profile', profile, 'build'], env=host_env, cwd=root, check=True)

def push(registry: str = 'ghcr.io/team-atlanta/crs-userspace', tag: str = 'latest'):
    dependencies = ['microservice-base', 'microservice-slim']
    compose_containers = [
        'bootstrap', 'controller', 'osv_analyzer',# 'telemetry_logger',
        'codebrowser', 'harness_builder', 'fuzzer_manager',
        'crash_collector', 'seeds_collector', 
        'coverage_service', 'harness_reachability', 
        'deepgen_service', 'seed_ensembler',
        'directed_fuzzing', 'custom_fuzzer',
        'c_llm',
    ]

    containers = dependencies + compose_containers

    print('==== pushing')
    for container in containers:
        container_name = container.split('/')[-1]
        subprocess.run(['docker', 'tag', f'{container_name}:latest', f'{registry}/{container_name}:{tag}'], check=True)
        subprocess.run(['docker', 'push', f'{registry}/{container_name}:{tag}'], check=True)

def launch(host_env: dict[str, str]):
    setup_docker_config()
    print('==== launching')
    setup_docker_config()
    subprocess.run(['docker', 'network', 'create', 'crs-internal'], stderr=subprocess.DEVNULL)
    build_compose_yaml(host_env, node_num)
    subprocess.run(['docker', 'compose', '--file', 'compose.yaml', '--profile', profile, 'up'], env=host_env, cwd=root, check=True)

if __name__ == '__main__':
    if args.command == 'clean':
        clean()
        exit(0)
    elif args.command == 'build':
        setup_dirs(fake_oss_fuzz=True)
        build()
        exit(0)
    elif args.command == 'push':
        push(args.registry, args.tag)
        exit(0)

    print('\x1b[32m\n [!] For a clean workspace, please remove'
        f' "{relative_to_safe(crs_oss_fuzz_path, root)}",'
        f' "{relative_to_safe(crs_target_src_path, root)}",'
        f' and "{relative_to_safe(crs_scratch_space, root)}",'
        f' and "{relative_to_safe(shared_crs_space, root)}",'
        f' and "{relative_to_safe(atlantis_large_data, root)}",'
        f' and "{relative_to_safe(atlantis_artifacts, root)}" manually\x1b[0m\n')

    setup_dirs()
    clone_oss_fuzz_repo()
    cp_context = clone_cp_repo(crs_oss_fuzz_path, crs_target_src_path, crs_target_name)
    host_env = setup_env(cp_context)

    if args.command == 'run':
        stop(host_env)
        build(host_env)
        launch(host_env)
        stop(host_env)
